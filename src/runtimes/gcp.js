// GCP Cloud Build runtime: run the sandbox scan in a throwaway Cloud Build machine in YOUR project.
//
// NOT LIVE-TESTED BY THE MAINTAINER, because it costs money. The generated build config and every
// command line are unit-tested, and plan() shows exactly what would run (bouncer --dry-run).
// docs/cloud.md explains the one-time setup, the costs, and what you may need to edit.
//
// How a scan works:
//   1. Copy git-bouncer's own sandbox/ folder (Dockerfile + scanner) to a private temp folder and
//      write a cloudbuild.yaml next to it (not inside it, so it isn't uploaded).
//   2. gcloud builds submit --async: gcloud uploads that folder under gs://<your bucket>/git-bouncer/
//      <run id>/ and starts a build, tagged with the run id, with three steps:
//        a. build the sandbox image from the uploaded folder;
//        b. the metadata canary: run the image with the scan's own flags and fail the build if the
//           sandbox can get a token from the metadata server;
//        c. the scan: `docker run` the scanner with the same hardening as a local scan, nonce on stdin.
//      Nothing from your machine or from the repository being checked is uploaded. The scanner clones
//      the repo itself, inside the sandbox.
//   3. gcloud builds describe, every 10 seconds, until the build has finished.
//   4. gcloud builds log: the complete log, which contains the nonce-framed report.
//   5. gcloud storage rm: delete everything under the run's prefix. If git-bouncer is interrupted,
//      destroy() cancels the build (found by its tag if its ID was never seen) so nothing keeps billing.
//
// Two refusals, on purpose:
//   - No dedicated service account, no scan. Without one the build runs as the project's default
//     Cloud Build identity, which can often write images and sources or even edit the project.
//   - No gcloud on Windows. There gcloud is a .cmd script, which Node can only start through
//     cmd.exe, and cmd.exe parses arguments like a shell.
//
// Why a generated file instead of --substitutions? The values would otherwise pass through gcloud's
// KEY=VALUE,KEY=VALUE flag parser, and a fixed config can't leave out --ref when there is none. The
// values go straight into a file written by toYaml() (every string JSON-quoted). Cloud Build expands
// $NAME anywhere in the file, so the file has exactly one "$": the constant NONCE_WRAPPER below.

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir as osTmpdir } from 'node:os'
import path from 'node:path'
import { clean } from '../ui/sanitize.js'
import {
  CANARY_FAILED, SANDBOX_IMAGE, TEMP_DIR_PLACEHOLDER, assertSandboxDir, assertScanInputs, canaryCommand,
  copySandbox, errorTail, fillStep, loadCloudConfig, makeDefaultExec, reportReady, runIdFor, sandboxRunArgs,
  scannerCommand, sleep, stoppedError, toYaml, writePlanFiles,
} from './cloud-common.js'

/**
 * Google's docker builder, pinned by digest: this image gets the build machine's Docker socket and
 * sits on the network where the build's token is served. Dependabot can't see a digest inside a JS
 * string, so refresh it by hand: run
 *   docker buildx imagetools inspect gcr.io/cloud-builders/docker:latest
 * and paste the new "Digest:" here, with today's date. (2026-11-27: Docker CLI 20.10.24 with
 * BuildKit and buildx 0.23, bash, linux/amd64.)
 */
export const DOCKER_BUILDER = 'gcr.io/cloud-builders/docker@sha256:9204cf318cf3f461092572b5d92b0f9876cfcf681046352f8c086652836e3482'

/**
 * The one shell in the build. Cloud Build steps have no stdin, and the nonce must reach the scanner
 * on stdin (never as an argument, which every process in the sandbox could read). So the scan step
 * runs bash with this CONSTANT script. The nonce comes from the step's environment, and every other
 * argument arrives as "$@", which bash passes on without parsing. "$$" is Cloud Build's escape for a
 * literal "$", so bash sees: printf '%s\n' "$GIT_BOUNCER_NONCE" | docker "$@"
 */
export const NONCE_WRAPPER = 'printf \'%s\\n\' "$$GIT_BOUNCER_NONCE" | docker "$$@"'

export const GCP_LIMITS = Object.freeze({
  buildTimeoutSeconds: 1800, // the whole build; also caps the bill if git-bouncer is killed mid-scan
  queueTtlSeconds: 900, // give up if Cloud Build can't start the build within 15 minutes
  imageStepTimeoutSeconds: 900,
  canaryStepTimeoutSeconds: 120,
  scanStepTimeoutSeconds: 1200,
})

export const STAGING_PREFIX = 'git-bouncer'
const SCAN_STEP = { index: 2, id: 'scan' }
const CANARY_STEP = { index: 1, id: 'metadata-canary' }
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/
const REGION = /^(?:global|[a-z]+-[a-z]+[0-9]{1,2})$/
const SERVICE_ACCOUNT = /^[a-z0-9][a-z0-9._-]{0,99}@[a-z0-9][a-z0-9.-]{0,200}\.[a-z]{2,63}$/
// Cloud Storage names: no dots (they break HTTPS hostnames), and Google refuses names starting with "goog".
const BUCKET = /^(?!goog)[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$/
const BUILD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const RUNNING = new Set(['STATUS_UNKNOWN', 'PENDING', 'QUEUED', 'WORKING'])
const STATUSES = new Set([...RUNNING, 'SUCCESS', 'FAILURE', 'INTERNAL_ERROR', 'TIMEOUT', 'CANCELLED', 'EXPIRED'])

const SHORT_MS = 2 * 60 * 1000
const SUBMIT_MS = 10 * 60 * 1000
const WAIT_MS = (GCP_LIMITS.queueTtlSeconds + GCP_LIMITS.buildTimeoutSeconds + 300) * 1000
const POLL_MS = 10 * 1000
const LOG_ATTEMPTS = 4
const INFLIGHT_GRACE_MS = 15 * 1000

/** The run's tag on the build, so destroy() can find the build even if its ID was never printed. */
export const runTag = runId => `git-bouncer-run-${runId}`

/**
 * The Cloud Build config as a plain object (what toYaml() writes to cloudbuild.yaml).
 * The image and canary steps are plain `args` arrays for the docker builder's own entrypoint; the
 * scan step is the one constant bash wrapper. No value is ever part of a shell script.
 */
export function buildCloudbuildConfig({ url, ref, nonce, project, serviceAccount, runId = runIdFor(nonce) }) {
  assertScanInputs({ url, ref, nonce })
  return {
    steps: [
      {
        id: 'build-sandbox-image',
        name: DOCKER_BUILDER,
        // BuildKit sets TARGETARCH, which sandbox/Dockerfile uses to pick the osv-scanner binary.
        env: ['DOCKER_BUILDKIT=1'],
        args: ['build', `--tag=${SANDBOX_IMAGE}`, '.'],
        timeout: `${GCP_LIMITS.imageStepTimeoutSeconds}s`,
      },
      {
        id: CANARY_STEP.id,
        name: DOCKER_BUILDER,
        args: [...sandboxRunArgs(), ...canaryCommand('token')],
        timeout: `${GCP_LIMITS.canaryStepTimeoutSeconds}s`,
      },
      {
        id: SCAN_STEP.id,
        name: DOCKER_BUILDER,
        entrypoint: 'bash',
        env: [`GIT_BOUNCER_NONCE=${nonce}`],
        args: ['-c', NONCE_WRAPPER, 'bash', ...sandboxRunArgs({ interactive: true }), ...scannerCommand({ url, ref })],
        timeout: `${GCP_LIMITS.scanStepTimeoutSeconds}s`,
      },
    ],
    timeout: `${GCP_LIMITS.buildTimeoutSeconds}s`,
    queueTtl: `${GCP_LIMITS.queueTtlSeconds}s`,
    tags: ['git-bouncer', runTag(runId)],
    // A dedicated, nearly powerless service account (see docs/cloud.md). Cloud Build requires
    // user-chosen service accounts to log to Cloud Logging or a bucket you own.
    serviceAccount: `projects/${project}/serviceAccounts/${serviceAccount}`,
    options: { logging: 'CLOUD_LOGGING_ONLY' },
  }
}

/** cloudbuild.yaml text for a scan. */
export function renderCloudbuildYaml(opts) {
  const yaml = toYaml(buildCloudbuildConfig(opts), {
    comments: [
      'Generated by git-bouncer for one scan. Not live-tested by the maintainer: see docs/cloud.md.',
      'Step 1 builds the sandbox image from git-bouncer\'s own sandbox/ folder. Step 2 checks that the',
      'sandbox cannot get credentials from the metadata server. Step 3 runs the scanner with no',
      'credentials, no mounts and the same hardening as a local scan; its nonce arrives on stdin.',
    ],
  })
  // Cloud Build expands $NAME and ${NAME} anywhere in the config. The values can't contain "$"
  // (assertScanInputs), and the only "$" we write is in the constant wrapper. Check both.
  const quotedWrapper = JSON.stringify(NONCE_WRAPPER)
  if (yaml.split(quotedWrapper).length !== 2 || yaml.split(quotedWrapper).join('').includes('$')) {
    throw new Error('internal: the generated cloudbuild.yaml has a "$" outside the nonce wrapper')
  }
  return yaml
}

/**
 * Keep only what one step printed, without Cloud Build's `Step #2 - "scan": ` prefix, so the report
 * markers are whole lines again. Lines from other steps are dropped. Lines with no step prefix
 * (gcloud's own banner lines, or a log format without prefixes) are kept: only the scanner knows the
 * nonce, so they can't be mistaken for a report, and a change in Google's log format then makes the
 * scan fail closed (no report found) rather than silently empty.
 */
export function extractStepOutput(logText, { index, id } = SCAN_STEP) {
  const out = []
  for (const line of String(logText).split(/\r?\n/)) {
    const m = /^Step #(\d+)(?: - "([^"]*)")?:(?: (.*))?$/.exec(line)
    if (!m) { out.push(line); continue }
    if (Number(m[1]) === index && (m[2] === undefined || m[2] === id)) out.push(m[3] ?? '')
  }
  return out.join('\n')
}

/** Settings that come from the environment or the config file (no commands run). */
async function readSettings(env) {
  const cfg = await loadCloudConfig(env)
  const pick = (name, key) => env[name] || cfg.gcp[key] || null
  const s = {
    project: pick('GIT_BOUNCER_GCP_PROJECT', 'project'),
    region: pick('GIT_BOUNCER_GCP_REGION', 'region'),
    serviceAccount: pick('GIT_BOUNCER_GCP_SERVICE_ACCOUNT', 'serviceAccount'),
    bucket: pick('GIT_BOUNCER_GCP_BUCKET', 'bucket'),
    configPath: cfg.path,
  }
  if (s.project && !PROJECT_ID.test(s.project)) throw new Error(`"${clean(s.project, { max: 80 })}" is not a valid Google Cloud project ID.`)
  if (s.region && !REGION.test(s.region)) throw new Error(`"${clean(s.region, { max: 80 })}" is not a valid Cloud Build region (for example us-central1, or global).`)
  if (s.serviceAccount && !SERVICE_ACCOUNT.test(s.serviceAccount)) throw new Error('The configured service account is not a service account email address.')
  if (s.bucket && !BUCKET.test(s.bucket)) throw new Error(`"${clean(s.bucket, { max: 80 })}" is not a bucket name git-bouncer accepts (lowercase letters, digits, - and _; no dots).`)
  return s
}

/**
 * Every gcloud command a scan can run, in order. Values in <angle brackets> come from an earlier
 * step's output and are validated before they are filled in.
 */
export function gcpSteps({ source, config, project, region, bucket, runId }) {
  const scope = [`--project=${project}`, ...(region ? [`--region=${region}`] : [])]
  // --user-output-enabled: a user's `core/user_output_enabled=false` would otherwise make gcloud
  // print nothing, and a build that did start would look like one that didn't.
  const tail = ['--user-output-enabled', '--quiet']
  return [
    {
      id: 'submit',
      description: 'Upload git-bouncer\'s sandbox folder under the run\'s own prefix and start the build. Returns the build ID at once.',
      cmd: 'gcloud',
      args: ['builds', 'submit', source, `--config=${config}`, `--gcs-source-staging-dir=gs://${bucket}/${STAGING_PREFIX}/${runId}`, ...scope, '--async', '--format=value(id)', ...tail],
    },
    {
      id: 'status',
      description: 'Read the build\'s status, every 10 seconds until it has finished.',
      cmd: 'gcloud',
      args: ['builds', 'describe', '<build-id>', ...scope, '--format=json', ...tail],
    },
    {
      id: 'log',
      description: 'Fetch the complete build log, which contains the report between the nonce markers.',
      cmd: 'gcloud',
      args: ['builds', 'log', '<build-id>', ...scope, ...tail],
    },
    {
      id: 'cleanup-source',
      description: 'Delete everything this run uploaded (the run\'s prefix in your bucket).',
      cmd: 'gcloud',
      args: ['storage', 'rm', `gs://${bucket}/${STAGING_PREFIX}/${runId}/**`, `--project=${project}`, ...tail],
    },
    {
      id: 'find-builds',
      when: 'only if git-bouncer is interrupted before it has seen the build ID',
      description: 'Find a still-running build by this run\'s tag.',
      cmd: 'gcloud',
      args: ['builds', 'list', '--ongoing', `--filter=tags:${runTag(runId)}`, '--format=value(id)', '--limit=10', ...scope, ...tail],
    },
    {
      id: 'cancel',
      when: 'only if git-bouncer stops waiting (interrupt, timeout or error) while the build is still running',
      description: 'Cancel the build so nothing keeps running or billing.',
      cmd: 'gcloud',
      args: ['builds', 'cancel', '<build-id>', ...scope, ...tail],
    },
  ]
}

/**
 * @param {{exec?: Function, env?: Record<string,string>, tmpdir?: string, platform?: string,
 *          sleep?: (ms: number) => Promise<void>, onLog?: (line: string) => void}} [opts]
 */
export function createGcpRuntime({ exec, env = process.env, tmpdir = osTmpdir(), platform = process.platform, sleep: wait = sleep, onLog: defaultOnLog = () => {} } = {}) {
  const execFn = exec || makeDefaultExec(platform)
  // gcloud runs on the host, as if the user typed the command, so it gets the user's environment.
  // These override user settings that would change what gcloud prints or make it wait for input:
  // the screen-reader mode deletes "---> " from every log line, and log_http would print raw HTTP.
  const cliEnv = {
    ...env,
    CLOUDSDK_CORE_DISABLE_PROMPTS: '1',
    CLOUDSDK_CORE_USER_OUTPUT_ENABLED: 'true',
    CLOUDSDK_ACCESSIBILITY_SCREEN_READER: 'false',
    CLOUDSDK_CORE_LOG_HTTP: 'false',
    CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK: '1',
  }
  const gcloud = (args, opts = {}) => execFn('gcloud', args, { timeoutMs: SHORT_MS, env: cliEnv, ...opts })
  const inflight = new WeakMap() // session -> the cloud command scan() is waiting for right now
  let detected = null // what available() found, reused by plan(), scan() and describe()

  async function available() {
    if (platform === 'win32') {
      return { ok: false, reason: 'On Windows, gcloud is a .cmd script, and Node can only start those through cmd.exe, whose argument parsing git-bouncer will not rely on. Run git-bouncer from WSL to use Cloud Build.' }
    }
    let settings
    try { settings = await readSettings(env) } catch (e) { return { ok: false, reason: e.message } }

    const version = await gcloud(['--version'])
    if (version.code !== 0) return { ok: false, reason: 'gcloud (the Google Cloud CLI) is not installed or not on your PATH. See https://cloud.google.com/sdk/docs/install' }

    if (!settings.serviceAccount) {
      return { ok: false, reason: `Cloud Build scans need a dedicated service account that can only write logs and read git-bouncer's uploads (docs/cloud.md shows the commands). Without one the build would run as your project's default Cloud Build identity. Set GIT_BOUNCER_GCP_SERVICE_ACCOUNT or "gcp.serviceAccount" in ${settings.configPath}.` }
    }
    if (!settings.bucket) {
      return { ok: false, reason: `Cloud Build scans need a bucket of their own, in the same project, for the uploaded sandbox folder (docs/cloud.md). Set GIT_BOUNCER_GCP_BUCKET or "gcp.bucket" in ${settings.configPath}.` }
    }

    const auth = await gcloud(['auth', 'list', '--filter=status:ACTIVE', '--format=value(account)', '--user-output-enabled', '--quiet'])
    const account = auth.code === 0 ? auth.stdout.split(/\r?\n/).map(s => s.trim()).find(Boolean) : null
    if (!account) return { ok: false, reason: 'gcloud is installed but not signed in. Run: gcloud auth login' }
    const who = clean(account, { max: 200 })

    let project = settings.project
    if (!project) {
      const r = await gcloud(['config', 'get-value', 'project', '--user-output-enabled', '--quiet'])
      const value = r.code === 0 ? r.stdout.trim() : ''
      if (value && value !== '(unset)') project = value
    }
    if (!project) return { ok: false, account: who, reason: 'No Google Cloud project is selected. Run: gcloud config set project <project-id>, or set GIT_BOUNCER_GCP_PROJECT.' }
    if (!PROJECT_ID.test(project)) return { ok: false, account: who, reason: `"${clean(project, { max: 80 })}" is not a valid Google Cloud project ID.` }

    // The staging bucket must belong to this project. gcloud only checks that for its own default
    // bucket; with --gcs-source-staging-dir it trusts whatever bucket the name points to, and bucket
    // names are global, so someone else could own one with the name you configured.
    const p = await gcloud(['projects', 'describe', project, '--format=value(projectNumber)', '--user-output-enabled', '--quiet'])
    const projectNumber = p.code === 0 ? p.stdout.trim() : ''
    if (!/^[0-9]{1,20}$/.test(projectNumber)) return { ok: false, account: who, reason: `Could not read project ${project}: ${errorTail(p, 300)}` }
    const b = await gcloud(['storage', 'buckets', 'describe', `gs://${settings.bucket}`, '--raw', '--format=json', `--project=${project}`, '--user-output-enabled', '--quiet'])
    let owner = null
    try { owner = b.code === 0 ? String(JSON.parse(b.stdout).projectNumber) : null } catch { owner = null }
    if (owner !== projectNumber) {
      return { ok: false, account: who, reason: `The bucket gs://${settings.bucket} does not exist, can't be read, or belongs to another project. git-bouncer only uploads to a bucket that project ${project} owns.` }
    }

    detected = { project, projectNumber, region: settings.region, serviceAccount: settings.serviceAccount, bucket: settings.bucket }
    return { ok: true, account: who, project, region: settings.region || 'global', bucket: settings.bucket, serviceAccount: settings.serviceAccount }
  }

  /** Pure: reads the config file but runs no commands. Returns exactly what scan() will run. */
  async function plan({ url, ref = null, nonce, sandboxDir, workDir = TEMP_DIR_PLACEHOLDER }) {
    assertScanInputs({ url, ref, nonce })
    const settings = await readSettings(env)
    const project = settings.project || (detected && detected.project) || '<project>'
    const serviceAccount = settings.serviceAccount || '<service-account>'
    const bucket = settings.bucket || '<bucket>'
    const { region } = settings
    const runId = runIdFor(nonce)
    const at = name => (workDir === TEMP_DIR_PLACEHOLDER ? `${workDir}/${name}` : path.join(workDir, name))
    const files = { 'cloudbuild.yaml': renderCloudbuildYaml({ url, ref, nonce, project, serviceAccount, runId }) }
    const steps = gcpSteps({ source: at('source'), config: at('cloudbuild.yaml'), project, region, bucket, runId })
    const notes = [
      'Not live-tested by the maintainer, because it costs money. See docs/cloud.md before using it.',
      `${at('source')} is a copy of git-bouncer's own sandbox folder (${sandboxDir || 'sandbox/'}): the Dockerfile and the scanner. Nothing else from your machine, and nothing from the repository being checked, is uploaded.`,
      `gcloud uploads it under gs://${bucket}/${STAGING_PREFIX}/${runId}/, and git-bouncer deletes that prefix when the scan ends.`,
      `The build runs in project ${project}${region ? `, region ${region}` : ''}, as ${serviceAccount}, with a ${GCP_LIMITS.buildTimeoutSeconds / 60}-minute limit. Cloud Build bills by build-minute: https://cloud.google.com/build/pricing`,
      'Before the scan, a canary step fails the build if the sandbox can get a token from the metadata server.',
      'The scan container gets no credentials, no mounts and no environment variables, is not attached to the "cloudbuild" network where Cloud Build serves the build\'s credentials, and reads its nonce from stdin.',
      'Values in <angle brackets> are filled in from your settings or from the output of an earlier step.',
    ]
    return { steps, files, notes }
  }

  async function scan({ url, ref = null, nonce, sandboxDir, onLog = defaultOnLog, onSession = () => {} } = {}) {
    assertScanInputs({ url, ref, nonce })
    assertSandboxDir(sandboxDir)
    const ready = await available()
    if (!ready.ok) throw new Error(`Cloud Build is not ready: ${ready.reason}`)
    // An absolute local path, so gcloud can't read the source argument as an option, a gs:// object
    // or a git URL (`gcloud builds submit` accepts all three).
    if (!path.isAbsolute(tmpdir)) throw new Error('the temporary folder must be an absolute path')

    const runId = runIdFor(nonce)
    const workDir = await mkdtemp(path.join(tmpdir, 'git-bouncer-gcp-'))
    const session = {
      runtime: 'gcp', name: runTag(runId), runId, tag: runTag(runId),
      project: detected.project, region: detected.region || null, bucket: detected.bucket,
      staging: `gs://${detected.bucket}/${STAGING_PREFIX}/${runId}/`, workDir,
      buildId: null, status: null, logUrl: null,
      submitStarted: false, finished: false, destroyed: false, reportComplete: false,
      cleanup: { buildSettled: false, cancelled: [], stagingRemoved: false, workDirRemoved: false, problems: [] },
    }
    // Everything destroy() needs is in the session before anything exists in the cloud.
    onSession(session)

    const vars = {}
    let steps
    const run = async (id, opts = {}) => {
      if (session.destroyed) throw stoppedError(session)
      const { cmd, args } = fillStep(steps.find(s => s.id === id), vars)
      const p = execFn(cmd, args, { timeoutMs: SHORT_MS, env: cliEnv, ...opts })
      inflight.set(session, p)
      try { return await p } finally { inflight.delete(session) }
    }

    try {
      const p = await plan({ url, ref, nonce, sandboxDir, workDir })
      steps = p.steps
      await copySandbox(sandboxDir, path.join(workDir, 'source'))
      await writePlanFiles(workDir, p.files)
      if (session.destroyed) throw stoppedError(session)

      session.submitStarted = true
      const submit = await run('submit', { timeoutMs: SUBMIT_MS })
      let buildId = submit.code === 0 ? submit.stdout.trim().split(/\r?\n/).pop().trim() : ''
      if (submit.code === 0 && !BUILD_ID.test(buildId)) {
        // gcloud said it worked but printed no ID: look the build up by its tag.
        const found = (await findBuilds(session)) || []
        buildId = found.length === 1 ? found[0] : ''
      }
      if (!BUILD_ID.test(buildId)) throw new Error(`Cloud Build did not start the build: ${errorTail(submit)}`)
      session.buildId = vars['<build-id>'] = buildId
      onLog(`Cloud Build started build ${buildId} in project ${session.project}.`)

      const started = Date.now()
      let build = null
      let failures = 0
      let last = null
      for (;;) {
        build = parseBuild(await run('status'))
        failures = build ? 0 : failures + 1
        if (failures >= 6) throw new Error('Could not read the Cloud Build build\'s status (gcloud builds describe kept failing).')
        if (build && build.status !== last) { last = build.status; onLog(`Cloud Build: ${build.status}`) }
        if (build && !RUNNING.has(build.status)) break
        if (Date.now() - started > WAIT_MS) throw new Error('Gave up waiting for the Cloud Build build to finish.')
        await wait(POLL_MS)
      }
      Object.assign(session, { finished: true, status: build.status, logUrl: build.logUrl })

      // Builds that log to Cloud Logging can take a moment to become readable, so ask again a few
      // times before giving up. The check is the CLI's own (extractReport).
      let log = ''
      let reportText = ''
      for (let attempt = 0; attempt < LOG_ATTEMPTS; attempt += 1) {
        if (attempt > 0) await wait(5000)
        const r = await run('log', { timeoutMs: SUBMIT_MS })
        if (r.code === 0) { log = r.stdout; reportText = extractStepOutput(log, SCAN_STEP) }
        if (reportReady(reportText, nonce)) break
      }
      session.reportComplete = reportReady(reportText, nonce)
      if (!session.reportComplete && extractStepOutput(log, CANARY_STEP).split('\n').some(l => l.startsWith(CANARY_FAILED))) {
        throw new Error('The metadata canary failed: inside the sandbox, the build machine\'s metadata server handed out a token. git-bouncer will not scan in this setup. See "Security notes" in docs/cloud.md.')
      }
      if (!session.reportComplete) onLog(`The build log has no complete report (build status ${session.status}). See ${session.logUrl || 'the build history in the Cloud console'}.`)
      await cleanup(session)
      return { reportText, session }
    } catch (e) {
      await cleanup(session)
      throw Object.assign(e, { session })
    }
  }

  async function findBuilds(session) {
    const steps = gcpSteps({ source: '', config: '', project: session.project, region: session.region, bucket: session.bucket, runId: session.runId })
    const { cmd, args } = fillStep(steps.find(s => s.id === 'find-builds'), {})
    const r = await execFn(cmd, args, { timeoutMs: SHORT_MS, env: cliEnv })
    if (r.code !== 0) return null
    return r.stdout.split(/\r?\n/).map(s => s.trim()).filter(id => BUILD_ID.test(id))
  }

  /**
   * Cancel a build that may still be running, delete everything under the run's prefix, remove the
   * temp folder. Safe to call more than once, and while scan() is still running (that's what an
   * interrupt does). After it, scan() starts nothing new.
   */
  async function cleanup(session) {
    session.destroyed = true
    const c = session.cleanup
    const steps = gcpSteps({ source: '', config: '', project: session.project, region: session.region, bucket: session.bucket, runId: session.runId })
    const runStep = async (id, vars = {}) => {
      const { cmd, args } = fillStep(steps.find(s => s.id === id), vars)
      return execFn(cmd, args, { timeoutMs: SHORT_MS, env: cliEnv })
    }
    if (session.submitStarted && !c.buildSettled) {
      if (session.finished) {
        c.buildSettled = true
      } else {
        // If submit is still on its way, give it a moment to create the build, so the lookup sees it.
        const pending = inflight.get(session)
        if (!session.buildId && pending) await Promise.race([pending, wait(INFLIGHT_GRACE_MS)])
        const ids = session.buildId ? [session.buildId] : await findBuilds(session)
        if (ids === null) {
          c.problems.push(`Could not look for a running build tagged ${session.tag}. Check the Cloud Build history and cancel it there if it is running.`)
        } else {
          let ok = true
          for (const id of ids.filter(i => !c.cancelled.includes(i))) {
            const r = await runStep('cancel', { '<build-id>': id })
            if (r.code === 0) c.cancelled.push(id)
            else { ok = false; c.problems.push(`Could not cancel build ${id}. Cancel it in the Cloud console, or run: gcloud builds cancel ${id}`) }
          }
          // Found nothing? Then the build may not exist yet, so stay unsettled: if scan() learns the
          // ID afterwards, the next cleanup cancels it by ID.
          c.buildSettled = ok && ids.length > 0
        }
      }
    }
    if (session.submitStarted && !c.stagingRemoved) {
      const r = await runStep('cleanup-source')
      // Nothing uploaded yet (or already deleted) is fine too.
      if (r.code === 0 || /matched no objects/i.test(r.stderr || '')) c.stagingRemoved = true
      else c.problems.push(`Could not delete ${session.staging}. It only contains git-bouncer's own sandbox files.`)
    }
    if (session.workDir && !c.workDirRemoved) {
      try { await rm(session.workDir, { recursive: true, force: true }); c.workDirRemoved = true } catch { c.problems.push(`Could not remove the temporary folder ${session.workDir}.`) }
    }
    return session
  }

  return {
    name: 'gcp',
    available,
    plan,
    scan,
    /** Cloud Build machines are deleted when the build ends, so there is never a file to read back. */
    async readFile() { return null },
    /** Cancels a build left running (found by tag if need be) and deletes the run's uploads. Idempotent. */
    async destroy(session) { if (session && session.runtime === 'gcp' && session.cleanup) await cleanup(session) },
    describe() {
      return detected
        ? `Google Cloud Build in project ${detected.project}, as ${detected.serviceAccount} (billed to your account; not live-tested by the maintainer)`
        : 'Google Cloud Build (billed to your account; not live-tested by the maintainer)'
    },
  }
}

/** Pick the fields we need out of `gcloud builds describe --format=json`, validating each. */
function parseBuild(result) {
  if (!result || result.code !== 0) return null
  let b
  try { b = JSON.parse(result.stdout) } catch { return null }
  if (!b || typeof b !== 'object' || !STATUSES.has(b.status)) return null
  return {
    status: b.status,
    logUrl: typeof b.logUrl === 'string' && b.logUrl.startsWith('https://') ? clean(b.logUrl, { max: 500 }) : null,
  }
}
