// GCP Cloud Build runtime: run the sandbox scan in a throwaway Cloud Build machine in YOUR project.
//
// NOT LIVE-TESTED BY THE MAINTAINER, because it costs money. The generated build config and every
// command line are unit-tested, and plan() shows exactly what would run (bouncer --dry-run).
// docs/cloud.md explains the one-time setup, the costs, and what you may need to edit.
//
// How a scan works:
//   1. Copy git-bouncer's own sandbox/ folder (Dockerfile + scanner) to a private temp folder and
//      write a cloudbuild.yaml next to it (not inside it, so it isn't uploaded).
//   2. gcloud builds submit --async: gcloud uploads that folder to the project's Cloud Build staging
//      bucket and starts a build with two steps: build the sandbox image, then `docker run` it with
//      the same hardening flags as a local scan. Nothing from your machine or from the repository
//      being checked is uploaded. The scanner clones the repo itself, inside the sandbox.
//   3. gcloud builds log --stream: show progress and wait for the build to finish.
//   4. gcloud builds describe: the final status (polled if streaming stopped early).
//   5. gcloud builds log: the complete log, which contains the nonce-framed report. The streamed copy
//      isn't used for the report: gcloud prints streamed chunks with a newline after each one, so a
//      long report line could arrive split in two.
//   6. gcloud storage rm: delete the uploaded archive. If git-bouncer stops waiting (timeout, Ctrl-C)
//      while the build still runs, it runs `gcloud builds cancel` so nothing keeps billing.
//
// Why a generated file instead of --substitutions? Cloud Build substitutions would keep the config
// static, but the values would then pass through gcloud's KEY=VALUE,KEY=VALUE flag parser, and a
// static config can't leave out --ref when there is none. Here the values go straight into a
// file produced by toYaml() (every string JSON-quoted), the values are re-validated to contain no
// "$" (Cloud Build would expand $NAME inside the file), and the file is exactly what --dry-run shows.

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir as osTmpdir } from 'node:os'
import path from 'node:path'
import { clean } from '../ui/sanitize.js'
import {
  CLOUD_RUN_FLAGS, SANDBOX_IMAGE, TEMP_DIR_PLACEHOLDER, abortError, assertSandboxDir, assertScanInputs, copySandbox,
  defaultExec, errorTail, fillStep, hasCompleteReport, lineSink, loadCloudConfig, scannerCommand, sleep,
  toYaml, writePlanFiles,
} from './cloud-common.js'

export const DOCKER_BUILDER = 'gcr.io/cloud-builders/docker'

export const GCP_LIMITS = Object.freeze({
  buildTimeoutSeconds: 1800, // the whole build; also caps the bill if git-bouncer is killed mid-scan
  queueTtlSeconds: 900, // give up if Cloud Build can't start the build within 15 minutes
  imageStepTimeoutSeconds: 900,
  scanStepTimeoutSeconds: 1200,
})

const SCAN_STEP = { index: 1, id: 'scan' }
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/
const REGION = /^(?:global|[a-z]+-[a-z]+[0-9]{1,2})$/
const SERVICE_ACCOUNT = /^[a-z0-9][a-z0-9._-]{0,99}@[a-z0-9][a-z0-9.-]{0,200}\.[a-z]{2,63}$/
const BUILD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const STAGED_OBJECT = /^source\/[0-9]+(?:\.[0-9]+)?-[0-9a-f]{32}\.tgz$/
const RUNNING = new Set(['STATUS_UNKNOWN', 'PENDING', 'QUEUED', 'WORKING'])
const STATUSES = new Set([...RUNNING, 'SUCCESS', 'FAILURE', 'INTERNAL_ERROR', 'TIMEOUT', 'CANCELLED', 'EXPIRED'])

const SHORT_MS = 2 * 60 * 1000
const SUBMIT_MS = 10 * 60 * 1000
const WAIT_MS = (GCP_LIMITS.queueTtlSeconds + GCP_LIMITS.buildTimeoutSeconds + 300) * 1000
const POLL_MS = 10 * 1000
const LOG_ATTEMPTS = 4

/**
 * The Cloud Build config as a plain object (what toYaml() writes to cloudbuild.yaml).
 * Every step is an `args` array run by the docker builder's own entrypoint: no `entrypoint: bash`,
 * no `script:`, no shell anywhere in the build.
 */
export function buildCloudbuildConfig({ url, ref, nonce, project, serviceAccount }) {
  assertScanInputs({ url, ref, nonce })
  const config = {
    steps: [
      {
        id: 'build-sandbox-image',
        name: DOCKER_BUILDER,
        // BuildKit sets TARGETARCH and friends, which the Dockerfile may use to pick the right
        // osv-scanner binary. The builder's Docker 20.10 has BuildKit built in.
        env: ['DOCKER_BUILDKIT=1'],
        args: ['build', `--tag=${SANDBOX_IMAGE}`, '.'],
        timeout: `${GCP_LIMITS.imageStepTimeoutSeconds}s`,
      },
      {
        id: SCAN_STEP.id,
        name: DOCKER_BUILDER,
        args: ['run', ...CLOUD_RUN_FLAGS, SANDBOX_IMAGE, ...scannerCommand({ url, ref, nonce })],
        timeout: `${GCP_LIMITS.scanStepTimeoutSeconds}s`,
      },
    ],
    timeout: `${GCP_LIMITS.buildTimeoutSeconds}s`,
    queueTtl: `${GCP_LIMITS.queueTtlSeconds}s`,
    tags: ['git-bouncer'],
  }
  if (serviceAccount) {
    // A dedicated, nearly powerless service account (see docs/cloud.md). Cloud Build requires
    // user-chosen service accounts to log to Cloud Logging or a bucket you own.
    config.serviceAccount = `projects/${project}/serviceAccounts/${serviceAccount}`
    config.options = { logging: 'CLOUD_LOGGING_ONLY' }
  }
  return config
}

/** cloudbuild.yaml text for a scan. */
export function renderCloudbuildYaml(opts) {
  const yaml = toYaml(buildCloudbuildConfig(opts), {
    comments: [
      'Generated by git-bouncer for one scan. Not live-tested by the maintainer: see docs/cloud.md.',
      'Step 1 builds the sandbox image from git-bouncer\'s own sandbox/ folder. Step 2 runs the scanner',
      'in it with no credentials, no mounts, no environment and the same hardening as a local scan.',
    ],
  })
  // Cloud Build expands $NAME and ${NAME} anywhere in the config. assertScanInputs() already
  // guarantees the values contain no "$"; this makes sure nothing else slipped one in.
  if (yaml.includes('$')) throw new Error('internal: the generated cloudbuild.yaml contains "$"')
  return yaml
}

/**
 * Keep only what the scan step printed, without Cloud Build's `Step #1 - "scan": ` prefix, so the
 * report markers are whole lines again. Lines from other steps are dropped. Lines with no step
 * prefix (gcloud's own banner lines) are kept: they can't contain the nonce, so they can't be
 * mistaken for a report, and keeping them means a change in Google's log format makes the scan
 * fail closed (no report found) rather than silently empty.
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
    configPath: cfg.path,
  }
  if (s.project && !PROJECT_ID.test(s.project)) throw new Error(`"${clean(s.project, { max: 80 })}" is not a valid Google Cloud project ID.`)
  if (s.region && !REGION.test(s.region)) throw new Error(`"${clean(s.region, { max: 80 })}" is not a valid Cloud Build region (for example us-central1, or global).`)
  if (s.serviceAccount && !SERVICE_ACCOUNT.test(s.serviceAccount)) throw new Error('The configured service account is not a service account email address.')
  return s
}

/**
 * @param {{exec?: Function, env?: Record<string,string>, tmpdir?: string, platform?: string,
 *          sleep?: (ms: number, signal?: AbortSignal) => Promise<void>}} [opts]
 */
export function createGcpRuntime({ exec = defaultExec, env = process.env, tmpdir = osTmpdir(), platform = process.platform, sleep: wait = sleep } = {}) {
  // gcloud reads its own config and credentials from the user's environment; it runs on the host,
  // exactly as if the user typed the command. Prompts are switched off so nothing can hang.
  const cliEnv = { ...env, CLOUDSDK_CORE_DISABLE_PROMPTS: '1', CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK: '1' }
  const gcloud = (args, opts = {}) => exec('gcloud', args, { timeoutMs: SHORT_MS, env: cliEnv, ...opts })
  let detected = null // what available() found, reused by plan() and scan()

  async function available() {
    if (platform === 'win32') {
      return {
        ok: false,
        reason: 'On Windows, gcloud is a .cmd script, and Node can only start those through cmd.exe, whose argument quoting git-bouncer will not rely on. Run git-bouncer from WSL to use Cloud Build.',
      }
    }
    let settings
    try { settings = await readSettings(env) } catch (e) { return { ok: false, reason: e.message } }

    const version = await gcloud(['--version'])
    if (version.code !== 0) return { ok: false, reason: 'gcloud (the Google Cloud CLI) is not installed or not on your PATH. See https://cloud.google.com/sdk/docs/install' }

    const auth = await gcloud(['auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'])
    const account = auth.code === 0 ? auth.stdout.split(/\r?\n/).map(s => s.trim()).find(Boolean) : null
    if (!account) return { ok: false, reason: 'gcloud is installed but not signed in. Run: gcloud auth login' }

    let project = settings.project
    if (!project) {
      const r = await gcloud(['config', 'get-value', 'project'])
      const value = r.code === 0 ? r.stdout.trim() : ''
      if (value && value !== '(unset)') project = value
    }
    if (!project) {
      return { ok: false, account: clean(account, { max: 200 }), reason: 'No Google Cloud project is selected. Run: gcloud config set project <project-id>, or set GIT_BOUNCER_GCP_PROJECT.' }
    }
    if (!PROJECT_ID.test(project)) return { ok: false, account: clean(account, { max: 200 }), reason: `"${clean(project, { max: 80 })}" is not a valid Google Cloud project ID.` }

    detected = { project, region: settings.region, serviceAccount: settings.serviceAccount }
    return { ok: true, account: clean(account, { max: 200 }), project, region: settings.region || 'global' }
  }

  /** Pure: reads the config file but runs no commands. Returns exactly what scan() will run. */
  async function plan({ url, ref = null, nonce, sandboxDir, workDir = TEMP_DIR_PLACEHOLDER }) {
    assertScanInputs({ url, ref, nonce })
    const settings = await readSettings(env)
    const project = settings.project || (detected && detected.project) || '<project>'
    const { region, serviceAccount } = settings
    const at = name => (workDir === TEMP_DIR_PLACEHOLDER ? `${workDir}/${name}` : path.join(workDir, name))
    const files = { 'cloudbuild.yaml': renderCloudbuildYaml({ url, ref, nonce, project, serviceAccount }) }
    const steps = gcpSteps({ source: at('source'), config: at('cloudbuild.yaml'), project, region })
    const notes = [
      'Not live-tested by the maintainer, because it costs money. See docs/cloud.md before using it.',
      `${at('source')} is a copy of git-bouncer's own sandbox folder (${sandboxDir || 'sandbox/'}): the Dockerfile and the scanner. Nothing else from your machine, and nothing from the repository being checked, is uploaded.`,
      `gcloud uploads that folder to the project's Cloud Build staging bucket (${defaultStagingBucket(project)}), and git-bouncer deletes the archive when the scan ends.`,
      `The build runs in project ${project}${region ? `, region ${region}` : ''}, with a ${GCP_LIMITS.buildTimeoutSeconds / 60}-minute limit. Cloud Build bills by build-minute: https://cloud.google.com/build/pricing`,
      'The scan container gets no credentials, no mounts and no environment variables, and is not attached to the "cloudbuild" network where Cloud Build serves the build\'s credentials.',
      serviceAccount
        ? `The build runs as the service account you configured (${serviceAccount}) and logs to Cloud Logging only.`
        : 'The build runs as your project\'s default Cloud Build service account. A dedicated service account with no project roles is safer: see docs/cloud.md.',
      'Values in <angle brackets> are filled in from the output of an earlier step.',
    ]
    if (project === '<project>') notes.push('<project> is the project gcloud is set to use (gcloud config get-value project).')
    return { steps, files, notes }
  }

  async function scan({ url, ref = null, nonce, sandboxDir, onLog = () => {}, signal } = {}) {
    assertScanInputs({ url, ref, nonce })
    assertSandboxDir(sandboxDir)
    const ready = await available()
    if (!ready.ok) throw new Error(`Cloud Build is not ready: ${ready.reason}`)

    // An absolute local path, so gcloud can't read it as an option, a gs:// object or a git URL
    // (`gcloud builds submit` accepts all three as its source argument).
    if (!path.isAbsolute(tmpdir)) throw new Error('the temporary folder must be an absolute path')
    const workDir = await mkdtemp(path.join(tmpdir, 'git-bouncer-gcp-'))
    const session = {
      runtime: 'gcp', project: detected.project, region: detected.region || null, workDir,
      buildId: null, status: null, logUrl: null, stagedSource: null, finished: false, reportComplete: false,
      cleanup: { cancelled: false, stagedSourceRemoved: false, workDirRemoved: false, problems: [] },
    }
    const vars = {}
    let steps
    const run = async (id, opts = {}) => {
      const { cmd, args } = fillStep(steps.find(s => s.id === id), vars)
      const r = await exec(cmd, args, { timeoutMs: SHORT_MS, env: cliEnv, signal, ...opts })
      if (signal && signal.aborted) throw abortError()
      return r
    }
    const pause = async ms => { await wait(ms, signal); if (signal && signal.aborted) throw abortError() }

    try {
      const p = await plan({ url, ref, nonce, sandboxDir, workDir })
      steps = p.steps
      await copySandbox(sandboxDir, path.join(workDir, 'source'))
      await writePlanFiles(workDir, p.files)

      const submit = await run('submit', { timeoutMs: SUBMIT_MS })
      const buildId = submit.code === 0 ? submit.stdout.trim().split(/\r?\n/).pop().trim() : ''
      if (!BUILD_ID.test(buildId)) throw new Error(`Cloud Build did not start the build: ${errorTail(submit)}`)
      session.buildId = vars['<build-id>'] = buildId
      onLog(`Cloud Build started build ${buildId} in project ${session.project}.`)

      const started = Date.now()
      const sink = lineSink(onLog)
      await run('wait', { timeoutMs: WAIT_MS, onStdout: chunk => sink.write(chunk) })
      sink.end()

      // Streaming can stop early (for example without permission to read the logs bucket), so the
      // build's own status decides when it is done.
      let build = null
      let failures = 0
      for (;;) {
        build = parseBuild(await run('status'))
        if (build && !RUNNING.has(build.status)) break
        failures = build ? 0 : failures + 1
        if (failures >= 6) throw new Error('Could not read the Cloud Build build\'s status (gcloud builds describe kept failing).')
        if (Date.now() - started > WAIT_MS) throw new Error('Gave up waiting for the Cloud Build build to finish.')
        await pause(POLL_MS)
      }
      Object.assign(session, { finished: true, status: build.status, logUrl: build.logUrl, stagedSource: build.stagedSource })

      // Cloud Build marks a build finished only after its log is written, but a log kept in Cloud
      // Logging can take a moment to become readable. Ask again a few times before giving up.
      let reportText = ''
      for (let attempt = 0; attempt < LOG_ATTEMPTS; attempt += 1) {
        if (attempt > 0) await pause(5000)
        const r = await run('log', { timeoutMs: SUBMIT_MS })
        if (r.code === 0) reportText = extractStepOutput(r.stdout)
        if (hasCompleteReport(reportText, nonce)) break
      }
      session.reportComplete = hasCompleteReport(reportText, nonce)
      if (!session.reportComplete) onLog(`The build log has no complete report (build status ${session.status}). See ${session.logUrl || 'the build history in the Cloud console'}.`)
      await cleanup(session)
      return { reportText, session }
    } catch (e) {
      await cleanup(session)
      throw e
    }
  }

  /**
   * Cancel a build that is still running, delete the uploaded archive, remove the temp folder.
   * Safe to call more than once. Never passes the abort signal: after Ctrl-C, cancelling is exactly
   * what has to happen.
   */
  async function cleanup(session) {
    const c = session.cleanup
    const steps = gcpSteps({ source: '', config: '', project: session.project, region: session.region })
    const runCleanup = async (id, vars) => {
      const { cmd, args } = fillStep(steps.find(s => s.id === id), vars)
      try { return await exec(cmd, args, { timeoutMs: SHORT_MS, env: cliEnv }) } catch (e) { return { code: -1, stderr: String(e && e.message) } }
    }
    if (session.buildId && !session.finished && !c.cancelled) {
      const r = await runCleanup('cancel', { '<build-id>': session.buildId })
      if (r.code === 0) c.cancelled = true
      else c.problems.push(`Could not cancel build ${session.buildId}. Cancel it in the Cloud console, or run: gcloud builds cancel ${session.buildId}`)
    }
    const staged = session.stagedSource
    if (staged && !c.stagedSourceRemoved) {
      // Only ever delete the one archive gcloud uploaded for this build, in the bucket gcloud uses.
      if (staged.bucket === defaultStagingBucket(session.project) && STAGED_OBJECT.test(staged.object)) {
        const r = await runCleanup('cleanup-source', { '<staged-bucket>': staged.bucket, '<staged-object>': staged.object })
        if (r.code === 0) c.stagedSourceRemoved = true
        else c.problems.push(`Could not delete gs://${staged.bucket}/${staged.object}. It only contains git-bouncer's own sandbox files.`)
      } else {
        c.problems.push('The uploaded archive is not where git-bouncer expected it, so it was left alone.')
      }
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
    /** scan() already cleans up; this repeats anything that failed and cancels a build left running. */
    async destroy(session) { if (session && session.runtime === 'gcp' && session.cleanup) await cleanup(session) },
  }
}

/**
 * Every gcloud command a scan can run, in order. Values in <angle brackets> come from an earlier
 * step's output and are validated before they are filled in.
 */
export function gcpSteps({ source, config, project, region }) {
  const scope = [`--project=${project}`, ...(region ? [`--region=${region}`] : [])]
  return [
    {
      id: 'submit',
      description: 'Upload git-bouncer\'s sandbox folder and start the build. Returns the build ID at once.',
      cmd: 'gcloud',
      args: ['builds', 'submit', source, `--config=${config}`, ...scope, '--async', '--format=value(id)', '--quiet'],
    },
    {
      id: 'wait',
      description: 'Show the build\'s progress and wait for it to finish.',
      cmd: 'gcloud',
      args: ['builds', 'log', '<build-id>', '--stream', ...scope, '--quiet'],
    },
    {
      id: 'status',
      description: 'Read the final status (asked again every 10 seconds if the build is somehow still running).',
      cmd: 'gcloud',
      args: ['builds', 'describe', '<build-id>', ...scope, '--format=json', '--quiet'],
    },
    {
      id: 'log',
      description: 'Fetch the complete build log, which contains the report between the nonce markers.',
      cmd: 'gcloud',
      args: ['builds', 'log', '<build-id>', ...scope, '--quiet'],
    },
    {
      id: 'cleanup-source',
      description: 'Delete the uploaded copy of the sandbox folder from the Cloud Build staging bucket.',
      cmd: 'gcloud',
      args: ['storage', 'rm', 'gs://<staged-bucket>/<staged-object>', `--project=${project}`, '--quiet'],
    },
    {
      id: 'cancel',
      when: 'only if git-bouncer stops waiting (timeout, Ctrl-C or an error) while the build is still running',
      description: 'Cancel the build so nothing keeps running or billing.',
      cmd: 'gcloud',
      args: ['builds', 'cancel', '<build-id>', ...scope, '--quiet'],
    },
  ]
}

/** gcloud's default staging bucket name (gcloud checks that this bucket belongs to your project). */
export function defaultStagingBucket(project) {
  return `${String(project).replace(/google/g, 'elgoog')}_cloudbuild`
}

/** Pick the fields we need out of `gcloud builds describe --format=json`, validating each. */
function parseBuild(result) {
  if (!result || result.code !== 0) return null
  let b
  try { b = JSON.parse(result.stdout) } catch { return null }
  if (!b || typeof b !== 'object' || !STATUSES.has(b.status)) return null
  const src = b.source && b.source.storageSource
  return {
    status: b.status,
    logUrl: typeof b.logUrl === 'string' && b.logUrl.startsWith('https://') ? clean(b.logUrl, { max: 500 }) : null,
    stagedSource: src && typeof src.bucket === 'string' && typeof src.object === 'string' ? { bucket: src.bucket, object: src.object } : null,
  }
}
