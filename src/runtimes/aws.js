// AWS CodeBuild runtime: run the sandbox scan in a throwaway CodeBuild container in YOUR account.
//
// NOT LIVE-TESTED BY THE MAINTAINER, because it costs money. The generated buildspec, the StartBuild
// request and every command line are unit-tested, and plan() shows exactly what would run
// (bouncer --dry-run). docs/cloud.md has the one-time setup: an S3 bucket, an IAM role and a
// CodeBuild project, all yours.
//
// How a scan works:
//   1. Copy git-bouncer's own sandbox/ folder (Dockerfile + scanner) to a private temp folder, and
//      write start-build.json (the StartBuild request) next to it.
//   2. aws s3 cp: upload the folder to s3://<your bucket>/git-bouncer/<run id>/.
//   3. aws codebuild start-build --cli-input-json: start a build on your project, overriding the
//      source (that S3 folder), the buildspec, privileged mode (needed for Docker), artifacts (none),
//      cache (none), retries (none), timeouts and logging (CloudWatch only).
//   4. aws codebuild batch-get-builds: poll until the build has finished.
//   5. aws logs get-log-events: read the build log, which contains the nonce-framed report.
//   6. aws s3 rm: delete the uploaded folder. If git-bouncer stops waiting (timeout, Ctrl-C) while
//      the build still runs, it runs `aws codebuild stop-build` so nothing keeps billing.
//
// Why S3 for the source? CodeBuild has no "upload a folder" option. The alternatives were to embed
// the scanner in the buildspec or an environment variable (size limits, and the files would have to
// be unpacked by shell commands), or to have the build download git-bouncer from GitHub (then the
// cloud would run whatever GitHub serves, not the exact files you installed). An S3 folder in your
// own bucket uploads exactly the files on your disk, and costs one bucket to set up.
//
// CodeBuild runs buildspec commands with a shell; there is no argument-array form. So the shell text
// is constant: the URL, ref and nonce travel as environment variables in the StartBuild request and
// the commands only refer to them as "$GIT_BOUNCER_URL" etc. A shell does not re-parse the value of
// a double-quoted variable, so a value can't become a second command. Tests check that the buildspec
// is byte-for-byte the same whatever the values are.

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir as osTmpdir } from 'node:os'
import path from 'node:path'
import { clean } from '../ui/sanitize.js'
import {
  CLOUD_RUN_FLAGS, SANDBOX_IMAGE, SCANNER_ENTRY, TEMP_DIR_PLACEHOLDER, abortError, assertSandboxDir, assertScanInputs,
  copySandbox, defaultExec, errorTail, fillStep, hasCompleteReport, loadCloudConfig, runIdFor, sleep,
  toYaml, writePlanFiles,
} from './cloud-common.js'

export const AWS_LIMITS = Object.freeze({
  buildTimeoutMinutes: 30, // the whole build; also caps the bill if git-bouncer is killed mid-scan
  queuedTimeoutMinutes: 15, // give up if CodeBuild can't start the build within 15 minutes
})

export const S3_PREFIX = 'git-bouncer'

const PROJECT_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{1,254}$/
const REGION = /^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$/
// Lowercase letters, digits and hyphens. Dots are allowed by S3 but break HTTPS virtual-host
// addressing, so they're refused here.
const BUCKET = /^(?!xn--)[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/
const BUILD_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{1,254}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const LOG_NAME = /^[A-Za-z0-9_./#-]{1,512}$/
const LOG_TOKEN = /^[A-Za-z0-9/+=_-]{1,1024}$/
const STATUSES = new Set(['SUCCEEDED', 'FAILED', 'FAULT', 'TIMED_OUT', 'IN_PROGRESS', 'STOPPED'])

const SHORT_MS = 2 * 60 * 1000
const UPLOAD_MS = 10 * 60 * 1000
const WAIT_MS = (AWS_LIMITS.queuedTimeoutMinutes + AWS_LIMITS.buildTimeoutMinutes + 5) * 60 * 1000
const POLL_MS = 10 * 1000
const LOG_ATTEMPTS = 6
const MAX_LOG_PAGES = 500
const MAX_LOG_BYTES = 64 * 1024 * 1024

/** The shell words of a buildspec command. Only constants: never a value from the scan request. */
const SHELL_WORD = /^[A-Za-z0-9_./:=,@+-]+$/
const shellLine = words => {
  for (const w of words) if (!SHELL_WORD.test(w)) throw new Error(`internal: ${JSON.stringify(w)} is not a plain shell word`)
  return words.join(' ')
}

/**
 * The buildspec. It depends only on whether there is a ref, never on the values themselves.
 * @param {{hasRef: boolean}} opts
 */
export function buildBuildspec({ hasRef }) {
  const run = [
    shellLine(['docker', 'run', ...CLOUD_RUN_FLAGS, SANDBOX_IMAGE, 'node', SCANNER_ENTRY]),
    '--url="$GIT_BOUNCER_URL"',
    ...(hasRef ? ['--ref="$GIT_BOUNCER_REF"'] : []),
    '--nonce="$GIT_BOUNCER_NONCE"',
  ].join(' ')
  return {
    version: 0.2,
    env: { variables: { DOCKER_BUILDKIT: '1' } },
    phases: {
      build: {
        commands: [
          shellLine(['docker', 'build', `--tag=${SANDBOX_IMAGE}`, '.']),
          run,
        ],
      },
    },
  }
}

export function renderBuildspec({ hasRef }) {
  return toYaml(buildBuildspec({ hasRef }), {
    comments: [
      'Generated by git-bouncer for one scan. Not live-tested by the maintainer: see docs/cloud.md.',
      'The URL, ref and nonce are environment variables set by the StartBuild request. The commands',
      'below only ever refer to them inside double quotes, so their values are never parsed as shell.',
    ],
  })
}

/** The StartBuild request body (written to start-build.json and passed with --cli-input-json). */
export function buildStartBuildRequest({ project, bucket, runId, url, ref, nonce }) {
  assertScanInputs({ url, ref, nonce })
  return {
    projectName: project,
    sourceTypeOverride: 'S3',
    sourceLocationOverride: `${bucket}/${S3_PREFIX}/${runId}/`,
    buildspecOverride: renderBuildspec({ hasRef: Boolean(ref) }),
    environmentVariablesOverride: [
      { name: 'GIT_BOUNCER_URL', value: url, type: 'PLAINTEXT' },
      ...(ref ? [{ name: 'GIT_BOUNCER_REF', value: ref, type: 'PLAINTEXT' }] : []),
      { name: 'GIT_BOUNCER_NONCE', value: nonce, type: 'PLAINTEXT' },
    ],
    privilegedModeOverride: true, // CodeBuild needs privileged mode to run Docker at all
    artifactsOverride: { type: 'NO_ARTIFACTS' },
    cacheOverride: { type: 'NO_CACHE' },
    logsConfigOverride: { cloudWatchLogs: { status: 'ENABLED' }, s3Logs: { status: 'DISABLED' } },
    timeoutInMinutesOverride: AWS_LIMITS.buildTimeoutMinutes,
    queuedTimeoutInMinutesOverride: AWS_LIMITS.queuedTimeoutMinutes,
    autoRetryLimitOverride: 0, // a failed scan is reported, not silently re-run (and re-billed)
    debugSessionEnabled: false,
    idempotencyToken: runId, // a retried request can't start a second build
  }
}

/**
 * Join CloudWatch log events back into text. CodeBuild's events normally end with "\n"; if they
 * do, the messages are concatenated as they are, which also puts back together a long line that
 * was split across events. If none do, they are joined with newlines.
 */
export function joinLogEvents(events) {
  const msgs = (Array.isArray(events) ? events : []).map(e => (e && typeof e.message === 'string' ? e.message : ''))
  return msgs.some(m => m.endsWith('\n')) ? msgs.join('') : msgs.join('\n')
}

/** Settings from the environment and the config file (no commands run). */
async function readSettings(env) {
  const cfg = await loadCloudConfig(env)
  const pick = (name, key) => env[name] || cfg.aws[key] || null
  const s = {
    project: pick('GIT_BOUNCER_AWS_PROJECT', 'project'),
    bucket: pick('GIT_BOUNCER_AWS_BUCKET', 'bucket'),
    region: pick('GIT_BOUNCER_AWS_REGION', 'region') || env.AWS_REGION || env.AWS_DEFAULT_REGION || null,
    configPath: cfg.path,
  }
  if (s.project && !PROJECT_NAME.test(s.project)) throw new Error(`"${clean(s.project, { max: 80 })}" is not a valid CodeBuild project name.`)
  if (s.bucket && !BUCKET.test(s.bucket)) throw new Error(`"${clean(s.bucket, { max: 80 })}" is not a bucket name git-bouncer accepts (lowercase letters, digits and hyphens).`)
  if (s.region && !REGION.test(s.region)) throw new Error(`"${clean(s.region, { max: 80 })}" is not a valid AWS region (for example us-east-1).`)
  return s
}

/**
 * Every aws command a scan can run, in order. Values in <angle brackets> come from an earlier
 * step's output and are validated before they are filled in.
 */
export function awsSteps({ source, request, bucket, runId, region }) {
  const r = `--region=${region}`
  const prefix = `s3://${bucket}/${S3_PREFIX}/${runId}/`
  return [
    {
      id: 'upload',
      description: 'Upload git-bouncer\'s sandbox folder to your bucket.',
      cmd: 'aws',
      args: ['s3', 'cp', source, prefix, '--recursive', '--no-follow-symlinks', '--only-show-errors', r],
    },
    {
      id: 'start',
      description: 'Start a build on your CodeBuild project with git-bouncer\'s overrides. Returns the build ID at once.',
      cmd: 'aws',
      args: ['codebuild', 'start-build', `--cli-input-json=file://${request}`, r, '--output=json'],
    },
    {
      id: 'wait',
      description: 'Read the build\'s status, every 10 seconds until it has finished.',
      cmd: 'aws',
      args: ['codebuild', 'batch-get-builds', '--ids=<build-id>', r, '--output=json'],
    },
    {
      id: 'log',
      description: 'Read the build log, which contains the report between the nonce markers. Repeated with --next-token=<token> until the end of the log.',
      cmd: 'aws',
      args: ['logs', 'get-log-events', '--log-group-name=<log-group>', '--log-stream-name=<log-stream>', '--start-from-head', r, '--output=json'],
    },
    {
      id: 'cleanup-source',
      description: 'Delete the uploaded copy of the sandbox folder.',
      cmd: 'aws',
      args: ['s3', 'rm', prefix, '--recursive', '--only-show-errors', r],
    },
    {
      id: 'cancel',
      when: 'only if git-bouncer stops waiting (timeout, Ctrl-C or an error) while the build is still running',
      description: 'Stop the build so nothing keeps running or billing.',
      cmd: 'aws',
      args: ['codebuild', 'stop-build', '--id=<build-id>', r, '--output=json'],
    },
  ]
}

/**
 * @param {{exec?: Function, env?: Record<string,string>, tmpdir?: string,
 *          sleep?: (ms: number, signal?: AbortSignal) => Promise<void>}} [opts]
 */
export function createAwsRuntime({ exec = defaultExec, env = process.env, tmpdir = osTmpdir(), sleep: wait = sleep } = {}) {
  // The aws CLI reads its own config and credentials from the user's environment; it runs on the
  // host, exactly as if the user typed the command. AWS_PAGER="" stops v2 from opening a pager.
  const cliEnv = { ...env, AWS_PAGER: '' }
  const aws = (args, opts = {}) => exec('aws', args, { timeoutMs: SHORT_MS, env: cliEnv, ...opts })
  let detected = null

  async function available() {
    let settings
    try { settings = await readSettings(env) } catch (e) { return { ok: false, reason: e.message } }

    const version = await aws(['--version'])
    if (version.code !== 0) return { ok: false, reason: 'The AWS CLI (aws) is not installed or not on your PATH. See https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html' }

    if (!settings.project) return { ok: false, reason: `No CodeBuild project is configured. Create one (see docs/cloud.md), then set GIT_BOUNCER_AWS_PROJECT or "aws.project" in ${settings.configPath}.` }
    if (!settings.bucket) return { ok: false, reason: `No S3 bucket is configured for the scanner upload. Set GIT_BOUNCER_AWS_BUCKET or "aws.bucket" in ${settings.configPath}.` }

    let region = settings.region
    if (!region) {
      const r = await aws(['configure', 'get', 'region'])
      const value = r.code === 0 ? r.stdout.trim() : ''
      if (value) region = value
    }
    if (!region) return { ok: false, reason: `No AWS region is set. Set GIT_BOUNCER_AWS_REGION or "aws.region" in ${settings.configPath} to the region of your CodeBuild project.` }
    if (!REGION.test(region)) return { ok: false, reason: `"${clean(region, { max: 80 })}" is not a valid AWS region.` }

    const who = await aws(['sts', 'get-caller-identity', `--region=${region}`, '--output=json'])
    let arn = null
    try { arn = who.code === 0 ? JSON.parse(who.stdout).Arn : null } catch { arn = null }
    if (typeof arn !== 'string' || !arn) return { ok: false, reason: 'The AWS CLI is installed but not signed in (aws sts get-caller-identity failed). Run: aws configure, or aws sso login' }
    const account = clean(arn, { max: 300 })

    const proj = await aws(['codebuild', 'batch-get-projects', `--names=${settings.project}`, `--region=${region}`, '--output=json'])
    let found = false
    try { found = proj.code === 0 && JSON.parse(proj.stdout).projects.some(p => p && p.name === settings.project) } catch { found = false }
    if (proj.code !== 0) return { ok: false, account, reason: `Could not read CodeBuild project "${settings.project}" in ${region}: ${errorTail(proj, 300)}` }
    if (!found) return { ok: false, account, reason: `CodeBuild project "${settings.project}" was not found in ${region}. Create it first: see docs/cloud.md.` }

    detected = { project: settings.project, bucket: settings.bucket, region }
    return { ok: true, account, project: settings.project, region, bucket: settings.bucket }
  }

  /** Pure: reads the config file but runs no commands. Returns exactly what scan() will run. */
  async function plan({ url, ref = null, nonce, sandboxDir, workDir = TEMP_DIR_PLACEHOLDER }) {
    assertScanInputs({ url, ref, nonce })
    const settings = await readSettings(env)
    const project = settings.project || '<codebuild-project>'
    const bucket = settings.bucket || '<bucket>'
    const region = settings.region || (detected && detected.region) || '<region>'
    const runId = runIdFor(nonce)
    const at = name => (workDir === TEMP_DIR_PLACEHOLDER ? `${workDir}/${name}` : path.join(workDir, name))
    const request = buildStartBuildRequest({ project, bucket, runId, url, ref, nonce })
    const files = {
      'start-build.json': `${JSON.stringify(request, null, 2)}\n`,
      // The same buildspec that is inside start-build.json, as its own file so it's easy to read.
      'buildspec.yml': request.buildspecOverride,
    }
    const steps = awsSteps({ source: at('source'), request: at('start-build.json'), bucket, runId, region })
    const notes = [
      'Not live-tested by the maintainer, because it costs money. See docs/cloud.md before using it.',
      `${at('source')} is a copy of git-bouncer's own sandbox folder (${sandboxDir || 'sandbox/'}): the Dockerfile and the scanner. Nothing else from your machine, and nothing from the repository being checked, is uploaded.`,
      `It is uploaded to s3://${bucket}/${S3_PREFIX}/${runId}/ and deleted when the scan ends.`,
      `The build runs on your CodeBuild project ${project} in ${region}, with a ${AWS_LIMITS.buildTimeoutMinutes}-minute limit and no retries. CodeBuild bills by build-minute: https://aws.amazon.com/codebuild/pricing/`,
      'The scan container gets no credentials, no mounts and no environment variables. The URL, ref and nonce reach the build as environment variables of the CodeBuild container, and the scanner as arguments.',
      'Values in <angle brackets> are filled in from your settings or from the output of an earlier step.',
    ]
    return { steps, files, notes }
  }

  async function scan({ url, ref = null, nonce, sandboxDir, onLog = () => {}, signal } = {}) {
    assertScanInputs({ url, ref, nonce })
    assertSandboxDir(sandboxDir)
    const ready = await available()
    if (!ready.ok) throw new Error(`CodeBuild is not ready: ${ready.reason}`)
    if (!path.isAbsolute(tmpdir)) throw new Error('the temporary folder must be an absolute path')

    const workDir = await mkdtemp(path.join(tmpdir, 'git-bouncer-aws-'))
    const runId = runIdFor(nonce)
    const session = {
      runtime: 'aws', project: detected.project, region: detected.region, bucket: detected.bucket, runId, workDir,
      buildId: null, status: null, logUrl: null, uploadAttempted: false, finished: false, reportComplete: false,
      cleanup: { cancelled: false, sourceRemoved: false, workDirRemoved: false, problems: [] },
    }
    const vars = {}
    let steps
    const run = async (id, opts = {}, extraArgs = []) => {
      const filled = fillStep(steps.find(s => s.id === id), vars)
      const r = await exec(filled.cmd, [...filled.args, ...extraArgs], { timeoutMs: SHORT_MS, env: cliEnv, signal, ...opts })
      if (signal && signal.aborted) throw abortError()
      return r
    }
    const pause = async ms => { await wait(ms, signal); if (signal && signal.aborted) throw abortError() }

    try {
      const p = await plan({ url, ref, nonce, sandboxDir, workDir })
      steps = p.steps
      await copySandbox(sandboxDir, path.join(workDir, 'source'))
      await writePlanFiles(workDir, p.files)

      session.uploadAttempted = true
      const upload = await run('upload', { timeoutMs: UPLOAD_MS })
      if (upload.code !== 0) throw new Error(`Could not upload the sandbox folder to s3://${session.bucket}/: ${errorTail(upload)}`)

      const start = await run('start')
      let buildId = ''
      try { buildId = start.code === 0 ? JSON.parse(start.stdout).build.id : '' } catch { buildId = '' }
      if (typeof buildId !== 'string' || !BUILD_ID.test(buildId)) throw new Error(`CodeBuild did not start the build: ${errorTail(start)}`)
      session.buildId = vars['<build-id>'] = buildId
      onLog(`CodeBuild started build ${buildId} in ${session.region}.`)

      const started = Date.now()
      let build = null
      let failures = 0
      let lastPhase = null
      for (;;) {
        build = parseBuild(await run('wait'))
        failures = build ? 0 : failures + 1
        if (failures >= 6) throw new Error('Could not read the CodeBuild build\'s status (aws codebuild batch-get-builds kept failing).')
        if (build && build.phase && build.phase !== lastPhase) { lastPhase = build.phase; onLog(`CodeBuild: ${build.phase}`) }
        if (build && build.complete) break
        if (Date.now() - started > WAIT_MS) throw new Error('Gave up waiting for the CodeBuild build to finish.')
        await pause(POLL_MS)
      }
      Object.assign(session, { finished: true, status: build.status, logUrl: build.logUrl })

      let reportText = ''
      if (!build.logGroup || !build.logStream) {
        onLog('CodeBuild did not report a CloudWatch log for this build, so there is no report to read.')
      } else {
        vars['<log-group>'] = build.logGroup
        vars['<log-stream>'] = build.logStream
        // CloudWatch Logs takes a moment to make the last lines readable, so if the end marker isn't
        // there yet, read again a few times before giving up.
        for (let attempt = 0; attempt < LOG_ATTEMPTS; attempt += 1) {
          if (attempt > 0) await pause(5000)
          reportText = await readLog(run)
          if (hasCompleteReport(reportText, nonce)) break
        }
      }
      session.reportComplete = hasCompleteReport(reportText, nonce)
      if (!session.reportComplete) onLog(`The build log has no complete report (build status ${session.status}). See ${session.logUrl || 'the build history in the CodeBuild console'}.`)
      await cleanup(session)
      return { reportText, session }
    } catch (e) {
      await cleanup(session)
      throw e
    }
  }

  /** Read every page of the build's log stream (bounded), oldest first. */
  async function readLog(run) {
    const events = []
    let bytes = 0
    let token = null
    for (let page = 0; page < MAX_LOG_PAGES; page += 1) {
      const r = await run('log', { timeoutMs: SHORT_MS }, token ? [`--next-token=${token}`] : [])
      if (r.code !== 0) break
      let body
      try { body = JSON.parse(r.stdout) } catch { break }
      const batch = Array.isArray(body.events) ? body.events : []
      for (const e of batch) bytes += e && typeof e.message === 'string' ? e.message.length : 0
      events.push(...batch)
      const next = body.nextForwardToken
      // At the end of a stream, CloudWatch hands back the same token it was given.
      if (batch.length === 0 || typeof next !== 'string' || !LOG_TOKEN.test(next) || next === token || bytes > MAX_LOG_BYTES) break
      token = next
    }
    return joinLogEvents(events)
  }

  /**
   * Stop a build that is still running, delete the uploaded folder, remove the temp folder. Safe to
   * call more than once. Never passes the abort signal: after Ctrl-C, stopping is exactly what has
   * to happen.
   */
  async function cleanup(session) {
    const c = session.cleanup
    const steps = awsSteps({ source: '', request: '', bucket: session.bucket, runId: session.runId, region: session.region })
    const runCleanup = async (id, vars) => {
      const { cmd, args } = fillStep(steps.find(s => s.id === id), vars)
      try { return await exec(cmd, args, { timeoutMs: SHORT_MS, env: cliEnv }) } catch (e) { return { code: -1, stderr: String(e && e.message) } }
    }
    if (session.buildId && !session.finished && !c.cancelled) {
      const r = await runCleanup('cancel', { '<build-id>': session.buildId })
      if (r.code === 0) c.cancelled = true
      else c.problems.push(`Could not stop build ${session.buildId}. Stop it in the CodeBuild console, or run: aws codebuild stop-build --id ${session.buildId} --region ${session.region}`)
    }
    if (session.uploadAttempted && !c.sourceRemoved) {
      const r = await runCleanup('cleanup-source', {})
      if (r.code === 0) c.sourceRemoved = true
      else c.problems.push(`Could not delete s3://${session.bucket}/${S3_PREFIX}/${session.runId}/. It only contains git-bouncer's own sandbox files.`)
    }
    if (session.workDir && !c.workDirRemoved) {
      try { await rm(session.workDir, { recursive: true, force: true }); c.workDirRemoved = true } catch { c.problems.push(`Could not remove the temporary folder ${session.workDir}.`) }
    }
    return session
  }

  return {
    name: 'aws',
    available,
    plan,
    scan,
    /** CodeBuild containers are deleted when the build ends, so there is never a file to read back. */
    async readFile() { return null },
    /** scan() already cleans up; this repeats anything that failed and stops a build left running. */
    async destroy(session) { if (session && session.runtime === 'aws' && session.cleanup) await cleanup(session) },
  }
}

/** Pick the fields we need out of `aws codebuild batch-get-builds`, validating each. */
function parseBuild(result) {
  if (!result || result.code !== 0) return null
  let b
  try { b = JSON.parse(result.stdout).builds[0] } catch { return null }
  if (!b || typeof b !== 'object' || !STATUSES.has(b.buildStatus)) return null
  const logs = b.logs && typeof b.logs === 'object' ? b.logs : {}
  return {
    status: b.buildStatus,
    complete: b.buildComplete === true,
    phase: typeof b.currentPhase === 'string' ? clean(b.currentPhase, { max: 40 }) : null,
    logGroup: typeof logs.groupName === 'string' && LOG_NAME.test(logs.groupName) ? logs.groupName : null,
    logStream: typeof logs.streamName === 'string' && LOG_NAME.test(logs.streamName) ? logs.streamName : null,
    logUrl: typeof logs.deepLink === 'string' && logs.deepLink.startsWith('https://') ? clean(logs.deepLink, { max: 500 }) : null,
  }
}
