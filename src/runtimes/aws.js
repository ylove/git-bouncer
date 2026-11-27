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
//   2. aws s3api put-object --expected-bucket-owner, once per file: upload the folder to
//      s3://<your bucket>/git-bouncer/<run id>/. S3 refuses each request if the bucket isn't owned by
//      the account you're signed in to.
//   3. aws codebuild start-build --cli-input-json: start a build on your project, overriding the
//      source (that S3 folder), the buildspec, privileged mode (needed for Docker), artifacts (none),
//      cache (none), retries (none), timeouts and logging (CloudWatch only). The buildspec blocks the
//      cloud credential endpoints for containers, proves it with the metadata canary, then scans.
//   4. aws codebuild batch-get-builds: poll until the build has finished.
//   5. aws logs get-log-events: read the build log, which contains the nonce-framed report.
//   6. aws s3api list-objects-v2 + delete-objects: delete the upload. If interrupted, destroy() stops the
//      build (found from the project's recent builds if its ID was never seen).
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
// a double-quoted variable, so a value can't become a second command. The nonce is written to the
// scanner's stdin by printf, a shell builtin, so it is never any process's argument either. Tests
// check that the buildspec is byte-for-byte the same whatever the values are.

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir as osTmpdir } from 'node:os'
import path from 'node:path'
import { clean } from '../ui/sanitize.js'
import {
  CANARY_FAILED, CANARY_JS, SANDBOX_IMAGE, SANDBOX_PATH, SCANNER_ENTRY, TEMP_DIR_PLACEHOLDER, assertSandboxDir,
  assertScanInputs, copySandbox, errorTail, fillStep, loadCloudConfig, makeDefaultExec, reportReady,
  runIdFor, sandboxRunArgs, sleep, stoppedError, toYaml, writePlanFiles,
} from './cloud-common.js'

export const AWS_LIMITS = Object.freeze({
  buildTimeoutMinutes: 30, // the whole build; also caps the bill if git-bouncer is killed mid-scan
  queuedTimeoutMinutes: 15, // give up if CodeBuild can't start the build within 15 minutes
})

export const S3_PREFIX = 'git-bouncer'

const PROJECT_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{1,254}$/
const REGION = /^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$/
const ACCOUNT_ID = /^[0-9]{12}$/
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
const INFLIGHT_GRACE_MS = 15 * 1000
// aws CLI v2 reads `cli_auto_prompt` from the user's config; "on" would turn every call into a prompt.
const NO_PROMPT = '--no-cli-auto-prompt'

/** The shell words of a buildspec command. Only constants: never a value from the scan request. */
const SHELL_WORD = /^[A-Za-z0-9_./:=,@+-]+$/
const shellLine = words => {
  for (const w of words) if (!SHELL_WORD.test(w)) throw new Error(`internal: ${JSON.stringify(w)} is not a plain shell word`)
  return words.join(' ')
}

/**
 * The buildspec. It depends only on whether there is a ref, never on the values themselves.
 *
 * Before anything else it blocks, for containers, the two addresses where AWS hands out credentials:
 * the build host's instance metadata (169.254.169.254) and the CodeBuild credentials endpoint
 * (169.254.170.2). The commands run as root in the network namespace whose firewall the build's
 * Docker daemon uses, and DOCKER-USER is the chain Docker reserves for rules like these. /32s, so a
 * link-local DNS resolver keeps working. The canary then proves both are unreachable.
 * @param {{hasRef: boolean}} opts
 */
export function buildBuildspec({ hasRef }) {
  if (/[$'!\n\r]/.test(CANARY_JS)) throw new Error('internal: the canary script must be safe inside single quotes')
  const scan = [
    'printf \'%s\\n\' "$GIT_BOUNCER_NONCE" |',
    shellLine(['docker', ...sandboxRunArgs({ interactive: true }), 'node', SCANNER_ENTRY]),
    '--url="$GIT_BOUNCER_URL"',
    ...(hasRef ? ['--ref="$GIT_BOUNCER_REF"'] : []),
    '--nonce-stdin',
  ].join(' ')
  return {
    version: 0.2,
    env: { variables: { DOCKER_BUILDKIT: '1' } },
    phases: {
      build: {
        commands: [
          shellLine(['iptables', '-I', 'DOCKER-USER', '-d', '169.254.169.254/32', '-j', 'REJECT']),
          shellLine(['iptables', '-I', 'DOCKER-USER', '-d', '169.254.170.2/32', '-j', 'REJECT']),
          shellLine(['docker', 'build', `--tag=${SANDBOX_IMAGE}`, '.']),
          `${shellLine(['docker', ...sandboxRunArgs(), 'node', '-e'])} '${CANARY_JS}' any-answer`,
          scan,
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
 * was split across events. If none do, they are joined with newlines. Any other mix can only make
 * the report unreadable (INCOMPLETE), never make one up: only the scanner knows the nonce.
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
 * step's output (or your account) and are validated before they are filled in.
 */
export function awsSteps({ request, project, bucket, runId, region, account }) {
  const r = `--region=${region}`
  // The low-level s3api commands, because only they take --expected-bucket-owner: S3 refuses the
  // request if the bucket belongs to any other account. (The high-level `aws s3 cp/rm` can't.)
  const owner = `--expected-bucket-owner=${account}`
  return [
    {
      id: 'upload',
      description: 'Upload one file of git-bouncer\'s sandbox folder; repeated for each file (<file> is its path in the folder, <file-path> the copy on disk). Refused unless your account owns the bucket.',
      cmd: 'aws',
      args: ['s3api', 'put-object', `--bucket=${bucket}`, `--key=${S3_PREFIX}/${runId}/<file>`, '--body=<file-path>', owner, r, '--output=json', NO_PROMPT],
    },
    {
      id: 'start',
      description: 'Start a build on your CodeBuild project with git-bouncer\'s overrides. Returns the build ID at once.',
      cmd: 'aws',
      args: ['codebuild', 'start-build', `--cli-input-json=file://${request}`, r, '--output=json', NO_PROMPT],
    },
    {
      id: 'wait',
      description: 'Read the build\'s status, every 10 seconds until it has finished.',
      cmd: 'aws',
      args: ['codebuild', 'batch-get-builds', '--ids=<build-id>', r, '--output=json', NO_PROMPT],
    },
    {
      id: 'log',
      description: 'Read the build log, which contains the report between the nonce markers. Repeated with --next-token=<token> until the end of the log.',
      cmd: 'aws',
      args: ['logs', 'get-log-events', '--log-group-name=<log-group>', '--log-stream-name=<log-stream>', '--start-from-head', r, '--output=json', NO_PROMPT],
    },
    {
      id: 'cleanup-list',
      description: 'List what this run uploaded...',
      cmd: 'aws',
      args: ['s3api', 'list-objects-v2', `--bucket=${bucket}`, `--prefix=${S3_PREFIX}/${runId}/`, owner, r, '--output=json', NO_PROMPT],
    },
    {
      id: 'cleanup-delete',
      description: '...and delete it (<delete-request> lists those keys).',
      cmd: 'aws',
      args: ['s3api', 'delete-objects', `--bucket=${bucket}`, '--delete=<delete-request>', owner, r, '--output=json', NO_PROMPT],
    },
    {
      id: 'find-builds',
      when: 'only if git-bouncer is interrupted before it has seen the build ID',
      description: 'List the project\'s most recent builds...',
      cmd: 'aws',
      args: ['codebuild', 'list-builds-for-project', `--project-name=${project}`, '--sort-order=DESCENDING', '--max-items=50', r, '--output=json', NO_PROMPT],
    },
    {
      id: 'find-builds-detail',
      when: 'only if git-bouncer is interrupted before it has seen the build ID',
      description: '...and pick the running one whose source is this run\'s upload.',
      cmd: 'aws',
      args: ['codebuild', 'batch-get-builds', '--ids', '<build-ids>', r, '--output=json', NO_PROMPT],
    },
    {
      id: 'cancel',
      when: 'only if git-bouncer stops waiting (interrupt, timeout or error) while the build is still running',
      description: 'Stop the build so nothing keeps running or billing.',
      cmd: 'aws',
      args: ['codebuild', 'stop-build', '--id=<build-id>', r, '--output=json', NO_PROMPT],
    },
  ]
}

/**
 * @param {{exec?: Function, env?: Record<string,string>, tmpdir?: string, platform?: string,
 *          sleep?: (ms: number) => Promise<void>, onLog?: (line: string) => void}} [opts]
 */
export function createAwsRuntime({ exec, env = process.env, tmpdir = osTmpdir(), platform = process.platform, sleep: wait = sleep, onLog: defaultOnLog = () => {} } = {}) {
  const execFn = exec || makeDefaultExec(platform)
  // The aws CLI runs on the host, as if the user typed the command, so it gets the user's
  // environment. AWS_PAGER="" stops it from opening a pager.
  const cliEnv = { ...env, AWS_PAGER: '' }
  const aws = (args, opts = {}) => execFn('aws', args, { timeoutMs: SHORT_MS, env: cliEnv, ...opts })
  const inflight = new WeakMap()
  let detected = null

  async function available() {
    let settings
    try { settings = await readSettings(env) } catch (e) { return { ok: false, reason: e.message } }

    const version = await aws(['--version'])
    if (version.code !== 0) return { ok: false, reason: 'The AWS CLI (aws) is not installed or not on your PATH. See https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html' }
    const major = Number((/aws-cli\/(\d+)\./.exec(`${version.stdout} ${version.stderr}`) || [])[1])
    if (major !== 2) return { ok: false, reason: 'git-bouncer needs version 2 of the AWS CLI (version 1 fetches any http(s):// value it is given as a URL, and lacks --no-cli-auto-prompt).' }

    if (!settings.project) return { ok: false, reason: `No CodeBuild project is configured. Create one (see docs/cloud.md), then set GIT_BOUNCER_AWS_PROJECT or "aws.project" in ${settings.configPath}.` }
    if (!settings.bucket) return { ok: false, reason: `No S3 bucket is configured for the scanner upload. Set GIT_BOUNCER_AWS_BUCKET or "aws.bucket" in ${settings.configPath}.` }

    let region = settings.region
    if (!region) {
      const r = await aws(['configure', 'get', 'region', NO_PROMPT])
      const value = r.code === 0 ? r.stdout.trim() : ''
      if (value) region = value
    }
    if (!region) return { ok: false, reason: `No AWS region is set. Set GIT_BOUNCER_AWS_REGION or "aws.region" in ${settings.configPath} to the region of your CodeBuild project.` }
    if (!REGION.test(region)) return { ok: false, reason: `"${clean(region, { max: 80 })}" is not a valid AWS region.` }

    const who = await aws(['sts', 'get-caller-identity', `--region=${region}`, '--output=json', NO_PROMPT])
    let ident = null
    try { ident = who.code === 0 ? JSON.parse(who.stdout) : null } catch { ident = null }
    if (!ident || typeof ident.Arn !== 'string' || !ACCOUNT_ID.test(String(ident.Account))) {
      return { ok: false, reason: 'The AWS CLI is installed but not signed in (aws sts get-caller-identity failed). Run: aws configure, or aws sso login' }
    }
    const account = String(ident.Account)
    const arn = clean(ident.Arn, { max: 300 })

    // Bucket names are global. If the configured name ever isn't yours (a typo, or a bucket you
    // deleted and someone else claimed), its owner could swap the scanner after the upload, and
    // CodeBuild would run their code in privileged mode. So: your account must own it.
    const head = await aws(['s3api', 'head-bucket', `--bucket=${settings.bucket}`, `--expected-bucket-owner=${account}`, `--region=${region}`, '--output=json', NO_PROMPT])
    if (head.code !== 0) return { ok: false, account: arn, reason: `The bucket ${settings.bucket} does not exist, can't be reached, or is not owned by your account (${account}). git-bouncer only uploads to a bucket your own account owns.` }

    const proj = await aws(['codebuild', 'batch-get-projects', `--names=${settings.project}`, `--region=${region}`, '--output=json', NO_PROMPT])
    let found = false
    try { found = proj.code === 0 && JSON.parse(proj.stdout).projects.some(p => p && p.name === settings.project) } catch { found = false }
    if (proj.code !== 0) return { ok: false, account: arn, reason: `Could not read CodeBuild project "${settings.project}" in ${region}: ${errorTail(proj, 300)}` }
    if (!found) return { ok: false, account: arn, reason: `CodeBuild project "${settings.project}" was not found in ${region}. Create it first: see docs/cloud.md.` }

    detected = { project: settings.project, bucket: settings.bucket, region, account }
    return { ok: true, account: arn, project: settings.project, region, bucket: settings.bucket }
  }

  /** Pure: reads the config file but runs no commands. Returns exactly what scan() will run. */
  async function plan({ url, ref = null, nonce, sandboxDir, workDir = TEMP_DIR_PLACEHOLDER }) {
    assertScanInputs({ url, ref, nonce })
    const settings = await readSettings(env)
    const project = settings.project || '<codebuild-project>'
    const bucket = settings.bucket || '<bucket>'
    const region = settings.region || (detected && detected.region) || '<region>'
    const account = (detected && detected.account) || '<account-id>'
    const runId = runIdFor(nonce)
    const at = name => (workDir === TEMP_DIR_PLACEHOLDER ? `${workDir}/${name}` : path.join(workDir, name))
    const request = buildStartBuildRequest({ project, bucket, runId, url, ref, nonce })
    const files = {
      'start-build.json': `${JSON.stringify(request, null, 2)}\n`,
      // The same buildspec that is inside start-build.json, as its own file so it's easy to read.
      'buildspec.yml': request.buildspecOverride,
    }
    const steps = awsSteps({ request: at('start-build.json'), project, bucket, runId, region, account })
    const notes = [
      'Not live-tested by the maintainer, because it costs money. See docs/cloud.md before using it.',
      `${at('source')} is a copy of git-bouncer's own sandbox folder (${sandboxDir || 'sandbox/'}): the Dockerfile and the scanner. Nothing else from your machine, and nothing from the repository being checked, is uploaded. The upload step runs once per file in it.`,
      `It is uploaded to s3://${bucket}/${S3_PREFIX}/${runId}/ (only if your account owns the bucket) and deleted when the scan ends.`,
      `The build runs on your CodeBuild project ${project} in ${region}, with a ${AWS_LIMITS.buildTimeoutMinutes}-minute limit and no retries. CodeBuild bills by build-minute: https://aws.amazon.com/codebuild/pricing/`,
      'The buildspec blocks the instance metadata and CodeBuild credential addresses for containers, and a canary step fails the build if the sandbox can still reach either.',
      'The scan container gets no credentials, no mounts and no environment variables, and reads its nonce from stdin.',
      'Values in <angle brackets> are filled in from your settings or from the output of an earlier step.',
    ]
    return { steps, files, notes }
  }

  async function scan({ url, ref = null, nonce, sandboxDir, onLog = defaultOnLog, onSession = () => {} } = {}) {
    assertScanInputs({ url, ref, nonce })
    assertSandboxDir(sandboxDir)
    const ready = await available()
    if (!ready.ok) throw new Error(`CodeBuild is not ready: ${ready.reason}`)
    if (!path.isAbsolute(tmpdir)) throw new Error('the temporary folder must be an absolute path')

    const runId = runIdFor(nonce)
    const workDir = await mkdtemp(path.join(tmpdir, 'git-bouncer-aws-'))
    const session = {
      runtime: 'aws', name: `git-bouncer-run-${runId}`, runId,
      project: detected.project, region: detected.region, bucket: detected.bucket, account: detected.account,
      source: `s3://${detected.bucket}/${S3_PREFIX}/${runId}/`, workDir,
      buildId: null, status: null, logUrl: null,
      uploadStarted: false, startStarted: false, finished: false, destroyed: false, reportComplete: false,
      cleanup: { buildSettled: false, stopped: [], sourceRemoved: false, workDirRemoved: false, problems: [] },
    }
    // Everything destroy() needs is in the session before anything exists in the cloud.
    onSession(session)

    const vars = {}
    let steps
    const run = async (id, { vars: extra = {}, ...opts } = {}, extraArgs = []) => {
      if (session.destroyed) throw stoppedError(session)
      const filled = fillStep(steps.find(s => s.id === id), { ...vars, ...extra })
      const p = execFn(filled.cmd, [...filled.args, ...extraArgs], { timeoutMs: SHORT_MS, env: cliEnv, ...opts })
      inflight.set(session, p)
      try { return await p } finally { inflight.delete(session) }
    }

    try {
      const p = await plan({ url, ref, nonce, sandboxDir, workDir })
      steps = p.steps
      const copied = await copySandbox(sandboxDir, path.join(workDir, 'source'))
      await writePlanFiles(workDir, p.files)

      session.uploadStarted = true
      for (const file of copied.paths) {
        const upload = await run('upload', { timeoutMs: UPLOAD_MS, vars: { '<file>': file, '<file-path>': path.join(workDir, 'source', ...file.split('/')) } })
        if (upload.code !== 0) throw new Error(`Could not upload the sandbox folder to s3://${session.bucket}/: ${errorTail(upload)}`)
      }

      session.startStarted = true
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
        await wait(POLL_MS)
      }
      Object.assign(session, { finished: true, status: build.status, logUrl: build.logUrl })

      let reportText = ''
      if (!build.logGroup || !build.logStream) {
        onLog('CodeBuild did not report a CloudWatch log for this build, so there is no report to read.')
      } else {
        vars['<log-group>'] = build.logGroup
        vars['<log-stream>'] = build.logStream
        // The build has finished, but CloudWatch can take a moment to make the last lines readable.
        // Keep reading forward from where the last read ended, until the CLI would accept the report
        // or the attempts run out.
        const cursor = { token: null, events: [], bytes: 0, pages: 0 }
        for (let attempt = 0; attempt < LOG_ATTEMPTS; attempt += 1) {
          if (attempt > 0) await wait(5000)
          await readLog(run, cursor)
          reportText = joinLogEvents(cursor.events)
          if (reportReady(reportText, nonce)) break
        }
      }
      session.reportComplete = reportReady(reportText, nonce)
      if (!session.reportComplete && reportText.split('\n').some(l => l.startsWith(CANARY_FAILED))) {
        throw new Error('The metadata canary failed: the sandbox could still reach a cloud credential endpoint. git-bouncer will not scan in this setup. See "Security notes" in docs/cloud.md.')
      }
      if (!session.reportComplete) onLog(`The build log has no complete report (build status ${session.status}). See ${session.logUrl || 'the build history in the CodeBuild console'}.`)
      await cleanup(session)
      return { reportText, session }
    } catch (e) {
      await cleanup(session)
      throw Object.assign(e, { session })
    }
  }

  /**
   * Read the log stream forward from `cursor.token` to its current end. Empty pages don't end it:
   * GetLogEvents can return no events while more are available. The end is when CloudWatch hands
   * back the token it was given. Bounded by page and byte caps.
   */
  async function readLog(run, cursor) {
    while (cursor.pages < MAX_LOG_PAGES && cursor.bytes <= MAX_LOG_BYTES) {
      cursor.pages += 1
      const r = await run('log', { timeoutMs: SHORT_MS }, cursor.token ? [`--next-token=${cursor.token}`] : [])
      if (r.code !== 0) return
      let body
      try { body = JSON.parse(r.stdout) } catch { return }
      const batch = Array.isArray(body.events) ? body.events : []
      for (const e of batch) cursor.bytes += e && typeof e.message === 'string' ? e.message.length : 0
      cursor.events.push(...batch)
      const next = body.nextForwardToken
      if (typeof next !== 'string' || !LOG_TOKEN.test(next)) return
      if (next === cursor.token) return // the end of the stream, for now
      cursor.token = next
    }
  }

  /** The project's running builds whose source is this run's upload (null if the lookup failed). */
  async function findBuilds(session) {
    const steps = sessionSteps(session)
    const list = fillStep(steps.find(s => s.id === 'find-builds'), {})
    const r = await execFn(list.cmd, list.args, { timeoutMs: SHORT_MS, env: cliEnv })
    let ids
    try { ids = r.code === 0 ? JSON.parse(r.stdout).ids : null } catch { ids = null }
    if (!Array.isArray(ids)) return null
    ids = ids.filter(id => typeof id === 'string' && BUILD_ID.test(id) && id.startsWith(`${session.project}:`)).slice(0, 50)
    if (ids.length === 0) return []
    const detail = fillStep(steps.find(s => s.id === 'find-builds-detail'), { '<build-ids>': ids })
    const d = await execFn(detail.cmd, detail.args, { timeoutMs: SHORT_MS, env: cliEnv })
    let builds
    try { builds = d.code === 0 ? JSON.parse(d.stdout).builds : null } catch { builds = null }
    if (!Array.isArray(builds)) return null
    const location = `${session.bucket}/${S3_PREFIX}/${session.runId}/`
    return builds.filter(b => b && b.buildStatus === 'IN_PROGRESS' && b.source && b.source.location === location && BUILD_ID.test(b.id)).map(b => b.id)
  }

  const sessionSteps = session => awsSteps({ request: '', project: session.project, bucket: session.bucket, runId: session.runId, region: session.region, account: session.account })

  /**
   * Stop a build that may still be running, delete the uploaded folder, remove the temp folder.
   * Safe to call more than once, and while scan() is still running (that's what an interrupt does).
   * After it, scan() starts nothing new.
   */
  async function cleanup(session) {
    session.destroyed = true
    const c = session.cleanup
    const steps = sessionSteps(session)
    const runStep = async (id, vars = {}) => {
      const { cmd, args } = fillStep(steps.find(s => s.id === id), vars)
      return execFn(cmd, args, { timeoutMs: SHORT_MS, env: cliEnv })
    }
    if (session.startStarted && !c.buildSettled) {
      if (session.finished) {
        c.buildSettled = true
      } else {
        // If start-build is still on its way, give it a moment, so the lookup can see the build.
        const pending = inflight.get(session)
        if (!session.buildId && pending) await Promise.race([pending, wait(INFLIGHT_GRACE_MS)])
        const ids = session.buildId ? [session.buildId] : await findBuilds(session)
        if (ids === null) {
          c.problems.push(`Could not look for a running build of ${session.project}. Check its build history and stop any build whose source is ${session.source}.`)
        } else {
          let ok = true
          for (const id of ids.filter(i => !c.stopped.includes(i))) {
            const r = await runStep('cancel', { '<build-id>': id })
            if (r.code === 0) c.stopped.push(id)
            else { ok = false; c.problems.push(`Could not stop build ${id}. Stop it in the CodeBuild console, or run: aws codebuild stop-build --id ${id} --region ${session.region}`) }
          }
          // Found nothing? The build may not exist yet, so stay unsettled: if scan() learns the ID
          // afterwards, the next cleanup stops it by ID.
          c.buildSettled = ok && ids.length > 0
        }
      }
    }
    if (session.uploadStarted && !c.sourceRemoved) {
      // List what is actually there (an interrupted upload may be partial), then delete exactly that.
      const prefix = `${S3_PREFIX}/${session.runId}/`
      const list = await runStep('cleanup-list')
      let keys = null
      try { keys = list.code === 0 ? (JSON.parse(list.stdout || '{}').Contents || []).map(o => o && o.Key) : null } catch { keys = null }
      if (keys && keys.every(k => typeof k === 'string' && k.startsWith(prefix) && SANDBOX_PATH.test(k.slice(prefix.length)))) {
        const del = keys.length ? await runStep('cleanup-delete', { '<delete-request>': JSON.stringify({ Objects: keys.map(Key => ({ Key })), Quiet: true }) }) : { code: 0 }
        if (del.code === 0) c.sourceRemoved = true
      }
      if (!c.sourceRemoved) c.problems.push(`Could not delete ${session.source}. It only contains git-bouncer's own sandbox files.`)
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
    /** Stops a build left running (found by its source if need be) and deletes the upload. Idempotent. */
    async destroy(session) { if (session && session.runtime === 'aws' && session.cleanup) await cleanup(session) },
    describe() {
      return detected
        ? `AWS CodeBuild project ${detected.project} in ${detected.region} (billed to your account; not live-tested by the maintainer)`
        : 'AWS CodeBuild (billed to your account; not live-tested by the maintainer)'
    },
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
