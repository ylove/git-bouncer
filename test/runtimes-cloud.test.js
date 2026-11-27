// Tests for the cloud runtimes (GCP Cloud Build, AWS CodeBuild).
//
// These never touch a real cloud and never run gcloud or aws: every test injects a fake `exec`
// that records the exact argument arrays and answers with canned output. The only real program
// started here is Node itself (to run the metadata canary against a fake fetch).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, symlink } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseRepoUrl } from '../src/url.js'
import { extractReport } from '../src/report.js'
import { runArgs, sandboxFlags } from '../src/runtimes/container.js'
import {
  CANARY_JS, SANDBOX_IMAGE, assertScanInputs, canaryCommand, cloudConfigPath, copySandbox, fillStep,
  loadCloudConfig, makeDefaultExec, reportReady, runIdFor, sandboxRunArgs, scannerCommand, toYaml,
} from '../src/runtimes/cloud-common.js'
import {
  DOCKER_BUILDER, NONCE_WRAPPER, buildCloudbuildConfig, createGcpRuntime, extractStepOutput, renderCloudbuildYaml,
} from '../src/runtimes/gcp.js'
import {
  buildBuildspec, buildStartBuildRequest, createAwsRuntime, joinLogEvents, renderBuildspec,
} from '../src/runtimes/aws.js'

// Written as ${AT} so the CI hygiene check (which fails on anything shaped like an email address) stays strict.
const AT = '@'
const NONCE = '0123456789abcdef0123456789abcdef'
const URL_ = 'https://github.com/someone/take-home-test.git'
const SA = `git-bouncer-scan${AT}my-project-123.iam.gserviceaccount.com`
const GCP_BUILD_ID = '5f2b8c1e-3a4d-4e6f-9a0b-1c2d3e4f5a6b'
const AWS_BUILD_ID = 'git-bouncer:7d6c5b4a-3e2f-4a1b-8c9d-0e1f2a3b4c5d'
const ACCOUNT = '123456789012'
const RUN_ID = runIdFor(NONCE)
const SRC_DIR = fileURLToPath(new URL('../src/runtimes/', import.meta.url))

const report = nonce => [
  '',
  `-----BEGIN BOUNCER REPORT ${nonce}-----`,
  '{"schema":1,"status":"ok","findings":[]}',
  `-----END BOUNCER REPORT ${nonce}-----`,
]

/** A fake exec: records every call, answers from `respond`, and flags anything unexpected. */
function fakeExec(respond) {
  const calls = []
  const unexpected = []
  const exec = async (cmd, args, opts = {}) => {
    assert.equal(typeof cmd, 'string')
    assert.ok(Array.isArray(args), 'exec must get an argument array, never a command string')
    for (const a of args) {
      assert.equal(typeof a, 'string')
      assert.doesNotMatch(a, /[\r\n\0]/, 'no argument contains a newline or NUL')
    }
    calls.push({ cmd, args: [...args], opts })
    const r = await respond(cmd, args, opts)
    if (!r) { unexpected.push([cmd, ...args].join(' ')); return { code: 99, stdout: '', stderr: 'unexpected command' } }
    return { code: 0, stdout: '', stderr: '', ...r }
  }
  return { exec, calls, unexpected, argv: () => calls.map(c => [c.cmd, ...c.args]) }
}
const noExec = async () => { throw new Error('plan() must not run any command') }
const noSleep = async () => {}
const never = () => new Promise(() => {})
const starts = (args, prefix) => args.join(' ').startsWith(prefix)

async function makeSandbox() {
  const dir = await mkdtemp(path.join(tmpdir(), 'gb-test-sandbox-'))
  await writeFile(path.join(dir, 'Dockerfile'), 'FROM scratch\n')
  await writeFile(path.join(dir, 'osv-scanner.toml'), '# empty\n')
  await mkdir(path.join(dir, 'scanner'))
  await writeFile(path.join(dir, 'scanner', 'main.js'), '// scanner\n')
  await writeFile(path.join(dir, 'scanner', 'package.json'), '{}\n')
  return dir
}
const listTree = async dir => (await readdir(dir, { recursive: true })).map(p => p.split(path.sep).join('/')).sort()
const emptyHome = () => mkdtemp(path.join(tmpdir(), 'gb-test-home-'))

/** Run a test body with a fresh HOME and sandbox folder, removed afterwards. */
async function withDirs(fn) {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  try { await fn({ home, sandbox }) } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
}

// ---------------------------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------------------------

test('toYaml writes every string as a JSON-quoted scalar', () => {
  const yaml = toYaml({ a: 'x', n: 0.2, b: true, list: ['no', 'on', '1e3', '0x1F', 'null', '~'], map: { k: 'v' }, empty: [], none: {} })
  assert.equal(yaml, [
    'a: "x"', 'n: 0.2', 'b: true', 'list:', '  - "no"', '  - "on"', '  - "1e3"', '  - "0x1F"', '  - "null"', '  - "~"',
    'map:', '  k: "v"', 'empty: []', 'none: {}', '',
  ].join('\n'))
})

test('toYaml nests lists of maps the way Cloud Build and CodeBuild expect', () => {
  const yaml = toYaml({ steps: [{ id: 'a', args: ['x', 'y'], env: { K: 'v' } }, { id: 'b' }] }, { comments: ['header'] })
  assert.equal(yaml, ['# header', 'steps:', '  - id: "a"', '    args:', '      - "x"', '      - "y"', '    env:', '      K: "v"', '  - id: "b"', ''].join('\n'))
})

test('toYaml keeps hostile strings inside one scalar: YAML syntax in a value stays data', () => {
  const hostile = [
    '"', '\\', '": x', '- item', '# comment', '&anchor', '*alias', '!!python/object/apply:os.system', '{a: 1}', '[1, 2]',
    '|', '>', '%YAML 1.1', '---', '...', '@', '`id`', "'", '${PROJECT_ID}', 'key: value', '"\\"', ' leading', 'trailing ',
  ]
  for (let c = 0x20; c <= 0x7e; c += 1) hostile.push(String.fromCharCode(c))
  for (const s of hostile) {
    const lines = toYaml({ list: [s], key: s }).split('\n')
    assert.equal(lines.length, 4, JSON.stringify(s))
    assert.equal(lines[0], 'list:')
    assert.equal(JSON.parse(lines[1].slice(4)), s, 'the item decodes back to exactly the input')
    assert.equal(JSON.parse(lines[2].slice('key: '.length)), s)
  }
})

test('toYaml refuses anything it cannot write safely instead of escaping it', () => {
  for (const s of ['a\nb', 'a\rb', 'a\tb', '\x1b[2K', '\u0085', '\u2028', 'caf\u00e9', '\0']) {
    assert.throws(() => toYaml({ k: s }), /printable ASCII/, JSON.stringify(s))
  }
  assert.throws(() => toYaml({ 'bad key': 'x' }), /unsupported key/)
  assert.throws(() => toYaml({ k: null }), /unsupported value/)
  assert.throws(() => toYaml({ k: Number.NaN }), /unsupported value/)
  assert.throws(() => toYaml({ k: [['nested']] }), /nested lists/)
  assert.throws(() => toYaml({ k: 'x' }, { comments: ['line\nbreak'] }), /printable ASCII/)
})

test('assertScanInputs accepts exactly what the CLI\'s URL and ref validators produce', () => {
  for (const input of ['someone/take-home-test', 'https://gitlab.com/group/sub~group/re.po_-x', 'git' + AT + 'github.com:o/r.git', 'codeberg.org/a/b']) {
    assert.doesNotThrow(() => assertScanInputs({ url: parseRepoUrl(input).url, ref: null, nonce: NONCE }), input)
  }
  for (const ref of ['main', 'v1.2.3', 'feature/-rf+x' + AT + 'y', 'f'.repeat(40)]) {
    assert.doesNotThrow(() => assertScanInputs({ url: URL_, ref, nonce: NONCE }), ref)
  }
})

test('assertScanInputs refuses values a shell or a YAML file could give meaning to (defense in depth)', () => {
  const badUrls = [
    'https://github.com/o/$(id).git', 'https://github.com/o/`id`.git', 'https://github.com/o/r;id.git', 'https://github.com/o/"r".git',
    "https://github.com/o/'r'.git", 'https://github.com/o/r r.git', 'https://github.com/o/r\n.git', 'https://github.com/o/${PROJECT_ID}.git',
    'http://github.com/o/r.git', 'https://user' + AT + 'github.com/o/r.git', 'https://github.com/o/r', 'https://github.com/r.git',
    'https://github.com/-o/r.git', 'https://github.com/../r.git', 'file:///etc/passwd.git', '--upload-pack=x',
  ]
  for (const url of badUrls) assert.throws(() => assertScanInputs({ url, nonce: NONCE }), /repository URL/, url)
  for (const ref of ['$(id)', '$PROJECT_ID', 'a b', 'x\ny', '--upload-pack=x', '-x', 'a;b', '`id`', '"q"', '']) {
    assert.throws(() => assertScanInputs({ url: URL_, ref, nonce: NONCE }), /ref/, JSON.stringify(ref))
  }
  for (const nonce of ['', 'abc', NONCE.toUpperCase(), `${NONCE}\n`, `${NONCE} `, 'g'.repeat(32), '0'.repeat(65), undefined]) {
    assert.throws(() => assertScanInputs({ url: URL_, nonce }), /nonce/, JSON.stringify(nonce))
  }
})

test('the scanner gets its nonce on stdin, never as an argument', () => {
  assert.deepEqual(scannerCommand({ url: URL_, ref: 'v1' }), ['node', '/opt/bouncer/scanner/main.js', `--url=${URL_}`, '--ref=v1', '--nonce-stdin'])
  assert.deepEqual(scannerCommand({ url: URL_, ref: null }), ['node', '/opt/bouncer/scanner/main.js', `--url=${URL_}`, '--nonce-stdin'])
})

test('cloud sandboxes use the local runtime\'s hardening flags, from the one place they are defined', () => {
  const flags = sandboxFlags()
  assert.deepEqual(runArgs({ name: 'n', image: 'img' }), ['run', '--detach', '--name', 'n', ...flags, 'img'])
  assert.deepEqual(sandboxRunArgs(), ['run', '--rm', ...flags, SANDBOX_IMAGE])
  assert.deepEqual(sandboxRunArgs({ interactive: true }), ['run', '--rm', '--interactive', ...flags, SANDBOX_IMAGE])
  for (const f of ['--init', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--pull=never']) assert.ok(flags.includes(f), f)
  assert.equal(flags[flags.indexOf('--network') + 1], 'bridge')
  for (const forbidden of ['-v', '--volume', '--mount', '-e', '--env', '--env-file', '--privileged', '--cap-add', 'host', 'cloudbuild']) {
    assert.ok(!flags.includes(forbidden), forbidden)
  }
})

test('the metadata canary is a safe constant, and fails exactly when it should', () => {
  assert.doesNotMatch(CANARY_JS, /[$'!\n\r]/, 'no $ (Cloud Build), no single quote (AWS shell), no !, one line')
  assert.deepEqual(canaryCommand('token'), ['node', '-e', CANARY_JS, 'token'])
  // Run the real script under Node with fetch replaced, so no network is touched.
  const runCanary = (fetchBody, mode) => spawnSync(process.execPath, ['-e', `globalThis.fetch = ${fetchBody}; ${CANARY_JS}`, mode], { encoding: 'utf8', timeout: 30_000 })
  const answer = status => `async () => ({ status: ${status}, body: null })`
  const unreachable = 'async () => { throw new TypeError("fetch failed") }'
  let r = runCanary(unreachable, 'token')
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stdout, /metadata canary: passed/)
  r = runCanary(answer(200), 'token')
  assert.equal(r.status, 1)
  assert.match(r.stdout, /metadata canary: FAILED/)
  assert.equal(runCanary(answer(403), 'token').status, 0, 'GCP: an answer without a token is not a token')
  assert.equal(runCanary(answer(403), 'any-answer').status, 1, 'AWS: the endpoints are blocked, so any answer means the block failed')
  assert.equal(runCanary(unreachable, 'any-answer').status, 0)
})

test('reportReady uses the CLI\'s own report rules', () => {
  assert.ok(reportReady(report(NONCE).join('\n'), NONCE))
  assert.ok(!reportReady(report(NONCE).join('\r\n'), NONCE), 'CRLF is rejected by extractReport, so the retry loop must not stop on it')
  const gap = [...report(NONCE).slice(0, 3), 'stray line', report(NONCE)[3]].join('\n')
  assert.ok(!reportReady(gap, NONCE), 'markers must be adjacent to the one JSON line')
  assert.ok(!reportReady(report(NONCE).join('\n'), 'f'.repeat(32)))
  assert.equal(reportReady(report(NONCE).join('\n'), NONCE), extractReport(report(NONCE).join('\n'), NONCE).report !== null)
})

test('runIdFor is deterministic, short, hex, and does not reveal the nonce', () => {
  assert.match(RUN_ID, /^[0-9a-f]{24}$/)
  assert.equal(runIdFor(NONCE), RUN_ID)
  assert.notEqual(runIdFor('f'.repeat(32)), RUN_ID)
  assert.ok(!NONCE.includes(RUN_ID) && !RUN_ID.includes(NONCE.slice(0, 8)))
})

test('fillStep replaces known placeholders, expands a list placeholder, and refuses unknown ones', () => {
  const step = { cmd: 'gcloud', args: ['builds', 'log', '<build-id>', '--x=<build-id>'] }
  assert.deepEqual(fillStep(step, { '<build-id>': 'abc' }), { cmd: 'gcloud', args: ['builds', 'log', 'abc', '--x=abc'] })
  assert.deepEqual(fillStep({ cmd: 'aws', args: ['--ids', '<build-ids>', '--x'] }, { '<build-ids>': ['a', 'b'] }).args, ['--ids', 'a', 'b', '--x'])
  assert.throws(() => fillStep(step, {}), /no value for <build-id>/)
})

test('cloud config: the XDG location, and strict checking', async () => {
  const home = await emptyHome()
  try {
    assert.equal(cloudConfigPath({ HOME: home }), path.join(home, '.config', 'git-bouncer', 'cloud.json'))
    assert.equal(cloudConfigPath({ HOME: home, XDG_CONFIG_HOME: path.join(home, 'xdg') }), path.join(home, 'xdg', 'git-bouncer', 'cloud.json'))
    assert.equal(cloudConfigPath({ HOME: home, XDG_CONFIG_HOME: 'relative/path' }), path.join(home, '.config', 'git-bouncer', 'cloud.json'))
    assert.deepEqual(await loadCloudConfig({ HOME: home }), { path: cloudConfigPath({ HOME: home }), gcp: {}, aws: {} })

    const file = cloudConfigPath({ HOME: home })
    await mkdir(path.dirname(file), { recursive: true })
    await writeFile(file, JSON.stringify({ aws: { project: 'git-bouncer', region: 'us-east-1', bucket: 'my-bucket' }, gcp: { project: 'my-project-123', serviceAccount: SA, bucket: 'my-bouncer' } }))
    const cfg = await loadCloudConfig({ HOME: home })
    assert.deepEqual(cfg.aws, { project: 'git-bouncer', region: 'us-east-1', bucket: 'my-bucket' })
    assert.deepEqual(cfg.gcp, { project: 'my-project-123', serviceAccount: SA, bucket: 'my-bouncer' })

    await writeFile(file, JSON.stringify({ aws: { regoin: 'us-east-1' } }))
    await assert.rejects(loadCloudConfig({ HOME: home }), /unknown setting "aws\.regoin"/)
    await writeFile(file, JSON.stringify({ azure: {} }))
    await assert.rejects(loadCloudConfig({ HOME: home }), /unknown section "azure"/)
    await writeFile(file, JSON.stringify({ aws: { project: 7 } }))
    await assert.rejects(loadCloudConfig({ HOME: home }), /must be a non-empty string/)
    await writeFile(file, '{ not json')
    await assert.rejects(loadCloudConfig({ HOME: home }), /not valid JSON/)
  } finally {
    await rm(home, { recursive: true, force: true })
  }
})

test('copySandbox copies plain files and folders, and nothing else', async t => {
  const sandbox = await makeSandbox()
  const out = await mkdtemp(path.join(tmpdir(), 'gb-test-copy-'))
  try {
    assert.equal((await copySandbox(sandbox, path.join(out, 'source'))).files, 4)
    assert.deepEqual(await listTree(path.join(out, 'source')), ['Dockerfile', 'osv-scanner.toml', 'scanner', 'scanner/main.js', 'scanner/package.json'])
    await assert.rejects(copySandbox(sandbox, path.join(out, 'source')), /EEXIST/, 'never copies over an existing folder')
    try {
      await symlink(path.join(sandbox, 'Dockerfile'), path.join(sandbox, 'scanner', 'link'))
    } catch {
      t.diagnostic('this system does not allow creating symlinks; skipped the symlink case')
      return
    }
    await assert.rejects(copySandbox(sandbox, path.join(out, 'again')), /not a plain file or folder/)
  } finally {
    await rm(sandbox, { recursive: true, force: true })
    await rm(out, { recursive: true, force: true })
  }
})

test('the default exec finds programs on absolute PATH entries only, and reports a missing one', async t => {
  const exec = makeDefaultExec()
  const node = await exec(path.basename(process.execPath, '.exe'), ['-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', '--', '$(echo pwned)', 'a; b', '%PATH%'], { env: { ...process.env, PATH: path.dirname(process.execPath) }, timeoutMs: 30_000 })
  assert.equal(node.code, 0, node.stderr)
  assert.deepEqual(JSON.parse(node.stdout), ['$(echo pwned)', 'a; b', '%PATH%'], 'arguments arrive untouched: no shell')

  const missing = await exec('git-bouncer-no-such-program', ['--version'], { env: { PATH: path.dirname(process.execPath) } })
  assert.equal(missing.code, -1)
  assert.equal(missing.error.code, 'ENOENT')
  const relative = await exec(path.basename(process.execPath, '.exe'), ['--version'], { env: { PATH: '.' } })
  assert.equal(relative.code, -1, 'a relative PATH entry is never searched')

  if (process.platform !== 'win32') { t.diagnostic('the .cmd refusal only applies on Windows'); return }
  const dir = await mkdtemp(path.join(tmpdir(), 'gb-test-cmd-'))
  try {
    await writeFile(path.join(dir, 'fakecli.cmd'), '@echo off\r\necho hi\r\n')
    const r = await makeDefaultExec('win32')('fakecli', [], { env: { PATH: dir, PATHEXT: '.CMD' } })
    assert.equal(r.code, -1, 'a .cmd file is never started')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('the cloud runtimes never import child_process or use a shell option themselves', async () => {
  const files = (await readdir(SRC_DIR)).filter(f => /^(cloud-common|gcp|aws)\.js$/.test(f))
  assert.equal(files.length, 3)
  for (const file of files) {
    const src = await readFile(path.join(SRC_DIR, file), 'utf8')
    assert.doesNotMatch(src, /node:child_process/, `${file} goes through src/proc.js`)
    assert.doesNotMatch(src, /shell:\s*true/, file)
  }
})

// ---------------------------------------------------------------------------------------------
// GCP Cloud Build
// ---------------------------------------------------------------------------------------------

const FLAGS_YAML = sandboxFlags().map(f => `      - ${JSON.stringify(f)}`).join('\n')
const EXPECTED_CLOUDBUILD_YAML = `# Generated by git-bouncer for one scan. Not live-tested by the maintainer: see docs/cloud.md.
# Step 1 builds the sandbox image from git-bouncer's own sandbox/ folder. Step 2 checks that the
# sandbox cannot get credentials from the metadata server. Step 3 runs the scanner with no
# credentials, no mounts and the same hardening as a local scan; its nonce arrives on stdin.
steps:
  - id: "build-sandbox-image"
    name: "${DOCKER_BUILDER}"
    env:
      - "DOCKER_BUILDKIT=1"
    args:
      - "build"
      - "--tag=git-bouncer-sandbox:scan"
      - "."
    timeout: "900s"
  - id: "metadata-canary"
    name: "${DOCKER_BUILDER}"
    args:
      - "run"
      - "--rm"
${FLAGS_YAML}
      - "git-bouncer-sandbox:scan"
      - "node"
      - "-e"
      - ${JSON.stringify(CANARY_JS)}
      - "token"
    timeout: "120s"
  - id: "scan"
    name: "${DOCKER_BUILDER}"
    entrypoint: "bash"
    env:
      - "GIT_BOUNCER_NONCE=${NONCE}"
    args:
      - "-c"
      - "printf '%s\\\\n' \\"$$GIT_BOUNCER_NONCE\\" | docker \\"$$@\\""
      - "bash"
      - "run"
      - "--rm"
      - "--interactive"
${FLAGS_YAML}
      - "git-bouncer-sandbox:scan"
      - "node"
      - "/opt/bouncer/scanner/main.js"
      - "--url=https://github.com/someone/take-home-test.git"
      - "--ref=v1.2.3"
      - "--nonce-stdin"
    timeout: "1200s"
timeout: "1800s"
queueTtl: "900s"
tags:
  - "git-bouncer"
  - "git-bouncer-run-${RUN_ID}"
serviceAccount: "projects/my-project-123/serviceAccounts/${SA}"
options:
  logging: "CLOUD_LOGGING_ONLY"
`

test('gcp: the generated cloudbuild.yaml, exactly', () => {
  assert.equal(renderCloudbuildYaml({ url: URL_, ref: 'v1.2.3', nonce: NONCE, project: 'my-project-123', serviceAccount: SA }), EXPECTED_CLOUDBUILD_YAML)
})

test('gcp: the builder is pinned by digest, and the only "$" is in the one constant nonce wrapper', () => {
  assert.match(DOCKER_BUILDER, /^gcr\.io\/cloud-builders\/docker@sha256:[0-9a-f]{64}$/)
  assert.equal(NONCE_WRAPPER, 'printf \'%s\\n\' "$$GIT_BOUNCER_NONCE" | docker "$$@"')
  const url = parseRepoUrl('https://gitlab.com/group/sub~group/re.po_-x').url
  const ref = 'feature/-rf+x' + AT + 'y'
  const yaml = renderCloudbuildYaml({ url, ref, nonce: 'f'.repeat(64), project: 'my-project-123', serviceAccount: SA })
  const quoted = JSON.stringify(NONCE_WRAPPER)
  assert.equal(yaml.split(quoted).length, 2, 'the wrapper appears exactly once')
  assert.ok(!yaml.split(quoted).join('').includes('$'), 'no other "$" for Cloud Build to expand')
  assert.ok(yaml.includes(`      - "--url=${url}"\n`) && yaml.includes(`      - "--ref=${ref}"\n`), 'values are single, "="-bound arguments')
  assert.throws(() => renderCloudbuildYaml({ url: URL_, ref: '$PROJECT_ID', nonce: NONCE, project: 'my-project-123', serviceAccount: SA }), /ref/)
})

test('gcp: the nonce is only in the scan step\'s environment, never in an argument', () => {
  const config = buildCloudbuildConfig({ url: URL_, ref: null, nonce: NONCE, project: 'my-project-123', serviceAccount: SA })
  for (const s of config.steps) {
    assert.ok(!s.args.some(a => a.includes(NONCE) || a.startsWith('--nonce=')), s.id)
    assert.ok(!s.args.includes('--ref') && !s.args.some(a => a.startsWith('--ref')), 'no --ref when there is no ref')
    assert.equal(s.volumes, undefined)
    assert.equal(s.secretEnv, undefined)
  }
  assert.deepEqual(config.steps[2].env, [`GIT_BOUNCER_NONCE=${NONCE}`])
  assert.equal(config.steps[2].entrypoint, 'bash')
  assert.deepEqual(config.steps[2].args.slice(0, 3), ['-c', NONCE_WRAPPER, 'bash'], 'everything after "bash" is "$@": passed on, never parsed')
  assert.equal(config.steps[0].entrypoint, undefined)
  assert.equal(config.steps[1].entrypoint, undefined)
  assert.equal(config.images, undefined, 'nothing is pushed')
  assert.equal(config.artifacts, undefined, 'nothing is stored')
  assert.equal(config.serviceAccount, `projects/my-project-123/serviceAccounts/${SA}`)
  assert.deepEqual(config.options, { logging: 'CLOUD_LOGGING_ONLY' })
})

const GCP_ENV = home => ({ HOME: home, GIT_BOUNCER_GCP_SERVICE_ACCOUNT: SA, GIT_BOUNCER_GCP_BUCKET: 'my-bouncer' })

test('gcp: plan() runs nothing and lists the exact commands scan() will run', async () => {
  await withDirs(async ({ home }) => {
    const rt = createGcpRuntime({ exec: noExec, env: { ...GCP_ENV(home), GIT_BOUNCER_GCP_PROJECT: 'my-project-123', GIT_BOUNCER_GCP_REGION: 'europe-west4' } })
    const workDir = path.join(tmpdir(), 'gb-work')
    const p = await rt.plan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: '/opt/pkg/sandbox', workDir })
    const scope = ['--project=my-project-123', '--region=europe-west4']
    const tail = ['--user-output-enabled', '--quiet']
    assert.deepEqual(p.steps.map(s => [s.id, s.cmd, ...s.args]), [
      ['submit', 'gcloud', 'builds', 'submit', path.join(workDir, 'source'), `--config=${path.join(workDir, 'cloudbuild.yaml')}`, `--gcs-source-staging-dir=gs://my-bouncer/git-bouncer/${RUN_ID}`, ...scope, '--async', '--format=value(id)', ...tail],
      ['status', 'gcloud', 'builds', 'describe', '<build-id>', ...scope, '--format=json', ...tail],
      ['log', 'gcloud', 'builds', 'log', '<build-id>', ...scope, ...tail],
      ['cleanup-source', 'gcloud', 'storage', 'rm', `gs://my-bouncer/git-bouncer/${RUN_ID}/**`, '--project=my-project-123', ...tail],
      ['find-builds', 'gcloud', 'builds', 'list', '--ongoing', `--filter=tags:git-bouncer-run-${RUN_ID}`, '--format=value(id)', '--limit=10', ...scope, ...tail],
      ['cancel', 'gcloud', 'builds', 'cancel', '<build-id>', ...scope, ...tail],
    ])
    assert.deepEqual(Object.keys(p.files), ['cloudbuild.yaml'])
    assert.ok(p.notes[0].startsWith('Not live-tested by the maintainer'))
    for (const s of p.steps) assert.ok(!s.args.some(a => a.includes(NONCE)), 'the nonce is in no command line')

    const dry = await createGcpRuntime({ exec: noExec, env: { HOME: home } }).plan({ url: URL_, nonce: NONCE, sandboxDir: '/opt/pkg/sandbox' })
    assert.deepEqual(dry.steps[0].args.slice(0, 5), ['builds', 'submit', '<temp-dir>/source', '--config=<temp-dir>/cloudbuild.yaml', `--gcs-source-staging-dir=gs://<bucket>/git-bouncer/${RUN_ID}`])
    assert.ok(dry.files['cloudbuild.yaml'].includes('projects/<project>/serviceAccounts/<service-account>'))
  })
})

/** Canned gcloud answers. `state` records what has "happened in the cloud". */
function gcpCloud({ nonce = NONCE, status = 'SUCCESS', bucketOwner = '987654321', canaryFails = false, onSubmit, onDescribe } = {}) {
  const state = { created: false, cancelled: [], stagingRemoved: false, describes: 0 }
  const log = [
    `starting build "${GCP_BUILD_ID}"`, '', 'FETCHSOURCE', 'BUILD',
    'Starting Step #0 - "build-sandbox-image"',
    'Step #0 - "build-sandbox-image": Successfully tagged git-bouncer-sandbox:scan',
    `Step #0 - "build-sandbox-image": -----END BOUNCER REPORT ${nonce}-----`,
    'Finished Step #0 - "build-sandbox-image"',
    'Starting Step #1 - "metadata-canary"',
    ...(canaryFails
      ? ['Step #1 - "metadata-canary": metadata canary: 169.254.169.254 answered HTTP 200', 'Step #1 - "metadata-canary": metadata canary: FAILED, the sandbox can reach a cloud credential endpoint, refusing to scan']
      : ['Step #1 - "metadata-canary": metadata canary: passed', 'Finished Step #1 - "metadata-canary"', 'Starting Step #2 - "scan"',
        'Step #2 - "scan": [scanner] fetching one commit', ...report(nonce).map(l => `Step #2 - "scan":${l ? ` ${l}` : ''}`), 'Finished Step #2 - "scan"']),
    'DONE',
  ].join('\n')
  const handler = async (_cmd, args, opts) => {
    if (args.join(' ') === '--version') return { stdout: 'Google Cloud SDK 516.0.0\n' }
    if (starts(args, 'auth list')) return { stdout: `dev${AT}example.com\n` }
    if (starts(args, 'config get-value project')) return { stdout: 'my-project-123\n' }
    if (starts(args, 'projects describe my-project-123')) return { stdout: '987654321\n' }
    if (starts(args, 'storage buckets describe gs://my-bouncer')) return { stdout: JSON.stringify({ name: 'my-bouncer', projectNumber: bucketOwner }) }
    if (starts(args, 'builds submit')) { state.created = true; return onSubmit ? onSubmit(args, opts, state) : { stdout: `${GCP_BUILD_ID}\n` } }
    if (starts(args, `builds describe ${GCP_BUILD_ID}`)) {
      state.describes += 1
      const hooked = onDescribe && await onDescribe(state)
      return hooked || { stdout: JSON.stringify({ id: GCP_BUILD_ID, status: canaryFails ? 'FAILURE' : status, logUrl: 'https://console.cloud.google.com/cloud-build/builds/x' }) }
    }
    if (starts(args, `builds log ${GCP_BUILD_ID}`)) return { stdout: log }
    if (starts(args, 'builds list --ongoing')) return { stdout: state.created && !state.cancelled.length ? `${GCP_BUILD_ID}\n` : '' }
    if (starts(args, 'builds cancel')) { state.cancelled.push(args[2]); return {} }
    if (starts(args, `storage rm gs://my-bouncer/git-bouncer/${RUN_ID}/**`)) {
      if (!state.created) return { code: 1, stderr: 'ERROR: The following URLs matched no objects or files:\n' }
      state.stagingRemoved = true
      return {}
    }
    return null
  }
  return { handler, state }
}

test('gcp: available() explains each missing prerequisite, and requires a dedicated service account', async () => {
  await withDirs(async ({ home }) => {
    const check = async (env, respond = gcpCloud().handler, platform = 'linux') => createGcpRuntime({ exec: fakeExec(respond).exec, env, platform }).available()

    const win = fakeExec(gcpCloud().handler)
    let r = await createGcpRuntime({ exec: win.exec, env: GCP_ENV(home), platform: 'win32' }).available()
    assert.match(r.reason, /\.cmd script.*WSL/)
    assert.equal(win.calls.length, 0, 'nothing is started on Windows')

    assert.match((await check(GCP_ENV(home), () => ({ code: -1, error: Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) }))).reason, /gcloud .* is not installed/)
    r = await check({ HOME: home, GIT_BOUNCER_GCP_BUCKET: 'my-bouncer' })
    assert.equal(r.ok, false)
    assert.match(r.reason, /need a dedicated service account.*default Cloud Build identity.*GIT_BOUNCER_GCP_SERVICE_ACCOUNT/)
    assert.match((await check({ HOME: home, GIT_BOUNCER_GCP_SERVICE_ACCOUNT: SA })).reason, /need a bucket of their own.*GIT_BOUNCER_GCP_BUCKET/)
    assert.match((await check(GCP_ENV(home), (c, a) => (starts(a, 'auth list') ? { stdout: '' } : gcpCloud().handler(c, a)))).reason, /not signed in/)
    r = await check(GCP_ENV(home), (c, a) => (starts(a, 'config get-value') ? { stdout: '', stderr: '(unset)\n' } : gcpCloud().handler(c, a)))
    assert.match(r.reason, /No Google Cloud project is selected/)
    assert.equal(r.account, `dev${AT}example.com`)
    r = await check(GCP_ENV(home), gcpCloud({ bucketOwner: '111111111' }).handler)
    assert.match(r.reason, /gs:\/\/my-bouncer does not exist, can't be read, or belongs to another project/)

    const none = fakeExec(gcpCloud().handler)
    r = await createGcpRuntime({ exec: none.exec, env: { ...GCP_ENV(home), GIT_BOUNCER_GCP_PROJECT: '--impersonate-service-account=x' }, platform: 'linux' }).available()
    assert.match(r.reason, /not a valid Google Cloud project ID/)
    assert.equal(none.calls.length, 0, 'bad settings are reported before anything runs')
    assert.match((await check({ ...GCP_ENV(home), GIT_BOUNCER_GCP_BUCKET: 'my.dotted.bucket' })).reason, /not a bucket name git-bouncer accepts/)

    const good = fakeExec(gcpCloud().handler)
    const rt = createGcpRuntime({ exec: good.exec, env: GCP_ENV(home), platform: 'linux' })
    assert.match(rt.describe(), /^Google Cloud Build \(billed to your account; not live-tested/)
    r = await rt.available()
    assert.deepEqual(r, { ok: true, account: `dev${AT}example.com`, project: 'my-project-123', region: 'global', bucket: 'my-bouncer', serviceAccount: SA })
    assert.deepEqual(good.argv(), [
      ['gcloud', '--version'],
      ['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)', '--user-output-enabled', '--quiet'],
      ['gcloud', 'config', 'get-value', 'project', '--user-output-enabled', '--quiet'],
      ['gcloud', 'projects', 'describe', 'my-project-123', '--format=value(projectNumber)', '--user-output-enabled', '--quiet'],
      ['gcloud', 'storage', 'buckets', 'describe', 'gs://my-bouncer', '--raw', '--format=json', '--project=my-project-123', '--user-output-enabled', '--quiet'],
    ])
    assert.match(rt.describe(), new RegExp(`project my-project-123, as ${SA.replace(/[.]/g, '\\.')}`))
    const env = good.calls[0].opts.env
    assert.deepEqual([env.CLOUDSDK_CORE_DISABLE_PROMPTS, env.CLOUDSDK_ACCESSIBILITY_SCREEN_READER, env.CLOUDSDK_CORE_USER_OUTPUT_ENABLED, env.CLOUDSDK_CORE_LOG_HTTP], ['1', 'false', 'true', 'false'])
  })
})

test('gcp: extractStepOutput keeps one step\'s lines, without the prefix, and drops other steps', () => {
  const log = [
    'starting build "x"',
    'Step #0 - "build-sandbox-image": Sending build context',
    `Step #0 - "build-sandbox-image": -----BEGIN BOUNCER REPORT ${NONCE}-----`,
    'Step #2 - "scan": [scanner] content checks',
    'Step #2 - "scan":',
    'Step #2 - "other": not ours',
    'Step #2: unnamed form',
    'DONE',
  ].join('\n')
  assert.equal(extractStepOutput(log), ['starting build "x"', '[scanner] content checks', '', 'unnamed form', 'DONE'].join('\n'))
})

test('gcp: scan() runs exactly the planned commands, returns the report and leaves nothing behind', async () => {
  await withDirs(async ({ home, sandbox }) => {
    let uploaded = null
    let configOutsideSource = false
    const cloud = gcpCloud({
      onSubmit: async args => {
        uploaded = await listTree(args[2])
        const config = args[3].slice('--config='.length)
        configOutsideSource = existsSync(config) && path.dirname(config) !== args[2]
        return { stdout: `${GCP_BUILD_ID}\n` }
      },
    })
    const fake = fakeExec(cloud.handler)
    const logs = []
    let early = null
    const rt = createGcpRuntime({ exec: fake.exec, env: GCP_ENV(home), platform: 'linux', sleep: noSleep })
    const { reportText, session } = await rt.scan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: sandbox, onLog: l => logs.push(l), onSession: s => { early = { ...s } } })

    assert.ok(reportReady(reportText, NONCE))
    assert.deepEqual(extractReport(reportText, NONCE).problems.filter(p => /markers/.test(p)), [], 'exactly one pair of markers: other steps\' lines are dropped')
    assert.deepEqual(uploaded, ['Dockerfile', 'osv-scanner.toml', 'scanner', 'scanner/main.js', 'scanner/package.json'], 'only the sandbox files are uploaded')
    assert.ok(configOutsideSource, 'cloudbuild.yaml sits next to the upload, not inside it')
    assert.deepEqual(fake.unexpected, [])
    assert.equal(early.buildId, null, 'onSession runs before anything exists in the cloud...')
    assert.equal(early.tag, `git-bouncer-run-${RUN_ID}`, '...with the tag and prefix destroy() needs')
    assert.equal(early.staging, `gs://my-bouncer/git-bouncer/${RUN_ID}/`)

    const p = await createGcpRuntime({ exec: noExec, env: { ...GCP_ENV(home), GIT_BOUNCER_GCP_PROJECT: 'my-project-123' } })
      .plan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: sandbox, workDir: session.workDir })
    const planned = id => { const s = fillStep(p.steps.find(x => x.id === id), { '<build-id>': GCP_BUILD_ID }); return [s.cmd, ...s.args] }
    assert.deepEqual(fake.argv().slice(5), ['submit', 'status', 'log', 'cleanup-source'].map(planned))
    for (const c of fake.calls) assert.ok(!c.args.some(a => a.includes(NONCE)), 'the nonce is in no command line')

    assert.equal(session.status, 'SUCCESS')
    assert.equal(session.reportComplete, true)
    assert.deepEqual(session.cleanup, { buildSettled: true, cancelled: [], stagingRemoved: true, workDirRemoved: true, problems: [] })
    assert.ok(!existsSync(session.workDir))
    assert.ok(logs.some(l => l.includes(GCP_BUILD_ID)) && logs.includes('Cloud Build: SUCCESS'))
    assert.equal(await rt.readFile(session, 'package-lock.json'), null)
    await rt.destroy(session)
    assert.equal(fake.calls.length, 9, 'destroy() after a finished scan has nothing left to do')
  })
})

test('gcp: a failed metadata canary stops the scan with a clear error', async () => {
  await withDirs(async ({ home, sandbox }) => {
    const rt = createGcpRuntime({ exec: fakeExec(gcpCloud({ canaryFails: true }).handler).exec, env: GCP_ENV(home), platform: 'linux', sleep: noSleep })
    await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox }), e => /metadata canary failed/.test(e.message) && e.session && e.session.cleanup.stagingRemoved)
  })
})

test('gcp: a submit that printed no ID (but created the build) is found by its tag', async () => {
  await withDirs(async ({ home, sandbox }) => {
    const fake = fakeExec(gcpCloud({ onSubmit: () => ({ stdout: '' }) }).handler)
    const rt = createGcpRuntime({ exec: fake.exec, env: GCP_ENV(home), platform: 'linux', sleep: noSleep })
    const { session } = await rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox })
    assert.equal(session.buildId, GCP_BUILD_ID)
    assert.equal(session.reportComplete, true)
    assert.ok(fake.argv().some(a => a.join(' ').includes(`builds list --ongoing --filter=tags:git-bouncer-run-${RUN_ID}`)))
  })
})

test('gcp: a refused submit still cancels anything it created and deletes what it uploaded', async () => {
  await withDirs(async ({ home, sandbox }) => {
    let workDir = null
    const cloud = gcpCloud({ onSubmit: args => { workDir = path.dirname(args[2]); return { code: 1, stderr: 'ERROR: (gcloud.builds.submit) PERMISSION_DENIED: \x1b[31mno\x1b[0m\n' } } })
    const fake = fakeExec(cloud.handler)
    const rt = createGcpRuntime({ exec: fake.exec, env: GCP_ENV(home), platform: 'linux', sleep: noSleep })
    await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox }), e => /did not start the build/.test(e.message) && /PERMISSION_DENIED/.test(e.message) && !e.message.includes('\x1b'))
    assert.ok(fake.argv().some(a => a[2] === 'list'), 'looked for a build by tag')
    assert.deepEqual(cloud.state.cancelled, [GCP_BUILD_ID], 'the upload had happened and so had CreateBuild: it is cancelled')
    assert.equal(cloud.state.stagingRemoved, true, 'gcloud uploads before CreateBuild, so the prefix is always deleted')
    assert.ok(workDir && !existsSync(workDir))
  })
})

/**
 * An interrupt the way src/commands/check.js does it: the signal handler awaits
 * runtime.destroy(session) while scan() is still in the middle of a command, then the process
 * exits. Here the interrupted command simply never returns.
 */
test('gcp: an interrupt at any point leaves no build running and no upload behind', async () => {
  for (const when of ['before submit', 'during submit', 'during polling']) {
    await withDirs(async ({ home, sandbox }) => {
      let session = null
      let rt = null
      let destroyed
      const done = new Promise(resolve => { destroyed = resolve })
      const interrupt = async () => { await rt.destroy(session); destroyed(); return never() }
      const cloud = gcpCloud({
        onSubmit: when === 'during submit' ? interrupt : undefined,
        onDescribe: when === 'during polling' ? s => (s.describes === 2 ? interrupt() : { stdout: JSON.stringify({ id: GCP_BUILD_ID, status: 'WORKING' }) }) : undefined,
      })
      const fake = fakeExec(cloud.handler)
      rt = createGcpRuntime({ exec: fake.exec, env: GCP_ENV(home), platform: 'linux', sleep: noSleep })
      const scanning = rt.scan({
        url: URL_, nonce: NONCE, sandboxDir: sandbox,
        onSession: s => { session = s; if (when === 'before submit') rt.destroy(s).then(destroyed) },
      })
      if (when === 'before submit') await assert.rejects(scanning)
      await done
      const argv = fake.argv().map(a => a.join(' '))
      if (when === 'before submit') {
        assert.ok(!argv.some(a => a.includes('builds submit')), 'nothing is started after destroy()')
        assert.equal(cloud.state.created, false)
      } else {
        assert.deepEqual(cloud.state.cancelled, [GCP_BUILD_ID], `${when}: cancel issued`)
        assert.equal(cloud.state.stagingRemoved, true, `${when}: upload deleted`)
        assert.equal(argv.some(a => a.includes('builds list --ongoing')), when === 'during submit', 'the tag lookup is only needed when the ID was never seen')
      }
      assert.ok(!existsSync(session.workDir), `${when}: temp folder removed`)
      assert.deepEqual(fake.unexpected, [])
    })
  }
})

test('gcp: invalid inputs are refused before any command runs', async () => {
  const fake = fakeExec(gcpCloud().handler)
  const rt = createGcpRuntime({ exec: fake.exec, env: { HOME: '/nonexistent', ...GCP_ENV('/nonexistent') }, platform: 'linux' })
  await assert.rejects(rt.scan({ url: URL_, ref: '$(id)', nonce: NONCE, sandboxDir: '/nowhere' }), /ref/)
  await assert.rejects(rt.scan({ url: 'https://github.com/o/r;id.git', nonce: NONCE, sandboxDir: '/nowhere' }), /repository URL/)
  await assert.rejects(rt.plan({ url: URL_, nonce: 'nope', sandboxDir: '/nowhere' }), /nonce/)
  await assert.rejects(rt.scan({ url: URL_, nonce: NONCE }), /sandbox folder/)
  await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: 'relative/sandbox' }), /sandbox folder/)
  assert.equal(fake.calls.length, 0)
})

// ---------------------------------------------------------------------------------------------
// AWS CodeBuild
// ---------------------------------------------------------------------------------------------

const FLAGS_SH = sandboxFlags().join(' ')
const EXPECTED_BUILDSPEC = `# Generated by git-bouncer for one scan. Not live-tested by the maintainer: see docs/cloud.md.
# The URL, ref and nonce are environment variables set by the StartBuild request. The commands
# below only ever refer to them inside double quotes, so their values are never parsed as shell.
version: 0.2
env:
  variables:
    DOCKER_BUILDKIT: "1"
phases:
  build:
    commands:
      - "iptables -I DOCKER-USER -d 169.254.169.254/32 -j REJECT"
      - "iptables -I DOCKER-USER -d 169.254.170.2/32 -j REJECT"
      - "docker build --tag=git-bouncer-sandbox:scan ."
      - ${JSON.stringify(`docker run --rm ${FLAGS_SH} git-bouncer-sandbox:scan node -e '${CANARY_JS}' any-answer`)}
      - ${JSON.stringify(`printf '%s\\n' "$GIT_BOUNCER_NONCE" | docker run --rm --interactive ${FLAGS_SH} git-bouncer-sandbox:scan node /opt/bouncer/scanner/main.js --url="$GIT_BOUNCER_URL" --ref="$GIT_BOUNCER_REF" --nonce-stdin`)}
`

test('aws: the generated buildspec, exactly, with and without a ref', () => {
  assert.equal(renderBuildspec({ hasRef: true }), EXPECTED_BUILDSPEC)
  assert.equal(renderBuildspec({ hasRef: false }), EXPECTED_BUILDSPEC.replace(' --ref=\\"$GIT_BOUNCER_REF\\"', ''))
})

test('aws: the credential endpoints are blocked before any container runs, then the canary proves it', () => {
  const cmds = buildBuildspec({ hasRef: false }).phases.build.commands
  const firstDocker = cmds.findIndex(c => c.startsWith('docker '))
  assert.deepEqual(cmds.slice(0, firstDocker), [
    'iptables -I DOCKER-USER -d 169.254.169.254/32 -j REJECT',
    'iptables -I DOCKER-USER -d 169.254.170.2/32 -j REJECT',
  ])
  const canary = cmds.findIndex(c => c.includes(' node -e '))
  const scan = cmds.findIndex(c => c.includes('/opt/bouncer/scanner/main.js'))
  assert.ok(firstDocker < canary && canary < scan, 'image build, then canary, then scan')
  assert.ok(cmds[canary].endsWith("' any-answer"))
})

test('aws: the shell text never contains a value, and the nonce reaches the scanner through stdin', () => {
  const a = buildStartBuildRequest({ project: 'git-bouncer', bucket: 'my-bucket', runId: RUN_ID, url: URL_, ref: 'v1', nonce: NONCE })
  const hostileUrl = parseRepoUrl('https://gitlab.com/group/sub~group/re.po_-x').url
  const hostileRef = 'feature/-rf+x' + AT + 'y'
  const other = 'f'.repeat(64)
  const b = buildStartBuildRequest({ project: 'git-bouncer', bucket: 'my-bucket', runId: runIdFor(other), url: hostileUrl, ref: hostileRef, nonce: other })
  assert.equal(a.buildspecOverride, b.buildspecOverride, 'byte-for-byte the same whatever the values are')
  for (const v of [hostileUrl, hostileRef, other, URL_, NONCE]) assert.ok(!b.buildspecOverride.includes(v), v)
  assert.ok(!b.buildspecOverride.includes('--nonce='), 'never --nonce=<value>')
  assert.deepEqual(b.environmentVariablesOverride.map(e => e.name), ['GIT_BOUNCER_URL', 'GIT_BOUNCER_REF', 'GIT_BOUNCER_NONCE'])

  // Every word is a plain constant, apart from: the three "$VAR" references, printf's format and
  // pipe, and the canary script inside single quotes.
  for (const cmd of buildBuildspec({ hasRef: true }).phases.build.commands) {
    const rest = cmd.replace(`'${CANARY_JS}'`, '').replace(/^printf '%s\\n' "\$GIT_BOUNCER_NONCE" \| /, '')
    for (const word of rest.split(' ').filter(Boolean)) {
      if (/^--(url|ref)="\$GIT_BOUNCER_(URL|REF)"$/.test(word)) continue
      assert.match(word, /^[A-Za-z0-9_./:=,@+-]+$/, word)
    }
  }
})

test('aws: the StartBuild request turns off everything that could keep or leak data, or bill twice', () => {
  const req = buildStartBuildRequest({ project: 'git-bouncer', bucket: 'my-bucket', runId: 'abc123', url: URL_, ref: null, nonce: NONCE })
  assert.deepEqual({ ...req, buildspecOverride: '<buildspec>' }, {
    projectName: 'git-bouncer',
    sourceTypeOverride: 'S3',
    sourceLocationOverride: 'my-bucket/git-bouncer/abc123/',
    buildspecOverride: '<buildspec>',
    environmentVariablesOverride: [
      { name: 'GIT_BOUNCER_URL', value: URL_, type: 'PLAINTEXT' },
      { name: 'GIT_BOUNCER_NONCE', value: NONCE, type: 'PLAINTEXT' },
    ],
    privilegedModeOverride: true,
    artifactsOverride: { type: 'NO_ARTIFACTS' },
    cacheOverride: { type: 'NO_CACHE' },
    logsConfigOverride: { cloudWatchLogs: { status: 'ENABLED' }, s3Logs: { status: 'DISABLED' } },
    timeoutInMinutesOverride: 30,
    queuedTimeoutInMinutesOverride: 15,
    autoRetryLimitOverride: 0,
    debugSessionEnabled: false,
    idempotencyToken: 'abc123',
  })
  assert.ok(!req.buildspecOverride.includes('--ref'))
  assert.throws(() => buildStartBuildRequest({ project: 'p', bucket: 'b', runId: 'r', url: URL_, ref: '`id`', nonce: NONCE }), /ref/)
})

const AWS_ENV = home => ({ HOME: home, GIT_BOUNCER_AWS_PROJECT: 'git-bouncer', GIT_BOUNCER_AWS_BUCKET: 'my-bucket', GIT_BOUNCER_AWS_REGION: 'us-east-1' })

test('aws: plan() runs nothing and lists the exact commands scan() will run', async () => {
  await withDirs(async ({ home }) => {
    const rt = createAwsRuntime({ exec: noExec, env: AWS_ENV(home) })
    const workDir = path.join(tmpdir(), 'gb-work')
    const p = await rt.plan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: '/opt/pkg/sandbox', workDir })
    const owner = '--expected-bucket-owner=<account-id>'
    const json = ['--region=us-east-1', '--output=json', '--no-cli-auto-prompt']
    assert.deepEqual(p.steps.map(s => [s.id, s.cmd, ...s.args]), [
      ['upload', 'aws', 's3api', 'put-object', '--bucket=my-bucket', `--key=git-bouncer/${RUN_ID}/<file>`, '--body=<file-path>', owner, ...json],
      ['start', 'aws', 'codebuild', 'start-build', `--cli-input-json=file://${path.join(workDir, 'start-build.json')}`, ...json],
      ['wait', 'aws', 'codebuild', 'batch-get-builds', '--ids=<build-id>', ...json],
      ['log', 'aws', 'logs', 'get-log-events', '--log-group-name=<log-group>', '--log-stream-name=<log-stream>', '--start-from-head', ...json],
      ['cleanup-list', 'aws', 's3api', 'list-objects-v2', '--bucket=my-bucket', `--prefix=git-bouncer/${RUN_ID}/`, owner, ...json],
      ['cleanup-delete', 'aws', 's3api', 'delete-objects', '--bucket=my-bucket', '--delete=<delete-request>', owner, ...json],
      ['find-builds', 'aws', 'codebuild', 'list-builds-for-project', '--project-name=git-bouncer', '--sort-order=DESCENDING', '--max-items=50', ...json],
      ['find-builds-detail', 'aws', 'codebuild', 'batch-get-builds', '--ids', '<build-ids>', ...json],
      ['cancel', 'aws', 'codebuild', 'stop-build', '--id=<build-id>', ...json],
    ])
    assert.deepEqual(Object.keys(p.files), ['start-build.json', 'buildspec.yml'])
    const req = JSON.parse(p.files['start-build.json'])
    assert.equal(req.buildspecOverride, p.files['buildspec.yml'])
    assert.equal(req.buildspecOverride, EXPECTED_BUILDSPEC)
    // The AWS CLI reads a value starting with file:// (and in v1, http:// or https://) as "load the
    // value from there". Only the request file is meant to be read that way.
    for (const s of p.steps) {
      if (s.args[0] === 's3api') assert.ok(s.args.includes(owner), `${s.id}: S3 refuses it unless your account owns the bucket`)
      for (const a of s.args) {
        if (a.startsWith('--cli-input-json=')) continue
        assert.doesNotMatch(a.includes('=') ? a.slice(a.indexOf('=') + 1) : a, /^(file|fileb|https?):\/\//i, a)
        assert.ok(!a.includes(NONCE), 'the nonce is in no command line')
      }
    }
  })
})

/** Canned aws answers. `state` records what has "happened in the cloud". */
function awsCloud({ nonce = NONCE, onUpload, onStart, onWait, logPages, canaryFails = false, version = 'aws-cli/2.17.0 Python/3.11', owner = ACCOUNT } = {}) {
  const state = { created: false, stopped: [], uploaded: [], sourceRemoved: false, waits: 0, logCalls: [] }
  const events = [
    '[Container] Running command docker build --tag=git-bouncer-sandbox:scan .\n',
    ...(canaryFails
      ? ['metadata canary: 169.254.169.254 answered HTTP 401\n', 'metadata canary: FAILED, the sandbox can reach a cloud credential endpoint, refusing to scan\n']
      : ['metadata canary: passed\n', '[scanner] fetching one commit\n', ...report(nonce).map(l => `${l}\n`)]),
  ].map(message => ({ timestamp: 1, message }))
  const handler = async (_cmd, args, opts) => {
    if (args.join(' ') === '--version') return { stdout: `${version}\n` }
    if (starts(args, 'configure get region')) return { stdout: 'eu-west-1\n' }
    if (starts(args, 'sts get-caller-identity')) return { stdout: JSON.stringify({ Account: ACCOUNT, Arn: `arn:aws:iam::${ACCOUNT}:user/dev` }) }
    if (starts(args, 's3api head-bucket')) return args.includes(`--expected-bucket-owner=${owner}`) && owner === ACCOUNT ? { stdout: '{}' } : { code: 254, stderr: 'An error occurred (403) when calling the HeadBucket operation: Forbidden' }
    if (starts(args, 'codebuild batch-get-projects')) return { stdout: JSON.stringify({ projects: [{ name: 'git-bouncer' }], projectsNotFound: [] }) }
    if (starts(args, 's3api put-object')) {
      assert.ok(args.includes(`--expected-bucket-owner=${ACCOUNT}`))
      const hooked = onUpload && await onUpload(args, opts, state)
      if (hooked) return hooked
      state.uploaded.push(args.find(a => a.startsWith('--key=')).slice('--key='.length))
      return { stdout: '{"ETag":"x"}' }
    }
    if (starts(args, 's3api list-objects-v2')) return { stdout: state.uploaded.length ? JSON.stringify({ Contents: state.uploaded.map(Key => ({ Key })) }) : '{}' }
    if (starts(args, 's3api delete-objects')) {
      const keys = JSON.parse(args.find(a => a.startsWith('--delete=')).slice('--delete='.length)).Objects.map(o => o.Key)
      assert.deepEqual(keys, state.uploaded, 'deletes exactly what was uploaded')
      state.sourceRemoved = true
      return { stdout: '{}' }
    }
    if (starts(args, 'codebuild start-build')) {
      state.created = true
      return onStart ? onStart(args, opts, state) : { stdout: JSON.stringify({ build: { id: AWS_BUILD_ID, buildStatus: 'IN_PROGRESS' } }) }
    }
    if (starts(args, 'codebuild batch-get-builds --ids ')) {
      return { stdout: JSON.stringify({ builds: args.slice(3, args.indexOf('--region=us-east-1')).map(id => ({ id, buildStatus: id === AWS_BUILD_ID && state.created && !state.stopped.length ? 'IN_PROGRESS' : 'SUCCEEDED', source: { location: id === AWS_BUILD_ID ? `my-bucket/git-bouncer/${RUN_ID}/` : 'my-bucket/git-bouncer/other/' } })) }) }
    }
    if (starts(args, 'codebuild batch-get-builds --ids=')) {
      state.waits += 1
      const hooked = onWait && await onWait(state)
      if (hooked) return hooked
      const done = state.waits > 1
      return {
        stdout: JSON.stringify({ builds: [{
          id: AWS_BUILD_ID, buildStatus: done ? (canaryFails ? 'FAILED' : 'SUCCEEDED') : 'IN_PROGRESS', buildComplete: done, currentPhase: done ? 'COMPLETED' : 'BUILD',
          logs: { groupName: '/aws/codebuild/git-bouncer', streamName: AWS_BUILD_ID.split(':')[1], deepLink: 'https://console.aws.amazon.com/cloudwatch/home#logEvent' },
        }] }),
      }
    }
    if (starts(args, 'codebuild list-builds-for-project')) return { stdout: JSON.stringify({ ids: state.created ? ['git-bouncer:00000000-0000-4000-8000-000000000000', AWS_BUILD_ID] : [] }) }
    if (starts(args, 'logs get-log-events')) {
      const token = (args.find(a => a.startsWith('--next-token=')) || '').slice('--next-token='.length) || null
      state.logCalls.push(token)
      if (logPages) return { stdout: JSON.stringify(logPages(token, events, state)) }
      return { stdout: JSON.stringify(token ? { events: [], nextForwardToken: token } : { events, nextForwardToken: 'f/1' }) }
    }
    if (starts(args, 'codebuild stop-build')) { state.stopped.push(args[2].slice('--id='.length)); return { stdout: '{}' } }
    return null
  }
  return { handler, state }
}

test('aws: available() explains each missing prerequisite, including a bucket you don\'t own', async () => {
  await withDirs(async ({ home }) => {
    const base = { HOME: home, GIT_BOUNCER_AWS_PROJECT: 'git-bouncer', GIT_BOUNCER_AWS_BUCKET: 'my-bucket' }
    const ok = awsCloud().handler
    const check = async (env, respond = ok) => createAwsRuntime({ exec: fakeExec(respond).exec, env }).available()
    assert.match((await check(base, () => ({ code: -1, error: Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) }))).reason, /AWS CLI .* not installed/)
    assert.match((await check(base, awsCloud({ version: 'aws-cli/1.33.0 Python/3.9' }).handler)).reason, /needs version 2 of the AWS CLI/)
    assert.match((await check({ HOME: home, GIT_BOUNCER_AWS_BUCKET: 'my-bucket' })).reason, /No CodeBuild project is configured/)
    assert.match((await check({ HOME: home, GIT_BOUNCER_AWS_PROJECT: 'git-bouncer' })).reason, /No S3 bucket is configured/)
    assert.match((await check({ ...base, GIT_BOUNCER_AWS_BUCKET: 'my.dotted.bucket' })).reason, /not a bucket name git-bouncer accepts/)
    assert.match((await check({ ...base, GIT_BOUNCER_AWS_PROJECT: '--endpoint-url=x' })).reason, /not a valid CodeBuild project name/)
    assert.match((await check(base, (c, a) => (starts(a, 'configure get') ? { code: 1 } : ok(c, a)))).reason, /No AWS region is set/)
    assert.match((await check(base, (c, a) => (starts(a, 'sts') ? { code: 255, stderr: 'Unable to locate credentials' } : ok(c, a)))).reason, /not signed in/)
    assert.match((await check(base, awsCloud({ owner: '999999999999' }).handler)).reason, /not owned by your account \(123456789012\)/)
    const missing = await check(base, (c, a) => (starts(a, 'codebuild batch-get-projects') ? { stdout: JSON.stringify({ projects: [], projectsNotFound: ['git-bouncer'] }) } : ok(c, a)))
    assert.match(missing.reason, /CodeBuild project "git-bouncer" was not found in eu-west-1/)

    const good = fakeExec(ok)
    const rt = createAwsRuntime({ exec: good.exec, env: base })
    const r = await rt.available()
    assert.deepEqual(r, { ok: true, account: `arn:aws:iam::${ACCOUNT}:user/dev`, project: 'git-bouncer', region: 'eu-west-1', bucket: 'my-bucket' })
    assert.deepEqual(good.argv(), [
      ['aws', '--version'],
      ['aws', 'configure', 'get', 'region', '--no-cli-auto-prompt'],
      ['aws', 'sts', 'get-caller-identity', '--region=eu-west-1', '--output=json', '--no-cli-auto-prompt'],
      ['aws', 's3api', 'head-bucket', '--bucket=my-bucket', `--expected-bucket-owner=${ACCOUNT}`, '--region=eu-west-1', '--output=json', '--no-cli-auto-prompt'],
      ['aws', 'codebuild', 'batch-get-projects', '--names=git-bouncer', '--region=eu-west-1', '--output=json', '--no-cli-auto-prompt'],
    ])
    assert.equal(good.calls[0].opts.env.AWS_PAGER, '')
    assert.match(rt.describe(), /^AWS CodeBuild project git-bouncer in eu-west-1/)
  })
})

test('aws: joinLogEvents puts lines (and lines split across events) back together', () => {
  assert.equal(joinLogEvents([{ message: 'a\n' }, { message: 'b' }, { message: 'c\n' }]), 'a\nbc\n')
  assert.equal(joinLogEvents([{ message: 'a' }, { message: 'b' }]), 'a\nb')
  assert.equal(joinLogEvents([{ message: 'a\n' }, {}, null, { message: 7 }]), 'a\n')
  assert.equal(joinLogEvents(undefined), '')
})

test('aws: scan() runs exactly the planned commands, returns the report and leaves nothing behind', async () => {
  await withDirs(async ({ home, sandbox }) => {
    let uploaded = null
    let request = null
    const cloud = awsCloud({
      onUpload: async args => { if (!uploaded) uploaded = await listTree(path.dirname(args.find(a => a.startsWith('--body=')).slice('--body='.length))) },
      onStart: async args => { request = JSON.parse(await readFile(args[2].slice('--cli-input-json=file://'.length), 'utf8')); return { stdout: JSON.stringify({ build: { id: AWS_BUILD_ID } }) } },
    })
    const fake = fakeExec(cloud.handler)
    const logs = []
    let early = null
    const rt = createAwsRuntime({ exec: fake.exec, env: AWS_ENV(home), sleep: noSleep })
    const { reportText, session } = await rt.scan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: sandbox, onLog: l => logs.push(l), onSession: s => { early = { ...s } } })

    assert.ok(reportReady(reportText, NONCE))
    assert.deepEqual(uploaded, ['Dockerfile', 'osv-scanner.toml', 'scanner', 'scanner/main.js', 'scanner/package.json'], 'the copy on disk is exactly the sandbox files')
    assert.deepEqual(cloud.state.uploaded, ['Dockerfile', 'osv-scanner.toml', 'scanner/main.js', 'scanner/package.json'].map(f => `git-bouncer/${RUN_ID}/${f}`), 'and that is all that is uploaded')
    assert.deepEqual(request, buildStartBuildRequest({ project: 'git-bouncer', bucket: 'my-bucket', runId: RUN_ID, url: URL_, ref: 'v1.2.3', nonce: NONCE }))
    assert.deepEqual(fake.unexpected, [])
    assert.equal(early.buildId, null)
    assert.equal(early.source, `s3://my-bucket/git-bouncer/${RUN_ID}/`)

    const p = await createAwsRuntime({ exec: noExec, env: AWS_ENV(home) }).plan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: sandbox, workDir: session.workDir })
    const vars = { '<build-id>': AWS_BUILD_ID, '<log-group>': '/aws/codebuild/git-bouncer', '<log-stream>': AWS_BUILD_ID.split(':')[1], '<account-id>': ACCOUNT }
    const planned = (id, more = {}, extra = []) => { const s = fillStep(p.steps.find(x => x.id === id), { ...vars, ...more }); return [s.cmd, ...s.args, ...extra] }
    const files = ['Dockerfile', 'osv-scanner.toml', 'scanner/main.js', 'scanner/package.json']
    const del = JSON.stringify({ Objects: files.map(f => ({ Key: `git-bouncer/${RUN_ID}/${f}` })), Quiet: true })
    assert.deepEqual(fake.argv().slice(4), [
      ...files.map(f => planned('upload', { '<file>': f, '<file-path>': path.join(session.workDir, 'source', ...f.split('/')) })),
      planned('start'), planned('wait'), planned('wait'),
      planned('log'), planned('log', {}, ['--next-token=f/1']),
      planned('cleanup-list'), planned('cleanup-delete', { '<delete-request>': del }),
    ])
    assert.equal(session.status, 'SUCCEEDED')
    assert.equal(session.reportComplete, true)
    assert.deepEqual(session.cleanup, { buildSettled: true, stopped: [], sourceRemoved: true, workDirRemoved: true, problems: [] })
    assert.ok(!existsSync(session.workDir))
    assert.ok(logs.some(l => l.includes(AWS_BUILD_ID)) && logs.includes('CodeBuild: BUILD'))
    assert.equal(await rt.readFile(session, 'package-lock.json'), null)
    await rt.destroy(session)
    assert.equal(fake.calls.length, 15, 'destroy() after a finished scan has nothing left to do')
  })
})

test('aws: an empty page in the middle of the log does not end the read (review repro)', async () => {
  await withDirs(async ({ home, sandbox }) => {
    // Page 1 has events, page 2 is empty with a NEW token (CloudWatch allows that), page 3 has the
    // report, and page 4 hands back the token it was given: only that is the end of the stream.
    const cloud = awsCloud({
      logPages: (token, events) => ({
        [null]: { events: events.slice(0, 2), nextForwardToken: 'f/1' },
        'f/1': { events: [], nextForwardToken: 'f/2' },
        'f/2': { events: events.slice(2), nextForwardToken: 'f/3' },
        'f/3': { events: [], nextForwardToken: 'f/3' },
      })[token],
    })
    const rt = createAwsRuntime({ exec: fakeExec(cloud.handler).exec, env: AWS_ENV(home), sleep: noSleep })
    const { session } = await rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox })
    assert.equal(session.reportComplete, true)
    assert.deepEqual(cloud.state.logCalls, [null, 'f/1', 'f/2', 'f/3'])
  })
})

test('aws: a log that is still arriving is read again from where it stopped, not from the start', async () => {
  await withDirs(async ({ home, sandbox }) => {
    const sleeps = []
    let reads = 0
    const cloud = awsCloud({
      logPages: (token, events) => {
        reads += 1
        if (token === null) return { events: events.slice(0, -1), nextForwardToken: 'f/1' } // the end marker hasn't arrived yet
        if (token === 'f/1') return reads <= 2 ? { events: [], nextForwardToken: 'f/1' } : { events: events.slice(-1), nextForwardToken: 'f/2' }
        return { events: [], nextForwardToken: token }
      },
    })
    const rt = createAwsRuntime({ exec: fakeExec(cloud.handler).exec, env: AWS_ENV(home), sleep: async ms => { sleeps.push(ms) } })
    const { session } = await rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox })
    assert.equal(session.reportComplete, true)
    assert.deepEqual(cloud.state.logCalls, [null, 'f/1', 'f/1', 'f/2'], 'the second attempt continues from f/1')
    assert.deepEqual(sleeps, [10000, 5000])
  })
})

test('aws: a failed metadata canary stops the scan with a clear error', async () => {
  await withDirs(async ({ home, sandbox }) => {
    const cloud = awsCloud({ canaryFails: true })
    const rt = createAwsRuntime({ exec: fakeExec(cloud.handler).exec, env: AWS_ENV(home), sleep: noSleep })
    await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox }), /metadata canary failed/)
    assert.equal(cloud.state.sourceRemoved, true)
  })
})

test('aws: an interrupt at any point leaves no build running and no upload behind', async () => {
  for (const when of ['during upload', 'during start-build', 'during polling']) {
    await withDirs(async ({ home, sandbox }) => {
      let session = null
      let rt = null
      let destroyed
      const done = new Promise(resolve => { destroyed = resolve })
      const interrupt = async () => { await rt.destroy(session); destroyed(); return never() }
      const cloud = awsCloud({
        onUpload: when === 'during upload' ? (_a, _o, st) => (st.uploaded.length === 2 ? interrupt() : undefined) : undefined,
        onStart: when === 'during start-build' ? interrupt : undefined,
        onWait: when === 'during polling' ? s => (s.waits === 1 ? interrupt() : undefined) : undefined,
      })
      const fake = fakeExec(cloud.handler)
      rt = createAwsRuntime({ exec: fake.exec, env: AWS_ENV(home), sleep: noSleep })
      rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox, onSession: s => { session = s } })
      await done
      const argv = fake.argv().map(a => a.join(' '))
      assert.equal(cloud.state.sourceRemoved, true, `${when}: upload deleted`)
      if (when === 'during upload') {
        assert.ok(!argv.some(a => a.includes('start-build')), 'no build was started')
        assert.deepEqual(cloud.state.stopped, [])
      } else {
        assert.deepEqual(cloud.state.stopped, [AWS_BUILD_ID], `${when}: stop issued, for this run's build only`)
        assert.equal(argv.some(a => a.includes('list-builds-for-project')), when === 'during start-build', 'the lookup is only needed when the ID was never seen')
      }
      assert.ok(!existsSync(session.workDir), `${when}: temp folder removed`)
      assert.deepEqual(fake.unexpected, [])
    })
  }
})

test('aws: invalid inputs are refused before any command runs', async () => {
  const fake = fakeExec(awsCloud().handler)
  const rt = createAwsRuntime({ exec: fake.exec, env: AWS_ENV('/nonexistent') })
  await assert.rejects(rt.scan({ url: URL_, ref: 'a b', nonce: NONCE, sandboxDir: '/nowhere' }), /ref/)
  await assert.rejects(rt.scan({ url: 'https://github.com/o/`id`.git', nonce: NONCE, sandboxDir: '/nowhere' }), /repository URL/)
  await assert.rejects(rt.plan({ url: URL_, nonce: 'NOPE', sandboxDir: '/nowhere' }), /nonce/)
  await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: 'relative/sandbox' }), /sandbox folder/)
  assert.equal(fake.calls.length, 0)
})
