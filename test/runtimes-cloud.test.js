// Tests for the cloud runtimes (GCP Cloud Build, AWS CodeBuild).
//
// These never touch a real cloud and never run gcloud or aws: every test injects a fake `exec`
// that records the exact argument arrays and answers with canned output. The only real programs
// started here are Node itself, to prove the default exec passes arguments without a shell.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, symlink } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseRepoUrl } from '../src/url.js'
import {
  CLOUD_RUN_FLAGS, SANDBOX_RUN_FLAGS, assertScanInputs, cloudConfigPath, copySandbox, defaultExec,
  fillStep, hasCompleteReport, lineSink, loadCloudConfig, runIdFor, scannerCommand, toYaml,
} from '../src/runtimes/cloud-common.js'
import {
  buildCloudbuildConfig, createGcpRuntime, defaultStagingBucket, extractStepOutput, renderCloudbuildYaml,
} from '../src/runtimes/gcp.js'
import {
  buildBuildspec, buildStartBuildRequest, createAwsRuntime, joinLogEvents, renderBuildspec,
} from '../src/runtimes/aws.js'

// Written as ${AT} so the CI hygiene check (which fails on anything shaped like an email address) stays strict.
const AT = '@'
const NONCE = '0123456789abcdef0123456789abcdef'
const URL_ = 'https://github.com/someone/take-home-test.git'
const GCP_BUILD_ID = '5f2b8c1e-3a4d-4e6f-9a0b-1c2d3e4f5a6b'
const AWS_BUILD_ID = 'git-bouncer:7d6c5b4a-3e2f-4a1b-8c9d-0e1f2a3b4c5d'
const STAGED_OBJECT = 'source/1732744000.123456-0123456789abcdef0123456789abcdef.tgz'
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
    if (r.stdout && opts.onStdout) opts.onStdout(r.stdout)
    return { code: 0, stdout: '', stderr: '', ...r }
  }
  return { exec, calls, unexpected, argv: () => calls.map(c => [c.cmd, ...c.args]) }
}
const noExec = async () => { throw new Error('plan() must not run any command') }
const noSleep = async () => {}
const line = (args, prefix) => args.join(' ').startsWith(prefix)

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

async function emptyHome() {
  return mkdtemp(path.join(tmpdir(), 'gb-test-home-'))
}

// ---------------------------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------------------------

test('toYaml writes every string as a JSON-quoted scalar', () => {
  const yaml = toYaml({ a: 'x', n: 0.2, b: true, list: ['no', 'on', '1e3', '0x1F', 'null', '~'], map: { k: 'v' }, empty: [], none: {} })
  assert.equal(yaml, [
    'a: "x"',
    'n: 0.2',
    'b: true',
    'list:',
    '  - "no"',
    '  - "on"',
    '  - "1e3"',
    '  - "0x1F"',
    '  - "null"',
    '  - "~"',
    'map:',
    '  k: "v"',
    'empty: []',
    'none: {}',
    '',
  ].join('\n'))
})

test('toYaml nests lists of maps the way Cloud Build and CodeBuild expect', () => {
  const yaml = toYaml({ steps: [{ id: 'a', args: ['x', 'y'], env: { K: 'v' } }, { id: 'b' }] }, { comments: ['header'] })
  assert.equal(yaml, [
    '# header',
    'steps:',
    '  - id: "a"',
    '    args:',
    '      - "x"',
    '      - "y"',
    '    env:',
    '      K: "v"',
    '  - id: "b"',
    '',
  ].join('\n'))
})

test('toYaml keeps hostile strings inside one scalar: YAML syntax in a value stays data', () => {
  const hostile = [
    '"', '\\', '": x', '- item', '# comment', '&anchor', '*alias', '!!python/object/apply:os.system', '{a: 1}', '[1, 2]',
    '|', '>', '%YAML 1.1', '---', '...', '@', '`id`', "'", '${PROJECT_ID}', 'key: value', '"\\"', ' leading', 'trailing ',
  ]
  // ...and every printable ASCII character on its own.
  for (let c = 0x20; c <= 0x7e; c += 1) hostile.push(String.fromCharCode(c))
  for (const s of hostile) {
    const lines = toYaml({ list: [s], key: s }).split('\n')
    assert.equal(lines.length, 4, JSON.stringify(s)) // list:, the item, key:, and the final ""
    assert.equal(lines[0], 'list:')
    assert.ok(lines[1].startsWith('  - "'), JSON.stringify(s))
    assert.equal(JSON.parse(lines[1].slice(4)), s, 'the item decodes back to exactly the input')
    assert.equal(JSON.parse(lines[2].slice('key: '.length)), s)
  }
})

test('toYaml refuses anything it cannot write safely instead of escaping it', () => {
  for (const s of ['a\nb', 'a\rb', 'a\tb', '\x1b[2K', '\u0085', '\u2028', 'caf\u00e9', '\0']) {
    assert.throws(() => toYaml({ k: s }), /printable ASCII/, JSON.stringify(s))
  }
  assert.throws(() => toYaml({ 'bad key': 'x' }), /unsupported key/)
  assert.throws(() => toYaml({ 'k: v': 'x' }), /unsupported key/)
  assert.throws(() => toYaml({ k: null }), /unsupported value/)
  assert.throws(() => toYaml({ k: Number.NaN }), /unsupported value/)
  assert.throws(() => toYaml({ k: [['nested']] }), /nested lists/)
  assert.throws(() => toYaml({ k: 'x' }, { comments: ['line\nbreak'] }), /printable ASCII/)
})

test('assertScanInputs accepts exactly what the CLI\'s URL and ref validators produce', () => {
  for (const input of ['someone/take-home-test', 'https://gitlab.com/group/sub~group/re.po_-x', 'git' + AT + 'github.com:o/r.git', 'codeberg.org/a/b']) {
    const { url } = parseRepoUrl(input)
    assert.doesNotThrow(() => assertScanInputs({ url, ref: null, nonce: NONCE }), input)
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
    'https://github.com/-o/r.git', 'https://github.com/../r.git', 'https://metadata.google.internal.git', 'file:///etc/passwd.git', '--upload-pack=x',
  ]
  for (const url of badUrls) assert.throws(() => assertScanInputs({ url, nonce: NONCE }), /repository URL/, url)
  for (const ref of ['$(id)', '$PROJECT_ID', 'a b', 'x\ny', '--upload-pack=x', '-x', 'a;b', '`id`', '"q"', '']) {
    assert.throws(() => assertScanInputs({ url: URL_, ref, nonce: NONCE }), /ref/, JSON.stringify(ref))
  }
  for (const nonce of ['', 'abc', NONCE.toUpperCase(), `${NONCE}\n`, `${NONCE} `, 'g'.repeat(32), '0'.repeat(65), undefined]) {
    assert.throws(() => assertScanInputs({ url: URL_, nonce }), /nonce/, JSON.stringify(nonce))
  }
})

test('the scanner command binds every value to its flag with "="', () => {
  assert.deepEqual(scannerCommand({ url: URL_, ref: 'v1', nonce: NONCE }), ['node', '/opt/bouncer/scanner/main.js', `--url=${URL_}`, '--ref=v1', `--nonce=${NONCE}`])
  assert.deepEqual(scannerCommand({ url: URL_, ref: null, nonce: NONCE }), ['node', '/opt/bouncer/scanner/main.js', `--url=${URL_}`, `--nonce=${NONCE}`])
})

test('the cloud sandbox gets the same hardening flags as a local one, plus --rm and the default network', () => {
  assert.deepEqual([...SANDBOX_RUN_FLAGS], [
    '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--user=10001:10001',
    '--tmpfs=/work:rw,noexec,nosuid,nodev,size=2g', '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=768m',
    '--pids-limit=512', '--memory=3g',
  ])
  assert.deepEqual([...CLOUD_RUN_FLAGS], ['--rm', ...SANDBOX_RUN_FLAGS, '--network=bridge'])
  for (const flag of CLOUD_RUN_FLAGS) {
    assert.doesNotMatch(flag, /^(-v|--volume|--mount|-e|--env|--env-file|--privileged|--cap-add|--network=(host|cloudbuild))/, flag)
  }
})

test('hasCompleteReport needs both markers for this nonce, as whole lines, in order', () => {
  assert.ok(hasCompleteReport(report(NONCE).join('\n'), NONCE))
  assert.ok(hasCompleteReport(report(NONCE).join('\r\n'), NONCE))
  assert.ok(!hasCompleteReport(report(NONCE).join('\n'), 'f'.repeat(32)))
  assert.ok(!hasCompleteReport(report(NONCE).slice(0, 3).join('\n'), NONCE), 'no end marker')
  assert.ok(!hasCompleteReport([...report(NONCE)].reverse().join('\n'), NONCE), 'end before begin')
  assert.ok(!hasCompleteReport(report(NONCE).map(l => `Step #1: ${l}`).join('\n'), NONCE), 'markers must be whole lines')
})

test('runIdFor is deterministic, short, hex, and does not reveal the nonce', () => {
  const id = runIdFor(NONCE)
  assert.match(id, /^[0-9a-f]{24}$/)
  assert.equal(runIdFor(NONCE), id)
  assert.notEqual(runIdFor('f'.repeat(32)), id)
  assert.ok(!NONCE.includes(id) && !id.includes(NONCE.slice(0, 8)))
})

test('fillStep replaces only known placeholders and refuses unknown ones', () => {
  const step = { cmd: 'gcloud', args: ['builds', 'log', '<build-id>', '--x=<build-id>'] }
  assert.deepEqual(fillStep(step, { '<build-id>': 'abc' }), { cmd: 'gcloud', args: ['builds', 'log', 'abc', '--x=abc'] })
  assert.throws(() => fillStep(step, {}), /no value for <build-id>/)
})

test('lineSink hands onLog whole, sanitized lines', () => {
  const seen = []
  const sink = lineSink(l => seen.push(l))
  sink.write('Step #1: hel')
  sink.write('lo\n\x1b[2Kfake PASS\r\nlast')
  sink.end()
  assert.deepEqual(seen, ['Step #1: hello', '<ESC>fake PASS', 'last'])
})

test('cloud config: environment-free defaults, the XDG location, and strict checking', async () => {
  const home = await emptyHome()
  try {
    assert.equal(cloudConfigPath({ HOME: home }), path.join(home, '.config', 'git-bouncer', 'cloud.json'))
    const xdg = path.join(home, 'xdg')
    assert.equal(cloudConfigPath({ HOME: home, XDG_CONFIG_HOME: xdg }), path.join(xdg, 'git-bouncer', 'cloud.json'))
    assert.equal(cloudConfigPath({ HOME: home, XDG_CONFIG_HOME: 'relative/path' }), path.join(home, '.config', 'git-bouncer', 'cloud.json'))

    assert.deepEqual(await loadCloudConfig({ HOME: home }), { path: cloudConfigPath({ HOME: home }), gcp: {}, aws: {} })

    const file = cloudConfigPath({ HOME: home })
    await mkdir(path.dirname(file), { recursive: true })
    await writeFile(file, JSON.stringify({ aws: { project: 'git-bouncer', region: 'us-east-1', bucket: 'my-bucket' }, gcp: { project: 'my-project-123' } }))
    const cfg = await loadCloudConfig({ HOME: home })
    assert.deepEqual(cfg.aws, { project: 'git-bouncer', region: 'us-east-1', bucket: 'my-bucket' })
    assert.deepEqual(cfg.gcp, { project: 'my-project-123' })

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
    const counts = await copySandbox(sandbox, path.join(out, 'source'))
    assert.deepEqual(counts.files, 4)
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

test('defaultExec passes arguments to the program exactly, with no shell in between', async () => {
  const weird = ['$(echo pwned)', '`echo pwned`', 'a; echo pwned', 'a && echo pwned', 'a | b', '"double"', "'single'", '%PATH%', '*', '$HOME', '--flag=x', '']
  const r = await defaultExec(process.execPath, ['-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', '--', ...weird], { timeoutMs: 30_000 })
  assert.equal(r.code, 0, r.stderr)
  assert.deepEqual(JSON.parse(r.stdout), weird)
})

test('defaultExec feeds stdin, streams stdout, and reports a missing program instead of throwing', async () => {
  const chunks = []
  const echo = await defaultExec(process.execPath, ['-e', 'process.stdin.pipe(process.stdout)'], { input: 'hello', onStdout: c => chunks.push(c), timeoutMs: 30_000 })
  assert.equal(echo.code, 0)
  assert.equal(echo.stdout, 'hello')
  assert.equal(chunks.join(''), 'hello')

  const missing = await defaultExec('git-bouncer-no-such-program', ['--version'])
  assert.equal(missing.code, -1)
  assert.equal(missing.error.code, 'ENOENT')

  await assert.rejects(defaultExec('node -e 1', 'not an array'), /array of string arguments/)
})

test('defaultExec stops a program on timeout and on abort', async () => {
  const slow = ['-e', 'setTimeout(() => {}, 60000)']
  const timed = await defaultExec(process.execPath, slow, { timeoutMs: 300 })
  assert.equal(timed.timedOut, true)
  assert.notEqual(timed.code, 0)

  const ac = new AbortController()
  setTimeout(() => ac.abort(), 200)
  const aborted = await defaultExec(process.execPath, slow, { timeoutMs: 60_000, signal: ac.signal })
  assert.equal(aborted.aborted, true)
})

test('the runtime modules only ever use spawn(), never a shell', async () => {
  const files = (await readdir(SRC_DIR)).filter(f => /^(cloud-common|gcp|aws)\.js$/.test(f))
  assert.ok(files.includes('cloud-common.js'))
  for (const file of files) {
    const src = await readFile(path.join(SRC_DIR, file), 'utf8')
    const imports = src.split(/\r?\n/).filter(l => l.includes("'node:child_process'")) // CRLF on Windows checkouts
    assert.deepEqual(imports, file === 'cloud-common.js' ? ["import { spawn } from 'node:child_process'"] : [], file)
    assert.doesNotMatch(src, /shell:\s*true/, file)
    assert.doesNotMatch(src, /\b(execSync|execFile|execFileSync|spawnSync)\b/, file)
  }
  const common = await readFile(path.join(SRC_DIR, 'cloud-common.js'), 'utf8')
  assert.match(common, /spawn\(cmd, args, \{ shell: false/)
})

// ---------------------------------------------------------------------------------------------
// GCP Cloud Build
// ---------------------------------------------------------------------------------------------

const EXPECTED_CLOUDBUILD_YAML = `# Generated by git-bouncer for one scan. Not live-tested by the maintainer: see docs/cloud.md.
# Step 1 builds the sandbox image from git-bouncer's own sandbox/ folder. Step 2 runs the scanner
# in it with no credentials, no mounts, no environment and the same hardening as a local scan.
steps:
  - id: "build-sandbox-image"
    name: "gcr.io/cloud-builders/docker"
    env:
      - "DOCKER_BUILDKIT=1"
    args:
      - "build"
      - "--tag=git-bouncer-sandbox:scan"
      - "."
    timeout: "900s"
  - id: "scan"
    name: "gcr.io/cloud-builders/docker"
    args:
      - "run"
      - "--rm"
      - "--cap-drop=ALL"
      - "--security-opt=no-new-privileges"
      - "--read-only"
      - "--user=10001:10001"
      - "--tmpfs=/work:rw,noexec,nosuid,nodev,size=2g"
      - "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=768m"
      - "--pids-limit=512"
      - "--memory=3g"
      - "--network=bridge"
      - "git-bouncer-sandbox:scan"
      - "node"
      - "/opt/bouncer/scanner/main.js"
      - "--url=https://github.com/someone/take-home-test.git"
      - "--ref=v1.2.3"
      - "--nonce=0123456789abcdef0123456789abcdef"
    timeout: "1200s"
timeout: "1800s"
queueTtl: "900s"
tags:
  - "git-bouncer"
`

test('gcp: the generated cloudbuild.yaml, exactly', () => {
  assert.equal(renderCloudbuildYaml({ url: URL_, ref: 'v1.2.3', nonce: NONCE, project: 'my-project-123' }), EXPECTED_CLOUDBUILD_YAML)
})

test('gcp: every build step is an args array for the docker builder; no shell, no credentials', () => {
  for (const withSa of [false, true]) {
    const config = buildCloudbuildConfig({ url: URL_, ref: null, nonce: NONCE, project: 'my-project-123', serviceAccount: withSa ? `scanner${AT}my-project-123.iam.gserviceaccount.com` : null })
    assert.equal(config.steps.length, 2)
    for (const s of config.steps) {
      assert.equal(s.name, 'gcr.io/cloud-builders/docker')
      assert.ok(Array.isArray(s.args))
      assert.equal(s.entrypoint, undefined)
      assert.equal(s.script, undefined)
      assert.ok(!['sh', 'bash', '-c'].includes(s.args[0]))
      assert.equal(s.secretEnv, undefined)
      assert.equal(s.volumes, undefined)
    }
    assert.ok(!config.steps[1].args.includes('--ref'), 'no --ref when there is no ref')
    assert.ok(!config.steps[1].args.some(a => a.startsWith('--ref')))
    assert.equal(config.availableSecrets, undefined)
    assert.equal(config.images, undefined, 'nothing is pushed')
    assert.equal(config.artifacts, undefined, 'nothing is stored')
    assert.equal(config.timeout, '1800s')
  }
})

test('gcp: a configured service account is used, with Cloud Logging as Cloud Build requires', () => {
  const sa = `scanner${AT}my-project-123.iam.gserviceaccount.com`
  const config = buildCloudbuildConfig({ url: URL_, nonce: NONCE, project: 'my-project-123', serviceAccount: sa })
  assert.equal(config.serviceAccount, `projects/my-project-123/serviceAccounts/${sa}`)
  assert.deepEqual(config.options, { logging: 'CLOUD_LOGGING_ONLY' })
  const without = buildCloudbuildConfig({ url: URL_, nonce: NONCE, project: 'my-project-123' })
  assert.equal(without.serviceAccount, undefined)
  assert.equal(without.options, undefined)
})

test('gcp: hostile-looking but valid values stay single, "="-bound arguments; nothing for Cloud Build to expand', () => {
  const url = parseRepoUrl('https://gitlab.com/group/sub~group/re.po_-x').url
  const ref = 'feature/-rf+x' + AT + 'y'
  const yaml = renderCloudbuildYaml({ url, ref, nonce: NONCE, project: 'my-project-123' })
  assert.ok(yaml.includes(`      - "--url=${url}"\n`))
  assert.ok(yaml.includes(`      - "--ref=${ref}"\n`))
  assert.ok(!yaml.includes('$'), 'Cloud Build would expand $NAME')
  assert.equal(yaml.split('\n').length, EXPECTED_CLOUDBUILD_YAML.split('\n').length, 'same structure, line for line')
  assert.throws(() => renderCloudbuildYaml({ url: URL_, ref: '$PROJECT_ID', nonce: NONCE, project: 'my-project-123' }), /ref/)
})

test('gcp: plan() runs nothing and lists the exact commands scan() will run', async () => {
  const home = await emptyHome()
  try {
    const rt = createGcpRuntime({ exec: noExec, env: { HOME: home, GIT_BOUNCER_GCP_PROJECT: 'my-project-123', GIT_BOUNCER_GCP_REGION: 'europe-west4' } })
    const workDir = path.join(tmpdir(), 'gb-work')
    const p = await rt.plan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: '/opt/pkg/sandbox', workDir })
    const scope = ['--project=my-project-123', '--region=europe-west4']
    assert.deepEqual(p.steps.map(s => [s.id, s.cmd, ...s.args]), [
      ['submit', 'gcloud', 'builds', 'submit', path.join(workDir, 'source'), `--config=${path.join(workDir, 'cloudbuild.yaml')}`, ...scope, '--async', '--format=value(id)', '--quiet'],
      ['wait', 'gcloud', 'builds', 'log', '<build-id>', '--stream', ...scope, '--quiet'],
      ['status', 'gcloud', 'builds', 'describe', '<build-id>', ...scope, '--format=json', '--quiet'],
      ['log', 'gcloud', 'builds', 'log', '<build-id>', ...scope, '--quiet'],
      ['cleanup-source', 'gcloud', 'storage', 'rm', 'gs://<staged-bucket>/<staged-object>', '--project=my-project-123', '--quiet'],
      ['cancel', 'gcloud', 'builds', 'cancel', '<build-id>', ...scope, '--quiet'],
    ])
    assert.deepEqual(Object.keys(p.files), ['cloudbuild.yaml'])
    assert.ok(p.files['cloudbuild.yaml'].includes('--ref=v1.2.3'))
    assert.ok(p.notes[0].startsWith('Not live-tested by the maintainer'))

    // A dry run with nothing detected yet shows placeholders rather than guessing.
    const bare = createGcpRuntime({ exec: noExec, env: { HOME: home } })
    const dry = await bare.plan({ url: URL_, nonce: NONCE, sandboxDir: '/opt/pkg/sandbox' })
    assert.deepEqual(dry.steps[0].args, ['builds', 'submit', '<temp-dir>/source', '--config=<temp-dir>/cloudbuild.yaml', '--project=<project>', '--async', '--format=value(id)', '--quiet'])
    assert.ok(dry.notes.some(n => n.includes('gcloud config get-value project')))
  } finally {
    await rm(home, { recursive: true, force: true })
  }
})

test('gcp: available() explains each missing prerequisite', async () => {
  const home = await emptyHome()
  const env = extra => ({ HOME: home, ...extra })
  const ok = (_cmd, args) => {
    if (line(args, '--version')) return { stdout: 'Google Cloud SDK 500.0.0\n' }
    if (line(args, 'auth list')) return { stdout: `dev${AT}example.com\n` }
    if (line(args, 'config get-value project')) return { stdout: 'my-project-123\n' }
    return null
  }
  try {
    const win = fakeExec(ok)
    let r = await createGcpRuntime({ exec: win.exec, env: env(), platform: 'win32' }).available()
    assert.equal(r.ok, false)
    assert.match(r.reason, /\.cmd script.*WSL/)
    assert.equal(win.calls.length, 0, 'nothing is started on Windows')

    r = await createGcpRuntime({ exec: fakeExec(() => ({ code: -1, error: Object.assign(new Error('spawn gcloud ENOENT'), { code: 'ENOENT' }) })).exec, env: env(), platform: 'linux' }).available()
    assert.match(r.reason, /gcloud .* is not installed/)

    r = await createGcpRuntime({ exec: fakeExec((c, a) => (line(a, 'auth list') ? { stdout: '' } : ok(c, a))).exec, env: env(), platform: 'linux' }).available()
    assert.match(r.reason, /not signed in.*gcloud auth login/)

    r = await createGcpRuntime({ exec: fakeExec((c, a) => (line(a, 'config get-value') ? { stdout: '', stderr: '(unset)\n' } : ok(c, a))).exec, env: env(), platform: 'linux' }).available()
    assert.match(r.reason, /No Google Cloud project is selected/)
    assert.equal(r.account, `dev${AT}example.com`)

    const none = fakeExec(ok)
    r = await createGcpRuntime({ exec: none.exec, env: env({ GIT_BOUNCER_GCP_PROJECT: '--impersonate-service-account=x' }), platform: 'linux' }).available()
    assert.match(r.reason, /not a valid Google Cloud project ID/)
    assert.equal(none.calls.length, 0, 'bad settings are reported before anything runs')

    r = await createGcpRuntime({ exec: fakeExec(ok).exec, env: env({ GIT_BOUNCER_GCP_REGION: 'us central' }), platform: 'linux' }).available()
    assert.match(r.reason, /not a valid Cloud Build region/)

    const file = cloudConfigPath({ HOME: home })
    await mkdir(path.dirname(file), { recursive: true })
    await writeFile(file, '{ broken')
    r = await createGcpRuntime({ exec: fakeExec(ok).exec, env: env(), platform: 'linux' }).available()
    assert.match(r.reason, /cloud\.json is not valid JSON/)
    await rm(file)

    const good = fakeExec(ok)
    r = await createGcpRuntime({ exec: good.exec, env: env(), platform: 'linux' }).available()
    assert.deepEqual(r, { ok: true, account: `dev${AT}example.com`, project: 'my-project-123', region: 'global' })
    assert.deepEqual(good.argv(), [
      ['gcloud', '--version'],
      ['gcloud', 'auth', 'list', '--filter=status:ACTIVE', '--format=value(account)'],
      ['gcloud', 'config', 'get-value', 'project'],
    ])
    assert.equal(good.calls[0].opts.env.CLOUDSDK_CORE_DISABLE_PROMPTS, '1')

    const pinned = fakeExec(ok)
    r = await createGcpRuntime({ exec: pinned.exec, env: env({ GIT_BOUNCER_GCP_PROJECT: 'other-project-9' }), platform: 'linux' }).available()
    assert.equal(r.project, 'other-project-9')
    assert.ok(!pinned.argv().some(a => a.includes('get-value')), 'the configured project wins; gcloud is not asked')
  } finally {
    await rm(home, { recursive: true, force: true })
  }
})

test('gcp: extractStepOutput keeps the scan step\'s lines, without the prefix, and drops other steps', () => {
  const log = [
    'starting build "x"',
    'Step #0 - "build-sandbox-image": Sending build context',
    `Step #0 - "build-sandbox-image": -----BEGIN BOUNCER REPORT ${NONCE}-----`,
    'Step #1 - "scan": [scanner] content checks',
    'Step #1 - "scan":',
    'Step #1 - "other": not ours',
    'Step #1: unnamed form',
    'DONE',
  ].join('\n')
  assert.equal(extractStepOutput(log), ['starting build "x"', '[scanner] content checks', '', 'unnamed form', 'DONE'].join('\n'))
})

/** Canned gcloud answers for a successful Cloud Build scan. */
function gcpCloud({ nonce = NONCE, project = 'my-project-123', status = 'SUCCESS', onSubmit, onStream, stagedBucket } = {}) {
  const fullLog = [
    `starting build "${GCP_BUILD_ID}"`, '', 'FETCHSOURCE', 'BUILD',
    'Starting Step #0 - "build-sandbox-image"',
    'Step #0 - "build-sandbox-image": Successfully tagged git-bouncer-sandbox:scan',
    `Step #0 - "build-sandbox-image": -----END BOUNCER REPORT ${nonce}-----`,
    'Finished Step #0 - "build-sandbox-image"',
    'Starting Step #1 - "scan"',
    'Step #1 - "scan": [scanner] fetching one commit',
    ...report(nonce).map(l => `Step #1 - "scan":${l ? ` ${l}` : ''}`),
    'Finished Step #1 - "scan"', 'PUSH', 'DONE',
  ].join('\n')
  return async (_cmd, args, opts) => {
    if (line(args, '--version')) return { stdout: 'Google Cloud SDK 500.0.0\n' }
    if (line(args, 'auth list')) return { stdout: `dev${AT}example.com\n` }
    if (line(args, 'config get-value project')) return { stdout: `${project}\n` }
    if (line(args, 'builds submit')) { if (onSubmit) await onSubmit(args, opts); return { stdout: `${GCP_BUILD_ID}\n` } }
    if (line(args, `builds log ${GCP_BUILD_ID} --stream`)) return onStream ? onStream(args, opts) : { stdout: 'Step #1 - "scan": [scanner] fetching one commit\n' }
    if (line(args, `builds describe ${GCP_BUILD_ID}`)) {
      return { stdout: JSON.stringify({ id: GCP_BUILD_ID, status, logUrl: 'https://console.cloud.google.com/cloud-build/builds/x', source: { storageSource: { bucket: stagedBucket || defaultStagingBucket(project), object: STAGED_OBJECT } } }) }
    }
    if (line(args, `builds log ${GCP_BUILD_ID}`)) return { stdout: fullLog }
    if (line(args, 'storage rm')) return { stdout: '' }
    if (line(args, `builds cancel ${GCP_BUILD_ID}`)) return { stdout: '' }
    return null
  }
}

test('gcp: scan() runs exactly the planned commands, returns the report and leaves nothing behind', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  let uploaded = null
  let configOutsideSource = false
  try {
    const fake = fakeExec(gcpCloud({
      onSubmit: async args => {
        uploaded = await listTree(args[2])
        const config = args[3].slice('--config='.length)
        configOutsideSource = existsSync(config) && path.dirname(config) !== args[2]
        assert.equal(await readFile(config, 'utf8'), renderCloudbuildYaml({ url: URL_, ref: 'v1.2.3', nonce: NONCE, project: 'my-project-123' }))
      },
    }))
    const logs = []
    const rt = createGcpRuntime({ exec: fake.exec, env: { HOME: home }, platform: 'linux', sleep: noSleep })
    const { reportText, session } = await rt.scan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: sandbox, onLog: l => logs.push(l) })

    assert.ok(hasCompleteReport(reportText, NONCE))
    assert.ok(!reportText.includes('Successfully tagged'), 'other steps\' output is dropped')
    assert.deepEqual(uploaded, ['Dockerfile', 'osv-scanner.toml', 'scanner', 'scanner/main.js', 'scanner/package.json'], 'only the sandbox files are uploaded')
    assert.ok(configOutsideSource, 'cloudbuild.yaml sits next to the upload, not inside it')
    assert.deepEqual(fake.unexpected, [])

    const p = await createGcpRuntime({ exec: noExec, env: { HOME: home, GIT_BOUNCER_GCP_PROJECT: 'my-project-123' } })
      .plan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: sandbox, workDir: session.workDir })
    const vars = { '<build-id>': GCP_BUILD_ID, '<staged-bucket>': 'my-project-123_cloudbuild', '<staged-object>': STAGED_OBJECT }
    const planned = id => { const s = fillStep(p.steps.find(x => x.id === id), vars); return [s.cmd, ...s.args] }
    assert.deepEqual(fake.argv().slice(3), ['submit', 'wait', 'status', 'log', 'cleanup-source'].map(planned))

    assert.equal(session.status, 'SUCCESS')
    assert.equal(session.reportComplete, true)
    assert.deepEqual(session.cleanup, { cancelled: false, stagedSourceRemoved: true, workDirRemoved: true, problems: [] })
    assert.ok(!existsSync(session.workDir))
    assert.ok(logs.some(l => l.includes(GCP_BUILD_ID)))
    assert.equal(await rt.readFile(session, 'package-lock.json', 1000), null)
    await rt.destroy(session) // nothing left to do, and safe to call
    assert.equal(fake.argv().length, 8)
    assert.doesNotMatch(JSON.stringify(session), /token|secret|password/i)
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('gcp: Ctrl-C while waiting cancels the build, so nothing keeps billing', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  try {
    const ac = new AbortController()
    let workDir = null
    const fake = fakeExec(gcpCloud({
      onSubmit: args => { workDir = path.dirname(args[2]) },
      onStream: () => { ac.abort(); return { code: 1, aborted: true } },
    }))
    const rt = createGcpRuntime({ exec: fake.exec, env: { HOME: home, GIT_BOUNCER_GCP_PROJECT: 'my-project-123' }, platform: 'linux', sleep: noSleep })
    await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox, signal: ac.signal }), e => e.name === 'AbortError')
    const argv = fake.argv()
    assert.deepEqual(argv.at(-1), ['gcloud', 'builds', 'cancel', GCP_BUILD_ID, '--project=my-project-123', '--quiet'])
    assert.equal(fake.calls.at(-1).opts.signal, undefined, 'the cancel itself is not aborted')
    assert.ok(!argv.some(a => a.includes('storage')), 'the archive location is unknown until the build is described, so nothing is guessed')
    assert.ok(workDir && !existsSync(workDir), 'the temp folder is removed')
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('gcp: a build that never reports a status is cancelled after repeated failures', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  try {
    const base = gcpCloud()
    const fake = fakeExec((c, a, o) => (line(a, 'builds describe') ? { code: 1, stderr: 'ERROR: transient' } : base(c, a, o)))
    const rt = createGcpRuntime({ exec: fake.exec, env: { HOME: home, GIT_BOUNCER_GCP_PROJECT: 'my-project-123' }, platform: 'linux', sleep: noSleep })
    await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox }), /kept failing/)
    assert.equal(fake.argv().filter(a => a[2] === 'describe').length, 6)
    assert.deepEqual(fake.argv().at(-1).slice(0, 4), ['gcloud', 'builds', 'cancel', GCP_BUILD_ID])
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('gcp: a refused submit is reported (sanitized), nothing is cancelled, the temp folder is removed', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  try {
    let workDir = null
    const base = gcpCloud()
    const fake = fakeExec((c, a, o) => {
      if (line(a, 'builds submit')) { workDir = path.dirname(a[2]); return { code: 1, stderr: 'ERROR: (gcloud.builds.submit) PERMISSION_DENIED: \x1b[31mno\x1b[0m\n' } }
      return base(c, a, o)
    })
    const rt = createGcpRuntime({ exec: fake.exec, env: { HOME: home, GIT_BOUNCER_GCP_PROJECT: 'my-project-123' }, platform: 'linux', sleep: noSleep })
    await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox }), e => /did not start the build/.test(e.message) && /PERMISSION_DENIED/.test(e.message) && !e.message.includes('\x1b'))
    assert.ok(!fake.argv().some(a => a.includes('cancel')))
    assert.ok(workDir && !existsSync(workDir))
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('gcp: only the archive gcloud uploaded, in the project\'s own staging bucket, is ever deleted', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  try {
    const fake = fakeExec(gcpCloud({ stagedBucket: 'someone-elses-bucket' }))
    const rt = createGcpRuntime({ exec: fake.exec, env: { HOME: home, GIT_BOUNCER_GCP_PROJECT: 'my-project-123' }, platform: 'linux', sleep: noSleep })
    const { session } = await rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox })
    assert.ok(!fake.argv().some(a => a.includes('storage')))
    assert.equal(session.cleanup.stagedSourceRemoved, false)
    assert.match(session.cleanup.problems[0], /left alone/)
    assert.equal(defaultStagingBucket('my-google-project'), 'my-elgoog-project_cloudbuild')
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('gcp: invalid inputs are refused before any command runs', async () => {
  const fake = fakeExec(gcpCloud())
  const rt = createGcpRuntime({ exec: fake.exec, env: { HOME: '/nonexistent', GIT_BOUNCER_GCP_PROJECT: 'my-project-123' }, platform: 'linux' })
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
      - "docker build --tag=git-bouncer-sandbox:scan ."
      - "docker run --rm --cap-drop=ALL --security-opt=no-new-privileges --read-only --user=10001:10001 --tmpfs=/work:rw,noexec,nosuid,nodev,size=2g --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=768m --pids-limit=512 --memory=3g --network=bridge git-bouncer-sandbox:scan node /opt/bouncer/scanner/main.js --url=\\"$GIT_BOUNCER_URL\\" --ref=\\"$GIT_BOUNCER_REF\\" --nonce=\\"$GIT_BOUNCER_NONCE\\""
`

test('aws: the generated buildspec, exactly, with and without a ref', () => {
  assert.equal(renderBuildspec({ hasRef: true }), EXPECTED_BUILDSPEC)
  assert.equal(renderBuildspec({ hasRef: false }), EXPECTED_BUILDSPEC.replace(' --ref=\\"$GIT_BOUNCER_REF\\"', ''))
})

test('aws: the shell text never contains a value: only "$VAR" references inside double quotes', () => {
  const a = buildStartBuildRequest({ project: 'git-bouncer', bucket: 'my-bucket', runId: runIdFor(NONCE), url: URL_, ref: 'v1', nonce: NONCE })
  const hostileUrl = parseRepoUrl('https://gitlab.com/group/sub~group/re.po_-x').url
  const hostileRef = 'feature/-rf+x' + AT + 'y'
  const other = 'f'.repeat(64)
  const b = buildStartBuildRequest({ project: 'git-bouncer', bucket: 'my-bucket', runId: runIdFor(other), url: hostileUrl, ref: hostileRef, nonce: other })
  assert.equal(a.buildspecOverride, b.buildspecOverride, 'byte-for-byte the same whatever the values are')
  for (const v of [hostileUrl, hostileRef, other, URL_, NONCE]) assert.ok(!b.buildspecOverride.includes(v), v)
  assert.deepEqual(b.environmentVariablesOverride, [
    { name: 'GIT_BOUNCER_URL', value: hostileUrl, type: 'PLAINTEXT' },
    { name: 'GIT_BOUNCER_REF', value: hostileRef, type: 'PLAINTEXT' },
    { name: 'GIT_BOUNCER_NONCE', value: other, type: 'PLAINTEXT' },
  ])

  // Every word of the commands, other than the three references, is a plain constant word.
  for (const cmd of buildBuildspec({ hasRef: true }).phases.build.commands) {
    for (const word of cmd.split(' ')) {
      if (/^--(url|ref|nonce)="\$GIT_BOUNCER_(URL|REF|NONCE)"$/.test(word)) continue
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

test('aws: plan() runs nothing and lists the exact commands scan() will run', async () => {
  const home = await emptyHome()
  try {
    const env = { HOME: home, GIT_BOUNCER_AWS_PROJECT: 'git-bouncer', GIT_BOUNCER_AWS_BUCKET: 'my-bucket', GIT_BOUNCER_AWS_REGION: 'us-east-1' }
    const rt = createAwsRuntime({ exec: noExec, env })
    const workDir = path.join(tmpdir(), 'gb-work')
    const p = await rt.plan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: '/opt/pkg/sandbox', workDir })
    const prefix = `s3://my-bucket/git-bouncer/${runIdFor(NONCE)}/`
    assert.deepEqual(p.steps.map(s => [s.id, s.cmd, ...s.args]), [
      ['upload', 'aws', 's3', 'cp', path.join(workDir, 'source'), prefix, '--recursive', '--no-follow-symlinks', '--only-show-errors', '--region=us-east-1'],
      ['start', 'aws', 'codebuild', 'start-build', `--cli-input-json=file://${path.join(workDir, 'start-build.json')}`, '--region=us-east-1', '--output=json'],
      ['wait', 'aws', 'codebuild', 'batch-get-builds', '--ids=<build-id>', '--region=us-east-1', '--output=json'],
      ['log', 'aws', 'logs', 'get-log-events', '--log-group-name=<log-group>', '--log-stream-name=<log-stream>', '--start-from-head', '--region=us-east-1', '--output=json'],
      ['cleanup-source', 'aws', 's3', 'rm', prefix, '--recursive', '--only-show-errors', '--region=us-east-1'],
      ['cancel', 'aws', 'codebuild', 'stop-build', '--id=<build-id>', '--region=us-east-1', '--output=json'],
    ])
    assert.deepEqual(Object.keys(p.files), ['start-build.json', 'buildspec.yml'])
    const req = JSON.parse(p.files['start-build.json'])
    assert.equal(req.buildspecOverride, p.files['buildspec.yml'])
    assert.equal(req.buildspecOverride, EXPECTED_BUILDSPEC)
    assert.ok(p.notes[0].startsWith('Not live-tested by the maintainer'))

    // The AWS CLI reads a value starting with file:// (and in v1, http:// or https://) as "load the
    // value from there". Only the request file is meant to be read that way.
    for (const s of p.steps) {
      for (const a of s.args) {
        const value = a.includes('=') ? a.slice(a.indexOf('=') + 1) : a
        if (a.startsWith('--cli-input-json=')) continue
        assert.doesNotMatch(value, /^(file|fileb|https?):\/\//i, a)
      }
    }
  } finally {
    await rm(home, { recursive: true, force: true })
  }
})

test('aws: available() explains each missing prerequisite', async () => {
  const home = await emptyHome()
  const base = { HOME: home, GIT_BOUNCER_AWS_PROJECT: 'git-bouncer', GIT_BOUNCER_AWS_BUCKET: 'my-bucket' }
  const ok = (_cmd, args) => {
    if (line(args, '--version')) return { stdout: 'aws-cli/2.17.0\n' }
    if (line(args, 'configure get region')) return { stdout: 'eu-west-1\n' }
    if (line(args, 'sts get-caller-identity')) return { stdout: JSON.stringify({ Account: '123456789012', Arn: 'arn:aws:sts::123456789012:assumed-role/dev/me', UserId: 'X' }) }
    if (line(args, 'codebuild batch-get-projects')) return { stdout: JSON.stringify({ projects: [{ name: 'git-bouncer' }], projectsNotFound: [] }) }
    return null
  }
  const check = async (env, respond = ok) => createAwsRuntime({ exec: fakeExec(respond).exec, env }).available()
  try {
    assert.match((await check(base, () => ({ code: -1, error: Object.assign(new Error('spawn aws ENOENT'), { code: 'ENOENT' }) }))).reason, /AWS CLI .* not installed/)
    assert.match((await check({ HOME: home, GIT_BOUNCER_AWS_BUCKET: 'my-bucket' })).reason, /No CodeBuild project is configured/)
    assert.match((await check({ HOME: home, GIT_BOUNCER_AWS_PROJECT: 'git-bouncer' })).reason, /No S3 bucket is configured/)
    assert.match((await check({ ...base, GIT_BOUNCER_AWS_BUCKET: 'my.dotted.bucket' })).reason, /not a bucket name git-bouncer accepts/)
    assert.match((await check({ ...base, GIT_BOUNCER_AWS_PROJECT: '--endpoint-url=x' })).reason, /not a valid CodeBuild project name/)
    assert.match((await check(base, (c, a) => (line(a, 'configure get') ? { code: 1 } : ok(c, a)))).reason, /No AWS region is set/)
    assert.match((await check(base, (c, a) => (line(a, 'sts') ? { code: 255, stderr: 'Unable to locate credentials' } : ok(c, a)))).reason, /not signed in/)
    const missing = await check(base, (c, a) => (line(a, 'codebuild batch-get-projects') ? { stdout: JSON.stringify({ projects: [], projectsNotFound: ['git-bouncer'] }) } : ok(c, a)))
    assert.match(missing.reason, /CodeBuild project "git-bouncer" was not found in eu-west-1/)
    assert.equal(missing.account, 'arn:aws:sts::123456789012:assumed-role/dev/me')

    const good = fakeExec(ok)
    const r = await createAwsRuntime({ exec: good.exec, env: base }).available()
    assert.deepEqual(r, { ok: true, account: 'arn:aws:sts::123456789012:assumed-role/dev/me', project: 'git-bouncer', region: 'eu-west-1', bucket: 'my-bucket' })
    assert.deepEqual(good.argv(), [
      ['aws', '--version'],
      ['aws', 'configure', 'get', 'region'],
      ['aws', 'sts', 'get-caller-identity', '--region=eu-west-1', '--output=json'],
      ['aws', 'codebuild', 'batch-get-projects', '--names=git-bouncer', '--region=eu-west-1', '--output=json'],
    ])
    assert.equal(good.calls[0].opts.env.AWS_PAGER, '')

    const pinned = fakeExec(ok)
    await createAwsRuntime({ exec: pinned.exec, env: { ...base, AWS_REGION: 'ap-southeast-2' } }).available()
    assert.ok(!pinned.argv().some(a => a.includes('configure')), 'a region from the environment wins')
    assert.ok(pinned.argv().some(a => a.includes('--region=ap-southeast-2')))
  } finally {
    await rm(home, { recursive: true, force: true })
  }
})

test('aws: joinLogEvents puts lines (and lines split across events) back together', () => {
  assert.equal(joinLogEvents([{ message: 'a\n' }, { message: 'b' }, { message: 'c\n' }]), 'a\nbc\n')
  assert.equal(joinLogEvents([{ message: 'a' }, { message: 'b' }]), 'a\nb')
  assert.equal(joinLogEvents([{ message: 'a\n' }, {}, null, { message: 7 }]), 'a\n')
  assert.equal(joinLogEvents(undefined), '')
})

/** Canned aws answers for a successful CodeBuild scan. */
function awsCloud({ nonce = NONCE, onUpload, onStart, pollsBeforeDone = 1, logAnswers } = {}) {
  let polls = 0
  const events = [
    '[Container] Running command docker build --tag=git-bouncer-sandbox:scan .\n',
    `${'-----END BOUNCER REPORT'} ${nonce}-----\n`.replace(/^/, 'not at line start: '),
    '[scanner] fetching one commit\n',
    ...report(nonce).map(l => `${l}\n`),
  ].map(message => ({ timestamp: 1, message }))
  let logCall = 0
  return async (_cmd, args, opts) => {
    if (line(args, '--version')) return { stdout: 'aws-cli/2.17.0\n' }
    if (line(args, 'sts get-caller-identity')) return { stdout: JSON.stringify({ Arn: 'arn:aws:iam::123456789012:user/dev' }) }
    if (line(args, 'codebuild batch-get-projects')) return { stdout: JSON.stringify({ projects: [{ name: 'git-bouncer' }] }) }
    if (line(args, 's3 cp')) { if (onUpload) await onUpload(args, opts); return {} }
    if (line(args, 'codebuild start-build')) { if (onStart) await onStart(args, opts); return { stdout: JSON.stringify({ build: { id: AWS_BUILD_ID, buildStatus: 'IN_PROGRESS' } }) } }
    if (line(args, 'codebuild batch-get-builds')) {
      polls += 1
      const done = polls > pollsBeforeDone
      return {
        stdout: JSON.stringify({ builds: [{
          id: AWS_BUILD_ID, buildStatus: done ? 'SUCCEEDED' : 'IN_PROGRESS', buildComplete: done, currentPhase: done ? 'COMPLETED' : 'BUILD',
          logs: { groupName: '/aws/codebuild/git-bouncer', streamName: AWS_BUILD_ID.split(':')[1], deepLink: 'https://console.aws.amazon.com/cloudwatch/home#logEvent' },
        }] }),
      }
    }
    if (line(args, 'logs get-log-events')) {
      logCall += 1
      if (logAnswers) return logAnswers(logCall, args, events)
      const paged = args.some(a => a.startsWith('--next-token='))
      return { stdout: JSON.stringify(paged ? { events: [], nextForwardToken: 'f/2' } : { events, nextForwardToken: 'f/2' }) }
    }
    if (line(args, 's3 rm')) return {}
    if (line(args, 'codebuild stop-build')) return { stdout: '{}' }
    return null
  }
}

const AWS_ENV = home => ({ HOME: home, GIT_BOUNCER_AWS_PROJECT: 'git-bouncer', GIT_BOUNCER_AWS_BUCKET: 'my-bucket', GIT_BOUNCER_AWS_REGION: 'us-east-1' })

test('aws: scan() runs exactly the planned commands, returns the report and leaves nothing behind', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  let uploaded = null
  let request = null
  try {
    const fake = fakeExec(awsCloud({
      onUpload: async args => { uploaded = await listTree(args[2]) },
      onStart: async args => { request = JSON.parse(await readFile(args[2].slice('--cli-input-json=file://'.length), 'utf8')) },
    }))
    const logs = []
    const rt = createAwsRuntime({ exec: fake.exec, env: AWS_ENV(home), sleep: noSleep })
    const { reportText, session } = await rt.scan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: sandbox, onLog: l => logs.push(l) })

    assert.ok(hasCompleteReport(reportText, NONCE))
    assert.deepEqual(uploaded, ['Dockerfile', 'osv-scanner.toml', 'scanner', 'scanner/main.js', 'scanner/package.json'], 'only the sandbox files are uploaded')
    assert.deepEqual(request, buildStartBuildRequest({ project: 'git-bouncer', bucket: 'my-bucket', runId: runIdFor(NONCE), url: URL_, ref: 'v1.2.3', nonce: NONCE }))
    assert.deepEqual(fake.unexpected, [])

    const p = await createAwsRuntime({ exec: noExec, env: AWS_ENV(home) }).plan({ url: URL_, ref: 'v1.2.3', nonce: NONCE, sandboxDir: sandbox, workDir: session.workDir })
    const vars = { '<build-id>': AWS_BUILD_ID, '<log-group>': '/aws/codebuild/git-bouncer', '<log-stream>': AWS_BUILD_ID.split(':')[1] }
    const planned = (id, extra = []) => { const s = fillStep(p.steps.find(x => x.id === id), vars); return [s.cmd, ...s.args, ...extra] }
    assert.deepEqual(fake.argv().slice(3), [
      planned('upload'), planned('start'), planned('wait'), planned('wait'),
      planned('log'), planned('log', ['--next-token=f/2']),
      planned('cleanup-source'),
    ])

    assert.equal(session.status, 'SUCCEEDED')
    assert.equal(session.reportComplete, true)
    assert.deepEqual(session.cleanup, { cancelled: false, sourceRemoved: true, workDirRemoved: true, problems: [] })
    assert.ok(!existsSync(session.workDir))
    assert.ok(logs.some(l => l.includes(AWS_BUILD_ID)))
    assert.ok(logs.includes('CodeBuild: BUILD'))
    assert.equal(await rt.readFile(session, 'package-lock.json', 1000), null)
    await rt.destroy(session)
    assert.equal(fake.argv().length, 10, 'destroy() after a clean scan has nothing left to do')
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('aws: a log that is still arriving is read again until the report is complete', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  try {
    const sleeps = []
    let reads = 0
    const fake = fakeExec(awsCloud({
      logAnswers: (_n, args, events) => {
        if (args.some(a => a.startsWith('--next-token='))) return { stdout: JSON.stringify({ events: [], nextForwardToken: 'f/1' }) }
        reads += 1 // the first read is missing the end marker, as if CloudWatch hadn't caught up yet
        return { stdout: JSON.stringify({ events: reads === 1 ? events.slice(0, -1) : events, nextForwardToken: 'f/1' }) }
      },
    }))
    const rt = createAwsRuntime({ exec: fake.exec, env: AWS_ENV(home), sleep: async ms => { sleeps.push(ms) } })
    const { session } = await rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox })
    assert.equal(session.reportComplete, true)
    assert.deepEqual(sleeps, [10000, 5000], 'one status poll interval, then one wait for the log')
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('aws: Ctrl-C while waiting stops the build and deletes the upload', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  try {
    const ac = new AbortController()
    const fake = fakeExec(awsCloud({ pollsBeforeDone: 100 }))
    const rt = createAwsRuntime({ exec: fake.exec, env: AWS_ENV(home), sleep: async () => { ac.abort() } })
    await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox, signal: ac.signal }), e => e.name === 'AbortError')
    const tail = fake.argv().slice(-2)
    assert.deepEqual(tail[0], ['aws', 'codebuild', 'stop-build', `--id=${AWS_BUILD_ID}`, '--region=us-east-1', '--output=json'])
    assert.deepEqual(tail[1].slice(0, 3), ['aws', 's3', 'rm'])
    assert.equal(fake.calls.at(-2).opts.signal, undefined, 'stopping is not itself aborted')
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('aws: a refused start-build still deletes the upload; nothing to stop', async () => {
  const home = await emptyHome()
  const sandbox = await makeSandbox()
  try {
    const base = awsCloud()
    const fake = fakeExec((c, a, o) => (line(a, 'codebuild start-build') ? { code: 254, stderr: 'An error occurred (AccessDeniedException)\n' } : base(c, a, o)))
    const rt = createAwsRuntime({ exec: fake.exec, env: AWS_ENV(home), sleep: noSleep })
    await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: sandbox }), /did not start the build: An error occurred \(AccessDeniedException\)/)
    assert.ok(!fake.argv().some(a => a.includes('stop-build')))
    assert.deepEqual(fake.argv().at(-1).slice(0, 3), ['aws', 's3', 'rm'])
  } finally {
    await rm(home, { recursive: true, force: true })
    await rm(sandbox, { recursive: true, force: true })
  }
})

test('aws: invalid inputs are refused before any command runs', async () => {
  const fake = fakeExec(awsCloud())
  const rt = createAwsRuntime({ exec: fake.exec, env: { HOME: '/nonexistent', GIT_BOUNCER_AWS_PROJECT: 'git-bouncer', GIT_BOUNCER_AWS_BUCKET: 'my-bucket', GIT_BOUNCER_AWS_REGION: 'us-east-1' } })
  await assert.rejects(rt.scan({ url: URL_, ref: 'a b', nonce: NONCE, sandboxDir: '/nowhere' }), /ref/)
  await assert.rejects(rt.scan({ url: 'https://github.com/o/`id`.git', nonce: NONCE, sandboxDir: '/nowhere' }), /repository URL/)
  await assert.rejects(rt.plan({ url: URL_, nonce: 'NOPE', sandboxDir: '/nowhere' }), /nonce/)
  await assert.rejects(rt.scan({ url: URL_, nonce: NONCE, sandboxDir: 'relative/sandbox' }), /sandbox folder/)
  assert.equal(fake.calls.length, 0)
})
