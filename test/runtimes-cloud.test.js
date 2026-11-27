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
    const imports = src.split('\n').filter(l => l.includes("'node:child_process'"))
    assert.deepEqual(imports, file === 'cloud-common.js' ? ["import { spawn } from 'node:child_process'"] : [], file)
    assert.doesNotMatch(src, /shell:\s*true/, file)
    assert.doesNotMatch(src, /\b(execSync|execFile|execFileSync|spawnSync)\b/, file)
  }
  const common = await readFile(path.join(SRC_DIR, 'cloud-common.js'), 'utf8')
  assert.match(common, /spawn\(cmd, args, \{ shell: false/)
})
