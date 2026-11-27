import { test } from 'node:test'
import assert from 'node:assert/strict'
import { extractReport } from '../src/report.js'
import { runArgs } from '../src/runtimes/container.js'
import { installCommand, manualInstallHint, installEnv, validateGeneratedLockfile, HandoffError } from '../src/handoff.js'
import { which } from '../src/proc.js'

const N = 'a'.repeat(32)
const SHA = 'b'.repeat(40)
const frame = (obj, nonce = N) => `noise\n-----BEGIN BOUNCER REPORT ${nonce}-----\n${typeof obj === 'string' ? obj : JSON.stringify(obj)}\n-----END BOUNCER REPORT ${nonce}-----\n`
const good = (over = {}) => ({
  schema: 1, status: 'ok', target: { url: 'https://github.com/a/b.git', commit: SHA, tree: SHA, defaultBranch: 'main' },
  packageManager: { kind: 'npm', lockfile: 'package-lock.json', generatedLockfile: false, installed: true },
  timings: { clone: 1, git: 1, content: 1, autorun: 1, dependencies: 1 }, findings: [], ...over,
})

test('a well-formed report is complete', () => {
  const r = extractReport(frame(good()), N)
  assert.equal(r.complete, true, r.problems.join())
  assert.equal(r.report.target.commit, SHA)
})

test('a report framed with a different nonce is not accepted', () => {
  const r = extractReport(frame(good(), 'c'.repeat(32)), N)
  assert.equal(r.report, null)
  assert.equal(r.complete, false)
})

test('missing phases, error status or a missing commit make the scan incomplete', () => {
  assert.equal(extractReport(frame(good({ timings: { clone: 1 } })), N).complete, false)
  assert.equal(extractReport(frame(good({ status: 'error', error: 'boom' })), N).complete, false)
  assert.equal(extractReport(frame(good({ target: { commit: 'not-a-sha' } })), N).complete, false)
  assert.equal(extractReport(frame('{not json'), N).complete, false)
  assert.equal(extractReport('', N).complete, false)
})

test('malformed findings become a high-severity finding instead of disappearing', () => {
  const r = extractReport(frame(good({ findings: [{ id: 'lower-case', severity: 'info' }, null, { id: 'OK-ID', severity: 'low', title: 't' }] })), N)
  assert.equal(r.report.findings.filter(f => f.id === 'REPORT-MALFORMED-FINDING' && f.severity === 'high').length, 2)
  assert.equal(r.complete, false)
})

test('unknown severities are passed through so the verdict fails closed on them', () => {
  const r = extractReport(frame(good({ findings: [{ id: 'X', severity: 'apocalyptic', title: 't' }] })), N)
  assert.equal(r.report.findings[0].severity, 'apocalyptic')
})

test('oversized strings are clipped and unexpected package-manager values dropped', () => {
  const r = extractReport(frame(good({ findings: [{ id: 'X', severity: 'low', title: 'x'.repeat(5000) }], packageManager: { kind: 'evil', lockfile: '../../etc/passwd' } })), N)
  assert.equal(r.report.findings[0].title.length, 300)
  assert.deepEqual([r.report.packageManager.kind, r.report.packageManager.lockfile], ['none', null])
})

test('the container flags are the hardened set, with no mounts and no environment', () => {
  const args = runArgs({ name: 'n', image: 'img:1' })
  for (const flag of ['--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--pull=never']) assert.ok(args.includes(flag), flag)
  assert.equal(args[args.indexOf('--user') + 1], '10001:10001')
  assert.ok(args.some(a => a.startsWith('/work:') && a.includes('noexec') && a.includes('mode=1777') && !a.includes('uid=')), 'Podman rejects uid=/gid= tmpfs options')
  for (const forbidden of ['-v', '--volume', '--mount', '-e', '--env', '--env-file', '--privileged', '--cap-add']) assert.ok(!args.includes(forbidden), forbidden)
  assert.equal(args.at(-1), 'img:1')
})

test('only npm is installed automatically, lockfile-exact, with an ignore-scripts variant', () => {
  assert.deepEqual(installCommand('npm', { ignoreScripts: false }), ['npm', ['ci']])
  assert.deepEqual(installCommand('npm', { ignoreScripts: true }), ['npm', ['ci', '--ignore-scripts']])
  for (const kind of ['yarn', 'pnpm', 'bun', 'none']) assert.equal(installCommand(kind, {}), null, kind)
  assert.match(manualInstallHint('pnpm'), /--ignore-scripts/)
})

test('the install environment has no tokens or cloud credentials in it', () => {
  const env = installEnv({ PATH: '/usr/bin', HOME: '/h', GITHUB_TOKEN: 'x', GH_TOKEN: 'x', NPM_TOKEN: 'x', AWS_SECRET_ACCESS_KEY: 'x', AWS_PROFILE: 'x', OPENAI_API_KEY: 'x', MY_PASSWORD: 'x', npm_config__authToken: 'x', CLOUDSDK_CONFIG: 'x' })
  assert.deepEqual(Object.keys(env).sort(), ['HOME', 'PATH'])
})

test('which() never resolves a program through a relative PATH entry', async () => {
  const { mkdtemp, writeFile, chmod, rm } = await import('node:fs/promises')
  const { tmpdir } = await import('node:os')
  const path = await import('node:path')
  const dir = await mkdtemp(path.join(tmpdir(), 'bouncer-which-'))
  try {
    const name = process.platform === 'win32' ? 'fakegit.cmd' : 'fakegit'
    await writeFile(path.join(dir, name), 'echo hi\n')
    await chmod(path.join(dir, name), 0o755)
    const cwd = process.cwd()
    process.chdir(dir)
    try {
      assert.equal(await which('fakegit', { PATH: `.${path.delimiter}./node_modules/.bin`, PATHEXT: '.CMD' }), null)
      assert.equal(await which('fakegit', { PATH: dir, PATHEXT: '.CMD' }), path.join(dir, name))
    } finally { process.chdir(cwd) }
  } finally { await rm(dir, { recursive: true, force: true }) }
})

test('a lockfile coming out of the sandbox must be registry-only with sha512 hashes', () => {
  const ok = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/ms': { resolved: 'https://registry.npmjs.org/ms/-/ms-2.1.3.tgz', integrity: 'sha512-abc=' } } })
  assert.equal(validateGeneratedLockfile(ok), ok)
  for (const bad of [
    JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/../../x': { resolved: 'https://registry.npmjs.org/x/-/x-1.tgz', integrity: 'sha512-a' } } }),
    JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/x': { link: true, resolved: '../../outside' } } }),
    '{oops',
    JSON.stringify({ lockfileVersion: 1, dependencies: {} }),
    JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/x': { resolved: 'https://evil.example/x.tgz', integrity: 'sha512-a' } } }),
    JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/x': { resolved: 'https://registry.npmjs.org/x/-/x-1.tgz', integrity: 'sha1-a' } } }),
  ]) assert.throws(() => validateGeneratedLockfile(bad), HandoffError)
})
