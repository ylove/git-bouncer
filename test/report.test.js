import { test } from 'node:test'
import assert from 'node:assert/strict'
import { extractReport } from '../src/report.js'
import { runArgs } from '../src/runtimes/container.js'
import { installCommand, validateGeneratedLockfile, HandoffError } from '../src/handoff.js'

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
  assert.ok(args.some(a => a.startsWith('/work:') && a.includes('noexec')))
  for (const forbidden of ['-v', '--volume', '--mount', '-e', '--env', '--env-file', '--privileged', '--cap-add']) assert.ok(!args.includes(forbidden), forbidden)
  assert.equal(args.at(-1), 'img:1')
})

test('install commands are lockfile-exact, with an ignore-scripts variant for each manager', () => {
  assert.deepEqual(installCommand('npm', { ignoreScripts: false }), ['npm', ['ci']])
  assert.deepEqual(installCommand('npm', { ignoreScripts: true }), ['npm', ['ci', '--ignore-scripts']])
  assert.deepEqual(installCommand('yarn', { ignoreScripts: true, yarnMajor: 4 }), ['yarn', ['install', '--immutable', '--mode=skip-build']])
  assert.deepEqual(installCommand('yarn', { ignoreScripts: false, yarnMajor: 1 }), ['yarn', ['install', '--frozen-lockfile']])
  assert.deepEqual(installCommand('pnpm', { ignoreScripts: true }), ['pnpm', ['install', '--frozen-lockfile', '--ignore-scripts']])
  assert.equal(installCommand('none', {}), null)
})

test('a lockfile coming out of the sandbox must be registry-only with sha512 hashes', () => {
  const ok = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/ms': { resolved: 'https://registry.npmjs.org/ms/-/ms-2.1.3.tgz', integrity: 'sha512-abc=' } } })
  assert.equal(validateGeneratedLockfile(ok), ok)
  for (const bad of [
    '{oops',
    JSON.stringify({ lockfileVersion: 1, dependencies: {} }),
    JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/x': { resolved: 'https://evil.example/x.tgz', integrity: 'sha512-a' } } }),
    JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/x': { resolved: 'https://registry.npmjs.org/x/-/x-1.tgz', integrity: 'sha1-a' } } }),
  ]) assert.throws(() => validateGeneratedLockfile(bad), HandoffError)
})
