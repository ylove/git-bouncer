// Regression tests for the v1.0.0 release-gate audit (scanner side). Each test reproduces one audit
// finding with a fixture generated at test time, and must keep passing. Payloads are inert text, and
// hostile strings are built from split literals so this file scans clean with the repo's own scanner.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { Findings } from '../sandbox/scanner/findings.js'
import { gitChecks } from '../sandbox/scanner/clone.js'
import { dependencyChecks } from '../sandbox/scanner/checks/deps.js'
import { fixture } from './helpers/fixture.js'
import { fakeOsv } from './helpers/fake-osv.js'

const posix = process.platform === 'win32' ? 'uses a POSIX shell script as a stand-in for osv-scanner' : false
const ids = list => list.map(f => `${f.id}:${f.severity}`)

const LOCK = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/ms': { version: '2.1.3', resolved: 'https://registry.npmjs.org/ms/-/ms-2.1.3.tgz', integrity: 'sha512-x' } } })

/** Static dependency checks with a fake osv-scanner; returns the findings and every osv invocation. */
async function depsWithOsv(files, report) {
  const fx = await fixture(files)
  const osv = await fakeOsv(report)
  try {
    const f = new Findings()
    await dependencyChecks(fx.dir, f, { skipInstall: true, osvBin: osv.bin, osvConfig: 'bouncer-osv.toml' })
    return { findings: f.toJSON(), calls: await osv.calls() }
  } finally { await fx.cleanup(); await osv.cleanup() }
}

// --- 11: ordinary CVEs answer "is this app vulnerable?", not "will this repo attack me?" ---------

test('[audit 11] known vulnerabilities are low, with the counts kept in the title', { skip: posix }, async () => {
  const report = { results: [{ packages: [{
    package: { name: 'ms', version: '2.1.3', ecosystem: 'npm' },
    vulnerabilities: [{ id: 'GHSA-0000-0000-0000' }],
    groups: [{ ids: ['GHSA-0000-0000-0000'], max_severity: '9.8' }],
  }] }] }
  const { findings } = await depsWithOsv({ 'package.json': '{"dependencies":{"ms":"2.1.3"}}', 'package-lock.json': LOCK }, report)
  const vuln = findings.find(f => f.id === 'DEP-VULN')
  assert.ok(vuln, ids(findings))
  assert.equal(vuln.severity, 'low')
  assert.match(vuln.title, /1 known vulnerability in 1 package\(s\) \(1 critical, 0 high\)/)
})

// --- 8: a pom.xml <repositories> URL steered osv-scanner at the host's 127.0.0.1 ------------------

test('[audit 8] osv-scanner never resolves transitive dependencies (no fetching from repo-chosen servers)', { skip: posix }, async () => {
  const pom = '<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>y</artifactId><version>1</version>' +
    '<repositories><repository><id>r</id><url>https://repo.example.invalid/maven/</url></repository></repositories></project>'
  const { calls } = await depsWithOsv({ 'pom.xml': pom, 'package.json': '{}', 'package-lock.json': LOCK })
  assert.equal(calls.length, 2, JSON.stringify(calls))
  for (const args of calls) {
    assert.ok(args.includes('--no-resolve'), `every osv-scanner run needs --no-resolve: ${args.join(' ')}`)
    assert.equal(args[args.indexOf('--config') + 1], 'bouncer-osv.toml', 'and always our own config, never the repo\'s')
  }
  assert.deepEqual(calls.map(a => a[a.indexOf('-L') + 1]).sort(), ['package-lock.json', 'pom.xml'])
})

// --- 5: a repo-shipped .yarn/releases/yarn-*.cjs is repo code that every yarn command runs ---------

test('[audit 5] yarnPath is a warning even at the standard .yarn/releases path', async () => {
  const fx = await fixture({ '.yarnrc.yml': 'yarnPath: .yarn/releases/yarn-4.5.0.cjs\n' })
  try {
    const f = new Findings()
    await dependencyChecks(fx.dir, f, { skipInstall: true, osvBin: 'osv-scanner-not-installed-in-unit-tests' })
    const y = f.toJSON().find(x => x.id === 'YARN-PATH')
    assert.equal(y?.severity, 'medium', ids(f.toJSON()))
    assert.match(y.detail, /repo-controlled code/)
  } finally { await fx.cleanup() }
})

// --- 14: a failed `git ls-files` silently skipped every git-level check ---------------------------

test('[audit 14] a git listing that fails is reported as a coverage gap, not a clean result', { skip: posix }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'bouncer-git-'))
  try {
    execFileSync('git', ['-C', dir, 'init', '-q'])
    await writeFile(path.join(dir, '.git', 'index'), 'DIRC this is not a valid index') // ls-files refuses it
    const f = new Findings()
    await gitChecks(dir, f)
    const r = f.toJSON()
    assert.ok(r.some(x => x.id === 'GIT-LISTING-INCOMPLETE' && x.severity === 'medium' && /exited/.test(x.evidence)), ids(r))
  } finally { await rm(dir, { recursive: true, force: true }) }
})
