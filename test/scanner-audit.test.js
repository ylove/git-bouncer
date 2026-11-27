// Regression tests for the v1.0.0 release-gate audit (scanner side). Each test reproduces one audit
// finding with a fixture generated at test time, and must keep passing. Payloads are inert text, and
// hostile strings are built from split literals so this file scans clean with the repo's own scanner.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Findings } from '../sandbox/scanner/findings.js'
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
