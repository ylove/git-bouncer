// git-bouncer must pass its own pat-down. If a change makes this repo look malicious to its own
// scanner (say, by committing a literal IOC or a fake-font fixture), this test catches it.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { Findings } from '../sandbox/scanner/findings.js'
import { contentChecks } from '../sandbox/scanner/checks/content.js'
import { autorunChecks } from '../sandbox/scanner/checks/autorun.js'
import { dependencyChecks } from '../sandbox/scanner/checks/deps.js'

test('this repository scans clean with its own scanner (no medium, high or critical findings)', async () => {
  const root = fileURLToPath(new URL('..', import.meta.url))
  const f = new Findings()
  await contentChecks(root, f)
  await autorunChecks(root, f)
  // Static dependency checks only; and never move this repo's real config files aside.
  await dependencyChecks(root, f, { skipInstall: true, osvBin: 'osv-scanner-not-installed-in-unit-tests', dryRun: true })
  const serious = f.toJSON().filter(x => ['critical', 'high', 'medium'].includes(x.severity) && x.id !== 'DEP-OSV-UNAVAILABLE')
  assert.deepEqual(serious.map(x => `${x.id} ${x.file ?? ''}:${x.line ?? ''} ${x.evidence ?? ''}`), [])
})
