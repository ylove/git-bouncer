// Turn findings into a verdict.
//
//   critical / high -> FAIL  "turned away"  strong signal the repo may attack you on open or install
//   medium          -> WARN  "warning"      a person should look before trusting it
//   low / info      -> PASS  "let in"       shown for context, never blocks
//
// The policy lives in one small function so it's easy to review and test.

export const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info'])

export const EXIT = Object.freeze({ PASS: 0, FAIL: 1, ERROR: 2, WARN: 3 })

/**
 * @param {Array<{severity: string}>} findings
 * @returns {{verdict: 'pass'|'warn'|'fail', counts: Record<string, number>, exitCode: number}}
 */
export function computeVerdict(findings) {
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, 0]))
  for (const f of findings) {
    // An unknown severity is treated as the worst case, never silently ignored.
    if (Object.hasOwn(counts, f.severity)) counts[f.severity]++
    else counts.critical++
  }
  let verdict = 'pass'
  if (counts.critical || counts.high) verdict = 'fail'
  else if (counts.medium) verdict = 'warn'
  const exitCode = verdict === 'fail' ? EXIT.FAIL : verdict === 'warn' ? EXIT.WARN : EXIT.PASS
  return { verdict, counts, exitCode }
}
