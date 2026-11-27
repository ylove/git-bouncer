// Turn findings into a verdict.
//
//   critical / high -> FAIL  "turned away"  strong signal the repo may attack you on open or install
//   medium          -> WARN  "warning"      a person should look before trusting it
//   low / info      -> PASS  "let in"       shown for context, never blocks
//
// Fail closed, twice over:
//   - A scan only counts as clean if the caller says every check actually completed. An empty
//     findings list from a scanner that crashed, timed out, or sent a report we rejected is not a
//     pass; it's an incomplete scan.
//   - A finding whose severity isn't one of the five known strings forces FAIL. It's counted
//     separately as "unknown" so nobody mistakes it for a real critical.

export const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info'])

export const EXIT = Object.freeze({ PASS: 0, FAIL: 1, ERROR: 2, WARN: 3 })

/**
 * @param {Array<{severity: unknown}>} findings
 * @param {{complete?: boolean}} [opts]  complete: every expected check ran to the end
 * @returns {{verdict: 'pass'|'warn'|'fail'|'incomplete', counts: Record<string, number>, exitCode: number}}
 */
export function computeVerdict(findings, { complete = false } = {}) {
  const counts = Object.fromEntries([...SEVERITIES, 'unknown'].map(s => [s, 0]))
  for (const f of Array.isArray(findings) ? findings : [null]) {
    const sev = f && typeof f === 'object' && typeof f.severity === 'string' ? f.severity : null
    if (sev !== null && SEVERITIES.includes(sev)) counts[sev]++
    else counts.unknown++
  }
  let verdict
  if (counts.critical || counts.high || counts.unknown) verdict = 'fail'
  else if (!complete) verdict = 'incomplete'
  else if (counts.medium) verdict = 'warn'
  else verdict = 'pass'
  const exitCode = { fail: EXIT.FAIL, warn: EXIT.WARN, pass: EXIT.PASS, incomplete: EXIT.ERROR }[verdict]
  return { verdict, counts, exitCode }
}
