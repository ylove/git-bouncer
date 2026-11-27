// Findings collector shared by every check.
//
// Severity policy (the host turns this into a verdict):
//   critical / high -> FAIL   (strong signal that the repo may attack you on install or open)
//   medium          -> WARN   (needs a human look before you trust it)
//   low / info      -> shown, does not block
//
// Every string that came from the scanned repo is truncated here. The host also strips
// terminal control characters before printing, because file names and file contents are
// attacker-controlled.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

const LIMITS = { title: 200, detail: 1500, evidence: 240, file: 400 }
const MAX_FINDINGS = 400
const MAX_PER_RULE = 25

const clip = (s, n) => {
  if (s === undefined || s === null) return null
  const str = String(s)
  return str.length > n ? `${str.slice(0, n - 1)}…` : str
}

export class Findings {
  constructor() {
    this.items = []
    this.perRule = new Map()
    this.dropped = 0
  }

  /**
   * @param {{id: string, severity: string, title: string, detail?: string, file?: string,
   *          line?: number, evidence?: string}} f
   */
  add(f) {
    if (!SEVERITIES.includes(f.severity)) throw new Error(`bad severity ${f.severity} for ${f.id}`)
    const n = (this.perRule.get(f.id) || 0) + 1
    this.perRule.set(f.id, n)
    if (n > MAX_PER_RULE || this.items.length >= MAX_FINDINGS) {
      this.dropped++
      return
    }
    this.items.push({
      id: f.id,
      severity: f.severity,
      title: clip(f.title, LIMITS.title),
      detail: clip(f.detail, LIMITS.detail),
      file: clip(f.file, LIMITS.file),
      line: Number.isInteger(f.line) ? f.line : null,
      evidence: clip(f.evidence, LIMITS.evidence),
    })
  }

  toJSON() {
    const out = [...this.items]
    if (this.dropped) {
      out.push({
        id: 'SCAN-FINDINGS-TRUNCATED', severity: 'info',
        title: `${this.dropped} more findings were not listed`,
        detail: 'Each rule reports at most 25 findings and the report holds at most 400. The verdict already accounts for the listed ones.',
        file: null, line: null, evidence: null,
      })
    }
    return out
  }
}

/** Show a short, single-line excerpt around a match. */
export function excerpt(text, index, length = 80) {
  const start = Math.max(0, index - 20)
  return text.slice(start, start + length).replace(/[\r\n\t]+/g, ' ')
}
