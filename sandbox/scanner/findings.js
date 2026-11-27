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

const rank = sev => SEVERITIES.indexOf(sev) // 0 = critical (worst)

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
    this.droppedWorst = null
  }

  /**
   * @param {{id: string, severity: string, title: string, detail?: string, file?: string,
   *          line?: number, evidence?: string}} f
   */
  add(f) {
    if (!SEVERITIES.includes(f.severity)) throw new Error(`bad severity ${f.severity} for ${f.id}`)
    const item = {
      id: f.id,
      severity: f.severity,
      title: clip(f.title, LIMITS.title),
      detail: clip(f.detail, LIMITS.detail),
      file: clip(f.file, LIMITS.file),
      line: Number.isInteger(f.line) ? f.line : null,
      evidence: clip(f.evidence, LIMITS.evidence),
    }
    const kept = this.perRule.get(f.id) || []
    if (kept.length < MAX_PER_RULE && this.items.length < MAX_FINDINGS) {
      kept.push(item)
      this.perRule.set(f.id, kept)
      this.items.push(item)
      return
    }
    // Over a cap: a more severe finding replaces the least severe one we kept, so a flood of
    // harmless findings can never push a serious one out of the report.
    const pool = kept.length >= MAX_PER_RULE ? kept : this.items
    let weakest = -1
    for (let i = 0; i < pool.length; i++) {
      if (weakest === -1 || rank(pool[i].severity) > rank(pool[weakest].severity)) weakest = i
    }
    let droppedItem = item
    if (weakest !== -1 && rank(item.severity) < rank(pool[weakest].severity)) {
      droppedItem = pool[weakest]
      const idx = this.items.indexOf(droppedItem)
      this.items[idx] = item
      const list = this.perRule.get(droppedItem.id)
      list.splice(list.indexOf(droppedItem), 1)
      kept.push(item)
      this.perRule.set(f.id, kept)
    }
    this.dropped++
    if (this.droppedWorst === null || rank(droppedItem.severity) < rank(this.droppedWorst)) this.droppedWorst = droppedItem.severity
  }

  toJSON() {
    const out = [...this.items]
    if (this.dropped) {
      // The truncation notice carries the worst severity it hid, so the verdict still counts it.
      out.push({
        id: 'SCAN-FINDINGS-TRUNCATED', severity: this.droppedWorst,
        title: `${this.dropped} more findings were not listed`,
        detail: `Each rule reports at most ${MAX_PER_RULE} findings and the report holds at most ${MAX_FINDINGS}. The most severe unlisted one was ${this.droppedWorst}, and this entry carries that severity.`,
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
