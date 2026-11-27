// Read the sandbox's report, and treat it as untrusted data.
//
// The sandbox is where hostile files live. Nothing from the repo runs there, but we still don't
// assume the report is honest or well-formed: it's size-capped, found only between marker lines
// containing a nonce we chose for this run, and checked field by field. Anything unexpected makes
// the scan "incomplete", which can never become a pass (see verdict.js).

import { SEVERITIES } from './verdict.js'

const MAX_REPORT_BYTES = 8 * 1024 * 1024
const MAX_FINDINGS = 500
const ID = /^[A-Z0-9]+(?:-[A-Z0-9]+)*$/
const SHA = /^[0-9a-f]{40}$/
const REQUIRED_PHASES_CLONE = ['clone', 'git', 'content', 'autorun', 'dependencies']

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : null)

/**
 * @param {string} text   everything the sandbox printed on stdout
 * @param {string} nonce  the hex nonce we passed to the scanner
 * @returns {{report: object|null, complete: boolean, problems: string[]}}
 */
export function extractReport(text, nonce) {
  const problems = []
  if (typeof text !== 'string') return { report: null, complete: false, problems: ['no output from the sandbox'] }
  const lines = text.split('\n')
  const begin = lines.indexOf(`-----BEGIN BOUNCER REPORT ${nonce}-----`)
  if (begin === -1) return { report: null, complete: false, problems: ['the sandbox did not produce a report'] }
  if (lines[begin + 2] !== `-----END BOUNCER REPORT ${nonce}-----`) {
    return { report: null, complete: false, problems: ['the sandbox report was malformed (markers out of place)'] }
  }
  if (lines.filter(l => l.includes(nonce)).length !== 2) problems.push('the report markers appeared more than once')
  const raw = lines[begin + 1]
  if (Buffer.byteLength(raw) > MAX_REPORT_BYTES) return { report: null, complete: false, problems: ['the sandbox report was too large'] }
  let data
  try { data = JSON.parse(raw) } catch { return { report: null, complete: false, problems: ['the sandbox report was not valid JSON'] } }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { report: null, complete: false, problems: ['the sandbox report was not an object'] }
  if (data.schema !== 1) problems.push(`unsupported report schema ${JSON.stringify(data.schema)}`)

  const findings = []
  if (!Array.isArray(data.findings)) problems.push('the report had no findings list')
  else {
    if (data.findings.length > MAX_FINDINGS) problems.push('the report listed too many findings')
    for (const f of data.findings.slice(0, MAX_FINDINGS)) {
      if (!f || typeof f !== 'object' || typeof f.id !== 'string' || !ID.test(f.id) || f.id.length > 64) {
        problems.push('a finding was malformed')
        findings.push({ id: 'REPORT-MALFORMED-FINDING', severity: 'high', title: 'The sandbox sent a malformed finding', detail: 'Treated as a failure, because a report we can\'t read is a report we can\'t trust.' })
        continue
      }
      findings.push({
        id: f.id,
        // Unknown severities are kept as-is so computeVerdict() fails closed on them.
        severity: SEVERITIES.includes(f.severity) ? f.severity : String(f.severity).slice(0, 20),
        title: str(f.title, 300) ?? '(no title)',
        detail: str(f.detail, 2000),
        file: str(f.file, 500),
        line: Number.isInteger(f.line) && f.line > 0 ? f.line : null,
        evidence: str(f.evidence, 400),
      })
    }
  }

  const t = data.target && typeof data.target === 'object' ? data.target : {}
  const target = {
    url: str(t.url, 600),
    ref: str(t.ref, 200),
    commit: typeof t.commit === 'string' && SHA.test(t.commit) ? t.commit : null,
    tree: typeof t.tree === 'string' && SHA.test(t.tree) ? t.tree : null,
    defaultBranch: typeof t.defaultBranch === 'string' && /^[A-Za-z0-9._/-]{1,200}$/.test(t.defaultBranch) ? t.defaultBranch : null,
  }
  const pmIn = data.packageManager && typeof data.packageManager === 'object' ? data.packageManager : null
  const packageManager = pmIn ? {
    kind: ['npm', 'yarn', 'pnpm', 'bun', 'none'].includes(pmIn.kind) ? pmIn.kind : 'none',
    lockfile: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'].includes(pmIn.lockfile) ? pmIn.lockfile : null,
    generatedLockfile: pmIn.generatedLockfile === true,
    installed: pmIn.installed === true,
  } : null

  const status = data.status === 'ok' ? 'ok' : 'error'
  const timings = data.timings && typeof data.timings === 'object' ? data.timings : {}
  const missing = REQUIRED_PHASES_CLONE.filter(p => typeof timings[p] !== 'number')
  if (status !== 'ok') problems.push(`the scan did not finish: ${str(data.error, 300) || 'unknown error'}`)
  else if (missing.length) problems.push(`these checks did not run: ${missing.join(', ')}`)
  if (status === 'ok' && !target.commit) problems.push('the report did not say which commit was scanned')

  const report = {
    status,
    error: str(data.error, 400),
    errorDetail: str(data.errorDetail, 400),
    target,
    packageManager,
    findings,
    stats: data.stats && typeof data.stats === 'object' ? { files: Number(data.stats.files) || 0, truncated: data.stats.truncated === true } : null,
    tools: data.tools && typeof data.tools === 'object' ? Object.fromEntries(Object.entries(data.tools).slice(0, 8).map(([k, v]) => [String(k).slice(0, 20), str(v, 80)])) : {},
    scanner: data.scanner && typeof data.scanner === 'object' ? { version: str(data.scanner.version, 40), iocSnapshot: str(data.scanner.iocSnapshot, 20) } : null,
  }
  return { report, complete: problems.length === 0, problems }
}
