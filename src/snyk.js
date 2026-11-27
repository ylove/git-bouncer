// Optional Snyk check, for people who already use Snyk.
//
// The Snyk CLI needs your Snyk token. A token must never enter the sandbox, because the sandbox is
// where the untrusted files are. So Snyk runs here on the host, but only against COPIES of the
// dependency manifests and lockfile, taken out of the sandbox into a private temp folder. Snyk's
// open-source test reads those files as data; no code from the repo is on this machine, and none runs.

import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { run } from './proc.js'

const MANIFESTS = {
  npm: ['package.json', 'package-lock.json', 'npm-shrinkwrap.json'],
  yarn: ['package.json', 'yarn.lock'],
  pnpm: ['package.json', 'pnpm-lock.yaml'],
}

/** Is the Snyk CLI installed and signed in? (`snyk whoami` doesn't use test quota.) */
export async function snykReady() {
  const r = await run('snyk', ['whoami', '--experimental'], { timeoutMs: 20_000 })
  return r.code === 0
}

/** @returns {Promise<{ran: boolean, findings: object[], note?: string}>} */
export async function snykTest({ runtime, session, packageManager }) {
  const files = MANIFESTS[packageManager?.kind]
  if (!files) return { ran: false, findings: [], note: 'Snyk was skipped: no npm, yarn or pnpm project found.' }
  const dir = await mkdtemp(path.join(tmpdir(), 'git-bouncer-snyk-')) // created 0700 by Node
  try {
    let copied = 0
    for (const f of files) {
      const text = await runtime.readFile(session, f, 50 * 1024 * 1024)
      if (text !== null) { await writeFile(path.join(dir, f), text, { mode: 0o600 }); copied++ }
    }
    if (copied < 2) return { ran: false, findings: [], note: 'Snyk was skipped: manifest or lockfile missing.' }
    const r = await run('snyk', ['test', '--json'], { cwd: dir, timeoutMs: 10 * 60_000 })
    let data
    try { data = JSON.parse(r.stdout) } catch { data = null }
    if (!data || (r.code !== 0 && r.code !== 1)) {
      return { ran: false, findings: [{ id: 'SNYK-UNAVAILABLE', severity: 'low', title: 'Snyk could not complete', detail: String(data?.error || r.stderr || '').slice(0, 300) }] }
    }
    const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : []
    const findings = []
    const malicious = vulns.filter(v => /malicious/i.test(String(v.title)))
    for (const v of malicious.slice(0, 25)) {
      findings.push({ id: 'SNYK-MALWARE', severity: 'critical', title: `Snyk: malicious package ${v.packageName}@${v.version}`, evidence: String(v.id).slice(0, 80),
        detail: 'Snyk\'s database marks this package version as malicious.' })
    }
    const ordinary = vulns.filter(v => !/malicious/i.test(String(v.title)))
    if (ordinary.length) {
      const high = ordinary.filter(v => ['critical', 'high'].includes(v.severity)).length
      findings.push({ id: 'SNYK-VULN', severity: 'medium', title: `Snyk: ${ordinary.length} known vulnerabilit${ordinary.length === 1 ? 'y' : 'ies'} (${high} critical/high)`,
        evidence: [...new Set(ordinary.map(v => `${v.packageName}@${v.version}`))].slice(0, 5).join(', '),
        detail: 'Ordinary security bugs in dependencies (not malware). Worth fixing before you build on this code.' })
    }
    return { ran: true, findings }
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}
