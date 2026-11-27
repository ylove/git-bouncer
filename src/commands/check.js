// `bouncer scan` and `bouncer clone`: ID check -> sandbox pat-down -> verdict -> (clone) handoff.

import { randomBytes } from 'node:crypto'
import { rm } from 'node:fs/promises'
import { detectContainerRuntime, createContainerRuntime } from '../runtimes/container.js'
import { extractReport } from '../report.js'
import { computeVerdict, EXIT } from '../verdict.js'
import { handoff, HandoffError } from '../handoff.js'
import { snykReady, snykTest } from '../snyk.js'
import { clean } from '../ui/sanitize.js'
import { has } from '../proc.js'

// Findings that mean "a check didn't run to the end". The result is then INCOMPLETE, not a WARN.
const COVERAGE_GAPS = new Set(['SCAN-TRUNCATED', 'SCAN-INCOMPLETE', 'DEP-OSV-UNAVAILABLE', 'DEP-OSV-PARTIAL', 'DEP-INSTALL-FAILED',
  'DEP-INSTALL-SKIPPED', 'LOCK-OUT-OF-SYNC', 'LOCK-UNPARSABLE', 'DEP-SIGNATURES-UNCHECKED'])

/** Placeholder until the ID check (#2) is wired in: offline checks only. */
async function runIdCheck(target, deps) {
  if (deps.idCheck) return deps.idCheck(target)
  return { findings: [], facts: {}, complete: true }
}

async function pickRuntime(options, deps) {
  if (deps.runtime) return { runtime: deps.runtime, reasons: [] }
  if (options.runtime === 'docker' || options.runtime === 'podman') {
    const rt = createContainerRuntime(options.runtime, { onLog: deps.onLog })
    const a = await rt.available()
    return a.ok ? { runtime: rt, reasons: [] } : { runtime: null, reasons: [a.reason] }
  }
  if (options.runtime) return { runtime: null, reasons: [`the ${options.runtime} runtime is not available in this version yet`] }
  return detectContainerRuntime({ onLog: deps.onLog })
}

/**
 * @param {{command: 'scan'|'clone', target: object, dir: string|null, options: object}} cmd
 * @param {{out: object, prompter: object, stdout: object, version: string, idCheck?: Function, runtime?: object}} deps
 */
export async function check(cmd, deps) {
  const { out, prompter, stdout, version } = deps
  const { target, options } = cmd
  const json = options.json
  const all = []
  let session = null
  let runtime = null
  let keep = options.keep
  let halfCloned = null // a destination folder the handoff is still filling in
  const cleanup = async () => { if (session && runtime && !keep) { await runtime.destroy(session).catch(() => {}); session = null } }
  const onSignal = async signal => {
    out.line(); out.note(`Interrupted (${signal}): removing the sandbox${halfCloned ? ' and the unfinished clone' : ''}...`)
    keep = false
    await cleanup()
    if (halfCloned) await rm(halfCloned, { recursive: true, force: true }).catch(() => {})
    process.exit(signal === 'SIGINT' ? 130 : 143)
  }
  const signals = ['SIGINT', 'SIGTERM', 'SIGHUP']
  for (const s of signals) process.once(s, onSignal)

  try {
    out.line(`${out.c.bold('git-bouncer')} ${out.c.dim(version)}  checking ${clean(target.display)}${options.ref ? ` @ ${clean(options.ref)}` : ''}`)
    out.line()

    // 1. ID check, on this machine, before anything is downloaded.
    out.step('ID check: who published this, and is it who it claims to be?')
    const id = await runIdCheck({ ...target, ref: options.ref }, deps)
    all.push(...id.findings)
    if (id.findings.length) out.findings(id.findings)
    else out.note('no problems with the publisher found')
    const early = computeVerdict(id.findings, { complete: true })
    if (early.verdict === 'fail') {
      out.verdict('fail', early.counts)
      out.note('Turned away at the door: nothing was downloaded.')
      if (json) stdout.write(`${JSON.stringify({ verdict: 'fail', stage: 'id-check', target: target.display, findings: id.findings })}\n`)
      return EXIT.FAIL
    }

    // 2. Pat-down in the sandbox.
    out.line()
    out.step('Pat-down: cloning into a throwaway sandbox with none of your credentials')
    const picked = await pickRuntime(options, { ...deps, onLog: s => out.progress(s) })
    runtime = picked.runtime
    if (!runtime) {
      out.note(`No sandbox runtime is available: ${picked.reasons.join('; ')}.`)
      out.note('Install Podman (free, open source, no account) or Docker, then run this again. `bouncer doctor` shows what was found.')
      return EXIT.ERROR
    }
    out.note(`using ${runtime.describe()}`)
    if (runtime.sweepStale) await runtime.sweepStale().catch(() => 0)
    const image = runtime.ensureImage ? await runtime.ensureImage(version) : null
    const nonce = randomBytes(16).toString('hex')
    let result
    try {
      // onSession hands us the sandbox's name before it starts, so an interrupt can always remove it.
      result = await runtime.scan({ url: target.url, ref: options.ref, nonce, image, onSession: s => { session = s } })
    } catch (e) {
      session = e.session ?? session
      throw e
    }
    session = result.session
    const { report, complete, problems } = extractReport(result.reportText, nonce)
    if (report) all.push(...report.findings)
    for (const p of problems) {
      all.push({ id: 'SCAN-INCOMPLETE', severity: 'medium', title: 'The pat-down did not complete', detail: p })
    }
    if (report && report.status === 'error') {
      out.note(`The sandbox could not check this repo: ${clean(report.error)}${report.errorDetail ? ` (${clean(report.errorDetail, { max: 200 })})` : ''}`)
    }

    // 3. Optional Snyk, on copies of the manifests only (the token never enters the sandbox).
    if (report && report.status === 'ok' && options.snyk !== false && await has('snyk') && await snykReady()) {
      const wanted = options.snyk === true || await prompter.confirm('Snyk is set up here. Also run `snyk test` on the dependency manifests? (It counts toward your Snyk plan\'s monthly test limit.)', { defaultYes: false })
      if (wanted) {
        out.step('Snyk: testing copies of the manifest and lockfile (your token stays on this machine)')
        const s = await snykTest({ runtime, session, packageManager: report.packageManager })
        all.push(...s.findings)
        if (s.note) out.note(s.note)
      }
    }

    const sandboxFindings = all.filter(f => !id.findings.includes(f))
    if (sandboxFindings.length) out.findings(sandboxFindings)
    else out.note('nothing suspicious found')
    const gaps = all.filter(f => COVERAGE_GAPS.has(f.id))
    const v = computeVerdict(all, { complete: complete && id.complete !== false && gaps.length === 0 })
    out.verdict(v.verdict, v.counts)
    if (report?.target?.commit) out.note(`scanned commit ${report.target.commit} (${report.stats?.files ?? '?'} files)`)

    if (json) {
      stdout.write(`${JSON.stringify({ verdict: v.verdict, counts: v.counts, target: target.display, commit: report?.target?.commit ?? null, problems, findings: all })}\n`)
      return v.exitCode
    }
    if (cmd.command === 'scan') return v.exitCode

    // 4. Clone: ask before anything touches this machine.
    out.line()
    if (v.verdict === 'incomplete' && report && report.status === 'ok' && !v.counts.critical && !v.counts.high) {
      out.note(`Some checks couldn't finish (${gaps.map(g => g.id).join(', ') || 'see above'}). Nothing bad was found, but this is not a clean result.`)
    }
    if (v.verdict === 'fail' || (v.verdict === 'incomplete' && !(report && report.status === 'ok'))) {
      const del = await prompter.confirm('Delete the sandbox and everything in it?', { defaultYes: true, safeAnswer: true })
      if (!del) {
        keep = true
        out.note(`Kept. Look around with: ${runtime.name} exec -it ${session.name} sh   (then: ${runtime.name} rm -f ${session.name})`)
      }
      return v.exitCode
    }
    const ok = await prompter.confirm(
      v.verdict === 'pass'
        ? `Let it in? Clone to ./${cmd.dir}${options.install ? ' and install dependencies' : ''}`
        : `Let it in anyway? Clone to ./${cmd.dir}${options.install ? ' and install dependencies' : ''}`,
      { defaultYes: v.verdict === 'pass', safeAnswer: false })
    if (!ok) { out.note('Not cloned. The sandbox will be removed.'); return v.exitCode }
    try {
      const h = await handoff({ target: { ...target, ref: options.ref }, report, findings: all, dir: cmd.dir, install: options.install, runtime, session, prompter, out, onCreated: d => { halfCloned = d } })
      out.line()
      out.line(`${out.c.green('✔')} ${h.installed ? 'Cloned and installed' : 'Cloned'} into ./${cmd.dir}${h.ignoreScripts ? ' (install scripts were not run)' : ''}`)
    } catch (e) {
      if (e instanceof HandoffError) { out.line(`${out.c.red('✖')} ${clean(e.message)}`); return EXIT.ERROR }
      throw e
    }
    return v.exitCode
  } finally {
    for (const s of signals) process.removeListener(s, onSignal)
    await cleanup()
    if (session && keep && runtime && !json) out.note(`Sandbox kept: ${session.name}`)
  }
}
