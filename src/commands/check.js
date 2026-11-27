// `bouncer scan` and `bouncer clone`: ID check -> sandbox pat-down -> verdict -> (clone) handoff.

import { randomBytes } from 'node:crypto'
import { detectContainerRuntime, createContainerRuntime } from '../runtimes/container.js'
import { extractReport } from '../report.js'
import { computeVerdict, EXIT } from '../verdict.js'
import { handoff, HandoffError } from '../handoff.js'
import { snykReady, snykTest } from '../snyk.js'
import { clean } from '../ui/sanitize.js'
import { has } from '../proc.js'

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
  const cleanup = async () => { if (session && runtime && !keep) { await runtime.destroy(session).catch(() => {}); session = null } }
  const onSigint = async () => { out.line(); out.note('Interrupted: removing the sandbox...'); keep = false; await cleanup(); process.exit(130) }
  process.once('SIGINT', onSigint)

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
    const image = runtime.ensureImage ? await runtime.ensureImage(version) : null
    const nonce = randomBytes(16).toString('hex')
    const result = await runtime.scan({ url: target.url, ref: options.ref, nonce, image })
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
    const v = computeVerdict(all, { complete: complete && id.complete !== false })
    out.verdict(v.verdict, v.counts)
    if (report?.target?.commit) out.note(`scanned commit ${report.target.commit} (${report.stats?.files ?? '?'} files)`)

    if (json) {
      stdout.write(`${JSON.stringify({ verdict: v.verdict, counts: v.counts, target: target.display, commit: report?.target?.commit ?? null, problems, findings: all })}\n`)
      return v.exitCode
    }
    if (cmd.command === 'scan') return v.exitCode

    // 4. Clone: ask before anything touches this machine.
    out.line()
    if (v.verdict === 'fail' || v.verdict === 'incomplete') {
      const del = await prompter.confirm('Delete the sandbox and everything in it?', { defaultYes: true, safeAnswer: true })
      if (!del) {
        keep = true
        out.note(`Kept. Look around with: ${runtime.name} exec -it ${session.name} sh   (then: ${runtime.name} rm -f ${session.name})`)
      }
      return v.exitCode
    }
    const ok = await prompter.confirm(
      v.verdict === 'warn'
        ? `Let it in anyway? Clone to ./${cmd.dir}${options.install ? ' and install dependencies' : ''}`
        : `Let it in? Clone to ./${cmd.dir}${options.install ? ' and install dependencies' : ''}`,
      { defaultYes: v.verdict === 'pass', safeAnswer: false })
    if (!ok) { out.note('Not cloned. The sandbox will be removed.'); return v.exitCode }
    try {
      const h = await handoff({ target: { ...target, ref: options.ref }, report, findings: all, dir: cmd.dir, install: options.install, runtime, session, prompter, out })
      out.line()
      out.line(`${out.c.green('✔')} ${h.installed ? 'Cloned and installed' : 'Cloned'} into ./${cmd.dir}${h.ignoreScripts ? ' (install scripts were not run)' : ''}`)
    } catch (e) {
      if (e instanceof HandoffError) { out.line(`${out.c.red('✖')} ${clean(e.message)}`); return EXIT.ERROR }
      throw e
    }
    return v.exitCode
  } finally {
    process.removeListener('SIGINT', onSigint)
    await cleanup()
    if (session && keep && runtime && !json) out.note(`Sandbox kept: ${session.name}`)
  }
}
