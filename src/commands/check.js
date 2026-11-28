// `bouncer scan` and `bouncer clone`: ID check -> sandbox pat-down -> verdict -> (clone) handoff.

import { randomBytes } from 'node:crypto'
import { rm } from 'node:fs/promises'
import { detectContainerRuntime, createContainerRuntime, SANDBOX_DIR } from '../runtimes/container.js'
import { createGcpRuntime } from '../runtimes/gcp.js'
import { createAwsRuntime } from '../runtimes/aws.js'
import { offerInstall } from '../runtimes/install-offer.js'
import { extractReport } from '../report.js'
import { computeVerdict, EXIT } from '../verdict.js'
import { handoff, HandoffError } from '../handoff.js'
import { idCheck as realIdCheck } from '../idcheck/index.js'
import { snykReady, snykTest } from '../snyk.js'
import { clean } from '../ui/sanitize.js'
import { has } from '../proc.js'

// Findings that mean "a check didn't run to the end". The result is then INCOMPLETE, not a WARN.
const COVERAGE_GAPS = new Set(['SCAN-TRUNCATED', 'SCAN-INCOMPLETE', 'DEP-OSV-UNAVAILABLE', 'DEP-OSV-PARTIAL', 'DEP-INSTALL-FAILED',
  'DEP-INSTALL-SKIPPED', 'LOCK-OUT-OF-SYNC', 'LOCK-UNPARSABLE', 'DEP-SIGNATURES-UNCHECKED', 'ID-API-UNAVAILABLE', 'ID-IOC-UNAVAILABLE'])

/** The ID check (src/idcheck): look-alikes, known-bad repos and reputation, before anything downloads. */
async function runIdCheck(target, deps) {
  try {
    const r = await (deps.idCheck ?? realIdCheck)(target)
    return { findings: r.findings ?? [], facts: r.facts ?? {}, complete: r.complete === true }
  } catch (e) {
    // Never let an ID-check bug turn into a pass: report it as an incomplete check.
    return { findings: [{ id: 'ID-API-UNAVAILABLE', severity: 'low', title: 'The ID check could not run', detail: String(e && e.message ? e.message : e).slice(0, 300) }], facts: {}, complete: false }
  }
}

/** One line about the publisher, from public GitHub metadata (all values are re-sanitized on print). */
function describePublisher(facts) {
  const parts = []
  if (facts.ownerType) parts.push(facts.ownerType === 'Organization' ? 'organization' : 'personal account')
  if (facts.ownerCreatedAt) parts.push(`since ${String(facts.ownerCreatedAt).slice(0, 10)}`)
  // "Verified" is GitHub's domain verification. The website field itself is free text the owner typed,
  // so it is not repeated here as if it were verified.
  if (facts.verifiedOrg) parts.push('organization with a GitHub-verified domain')
  if (Number.isFinite(facts.stars)) parts.push(`${facts.stars} stars`)
  if (facts.latestRelease) parts.push(`latest release ${facts.latestRelease}`)
  return parts.join(', ')
}

const CLOUD = { gcp: createGcpRuntime, aws: createAwsRuntime }

async function pickRuntime(options, deps) {
  if (deps.runtime) return { runtime: deps.runtime, reasons: [] }
  const explicit = options.runtime
  if (explicit === 'docker' || explicit === 'podman') {
    const rt = createContainerRuntime(explicit, { onLog: deps.onLog })
    const a = await rt.available()
    return a.ok ? { runtime: rt, reasons: [] } : { runtime: null, reasons: [a.reason] }
  }
  if (CLOUD[explicit]) {
    const rt = CLOUD[explicit]({ onLog: deps.onLog })
    const a = await rt.available()
    return a.ok ? { runtime: rt, reasons: [] } : { runtime: null, reasons: [`${explicit}: ${a.reason}`] }
  }
  if (explicit) return { runtime: null, reasons: [`the ${explicit} runtime is not available in this version yet`] }
  const local = await detectContainerRuntime({ onLog: deps.onLog })
  if (local.runtime) return local
  // No local engine. A signed-in cloud CLI is offered next, but only with a yes (it costs money).
  for (const [name, make] of Object.entries(CLOUD)) {
    const rt = make({ onLog: deps.onLog })
    const a = await rt.available().catch(() => ({ ok: false }))
    if (a.ok && await deps.prompter.confirm(`No Docker or Podman here, but you're signed in to ${name === 'gcp' ? 'Google Cloud' : 'AWS'}. Run the check there instead? It runs a build in your account, which may cost money.`, { defaultYes: false, safeAnswer: false })) {
      return { runtime: rt, reasons: [] }
    }
  }
  return local
}

/** Print exactly what a cloud runtime would run, without running anything. */
async function printPlan(runtime, target, options, stdout) {
  const p = await runtime.plan({ url: target.url, ref: options.ref, nonce: '0'.repeat(32), sandboxDir: SANDBOX_DIR })
  stdout.write(`${JSON.stringify({ runtime: runtime.name, steps: p.steps, files: p.files, notes: p.notes }, null, 2)}\n`)
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
    const who = describePublisher(id.facts)
    if (who) out.note(clean(who, { max: 200 }))
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
    // A dry run only prints the cloud plan: it works before the cloud setup exists, so you can see what it needs.
    if (options.dryRun) {
      if (!CLOUD[options.runtime]) { out.note('--dry-run only applies to --runtime gcp or aws.'); return EXIT.ERROR }
      await printPlan(CLOUD[options.runtime]({}), target, options, stdout)
      const a = await CLOUD[options.runtime]({}).available().catch(e => ({ ok: false, reason: e.message }))
      if (!a.ok) out.note(`Not runnable yet: ${a.reason}`)
      out.note('Dry run: nothing was checked, so this exits 2, never 0.')
      return EXIT.ERROR
    }
    out.step('Pat-down: cloning into a throwaway sandbox with none of your credentials')
    const picked = await pickRuntime(options, { ...deps, onLog: s => out.progress(s) })
    runtime = picked.runtime
    if (!runtime) {
      out.note(`No sandbox runtime is available: ${picked.reasons.map(r => String(r).replace(/[.\s]+$/, '')).join('; ')}.`)
      if (!options.runtime) {
        const offer = await offerInstall({
          interactive: prompter.interactive,
          confirm: (q, o) => prompter.confirm(q, o),
          choose: prompter.choose ? (q, opts) => prompter.choose(q, opts) : undefined,
          out: s => out.line(s),
        })
        for (const step of offer.nextSteps || []) out.note(step)
        if (offer.installed) out.note('Installed. Run the same bouncer command again to check the repo.')
      }
      return EXIT.ERROR
    }

    out.note(`using ${runtime.describe()}`)
    if (runtime.sweepStale) await runtime.sweepStale().catch(() => 0)
    const image = runtime.ensureImage ? await runtime.ensureImage(version) : null
    const nonce = randomBytes(16).toString('hex')
    let result
    try {
      // onSession hands us the sandbox's name before it starts, so an interrupt can always remove it.
      result = await runtime.scan({ url: target.url, ref: options.ref, nonce, image, sandboxDir: SANDBOX_DIR, onSession: s => { session = s } })
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
      // A cloud build is already gone when it finishes; only a local sandbox can be kept to look around.
      const del = CLOUD[runtime.name] ? true : await prompter.confirm('Delete the sandbox and everything in it?', { defaultYes: true, safeAnswer: true })
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
