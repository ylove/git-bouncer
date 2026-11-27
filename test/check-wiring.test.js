// How the ID check feeds the verdict. No network, no container: both are replaced with stubs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { main } from '../src/cli.js'
import { EXIT } from '../src/verdict.js'

const sink = () => ({ text: '', write(s) { this.text += s } })
const neverUsedRuntime = {
  name: 'stub', describe: () => 'stub',
  available: async () => ({ ok: true }),
  scan: async () => { throw new Error('the sandbox must not start') },
  readFile: async () => null, destroy: async () => {},
}
const run = (args, deps) => { const out = sink(); const err = sink(); return main(args, { stdout: out, stderr: err, prompter: { interactive: false, confirm: async () => false }, ...deps }).then(code => ({ code, out: out.text, err: err.text })) }

test('a high ID-check finding turns the repo away before any sandbox starts', async () => {
  const idCheck = async () => ({ findings: [{ id: 'ID-LOOKALIKE-OWNER', severity: 'high', title: 'looks like microsoft' }], facts: {}, complete: true })
  const r = await run(['scan', 'github.com/micr0s0ft/vscode', '--no-snyk'], { idCheck, runtime: neverUsedRuntime })
  assert.equal(r.code, EXIT.FAIL)
  assert.match(r.err, /nothing was downloaded/)
})

test('an ID check that crashes is incomplete, never a pass', async () => {
  const idCheck = async () => { throw new Error('boom') }
  const runtime = { ...neverUsedRuntime, scan: async ({ nonce }) => ({ reportText: frame(nonce), session: { name: 'x' } }) }
  const r = await run(['scan', 'owner/repo', '--no-snyk'], { idCheck, runtime })
  assert.equal(r.code, EXIT.ERROR)
})

test('GitHub unreachable (rate limit, offline) makes the verdict incomplete even if the pat-down is clean', async () => {
  const idCheck = async () => ({ findings: [{ id: 'ID-API-UNAVAILABLE', severity: 'low', title: 'rate limited' }], facts: {}, complete: false })
  const runtime = { ...neverUsedRuntime, scan: async ({ nonce }) => ({ reportText: frame(nonce), session: { name: 'x' } }) }
  const r = await run(['scan', 'owner/repo', '--no-snyk', '--json'], { idCheck, runtime })
  assert.equal(JSON.parse(r.out.trim()).verdict, 'incomplete')
  assert.equal(r.code, EXIT.ERROR)
})

test('a clean ID check and a clean pat-down let the repo in', async () => {
  const idCheck = async () => ({ findings: [], facts: { ownerType: 'Organization' }, complete: true })
  const runtime = { ...neverUsedRuntime, scan: async ({ nonce }) => ({ reportText: frame(nonce), session: { name: 'x' } }) }
  const r = await run(['scan', 'owner/repo', '--no-snyk', '--json'], { idCheck, runtime })
  assert.equal(JSON.parse(r.out.trim()).verdict, 'pass')
  assert.equal(r.code, EXIT.PASS)
})

function frame(nonce) {
  const report = { schema: 1, status: 'ok', target: { url: 'https://github.com/owner/repo.git', commit: 'a'.repeat(40), tree: 'b'.repeat(40) },
    packageManager: { kind: 'none' }, timings: { clone: 1, git: 1, content: 1, autorun: 1, dependencies: 1 }, findings: [] }
  return `-----BEGIN BOUNCER REPORT ${nonce}-----\n${JSON.stringify(report)}\n-----END BOUNCER REPORT ${nonce}-----\n`
}

test('--dry-run prints the cloud plan as JSON and runs nothing', async () => {
  const idCheck = async () => ({ findings: [], facts: {}, complete: true })
  const r = await run(['scan', 'owner/repo', '--runtime', 'gcp', '--dry-run', '--no-snyk'], { idCheck })
  assert.equal(r.code, EXIT.PASS)
  const plan = JSON.parse(r.out)
  assert.equal(plan.runtime, 'gcp')
  assert.ok(plan.steps.length > 0 && plan.steps.every(s => typeof s.cmd === 'string' && Array.isArray(s.args)))
})

test('--dry-run without a cloud runtime is a usage error', async () => {
  const idCheck = async () => ({ findings: [], facts: {}, complete: true })
  const r = await run(['scan', 'owner/repo', '--dry-run', '--no-snyk'], { idCheck })
  assert.equal(r.code, EXIT.ERROR)
})

test('`bouncer shell-init bash` prints a snippet that never calls git for --bouncer', async () => {
  const r = await run(['shell-init', 'bash'], {})
  assert.equal(r.code, EXIT.PASS)
  assert.match(r.out, /git-bouncer clone/)
})
