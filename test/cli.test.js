import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { parseCommand, validateDir, main } from '../src/cli.js'
import { computeVerdict, EXIT } from '../src/verdict.js'

const bin = name => fileURLToPath(new URL(`../bin/${name}`, import.meta.url))
const runBin = (name, args) => spawnSync(process.execPath, [bin(name), ...args], { encoding: 'utf8' })

const sink = () => { let s = ''; return { write: c => { s += c }, get text() { return s } } }

test('--help and --version work through the real binaries', () => {
  const help = runBin('bouncer.js', ['--help'])
  assert.equal(help.status, 0)
  assert.match(help.stdout, /bouncer clone <url>/)
  const version = runBin('bouncer.js', ['--version'])
  assert.equal(version.status, 0)
  assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+/)
})

test('bad input exits 2 with a plain-language message', () => {
  const r = runBin('bouncer.js', ['clone', 'https://not-a-token@example.com/a/b'])
  assert.equal(r.status, EXIT.ERROR)
  assert.match(r.stderr, /credentials/)
})

test('`git bouncer <url>` means clone, and `git bouncer scan <url>` still works', () => {
  assert.equal(parseCommand(['owner/repo'], { asGitSubcommand: true }).command, 'clone')
  assert.equal(parseCommand(['scan', 'owner/repo'], { asGitSubcommand: true }).command, 'scan')
})

test('an option smuggled in as the URL reaches the URL validator and is refused there', () => {
  const r = runBin('git-bouncer.js', ['--', '--upload-pack=touch x'])
  assert.equal(r.status, EXIT.ERROR)
  assert.match(r.stderr, /looks like an option/)
})

test('the clone folder never defaults to a dot-name chosen by the repo (".git" folder planting)', () => {
  for (const url of ['https://github.com/evil/.vscode', 'https://github.com/evil/.devcontainer', 'https://github.com/evil/.claude']) {
    assert.throws(() => parseCommand(['clone', url]), /folder name you choose/, url)
  }
  assert.equal(parseCommand(['clone', 'https://github.com/evil/.vscode', 'review-me']).dir, 'review-me')
})

test('validateDir refuses .git look-alikes, traversal, absolute and network paths', () => {
  for (const d of ['.git', '.GIT', 'GIT', 'git.', 'Git . .', 'sub/.git', 'a/GIT~1', '..', '../x', '/etc/x', '\\\\attacker\\share', 'C:\\x', '-x', '.', 'a\u202Eb', 'a\u0085b', 'a b', '']) {
    assert.throws(() => validateDir(d), /not allowed/, JSON.stringify(d))
  }
  for (const d of ['repo', 'my-copy', 'work/repo', 'repo.v2', 'repo/']) assert.ok(validateDir(d))
})

test('clone defaults the folder to the repo name', () => {
  assert.equal(parseCommand(['clone', 'owner/repo']).dir, 'repo')
  assert.equal(parseCommand(['clone', 'owner/repo', 'my-copy']).dir, 'my-copy')
})

test('--ref values are checked by the ref validator, including the --ref=... form', () => {
  assert.equal(parseCommand(['scan', 'owner/repo', '--ref', 'v1.2.3']).options.ref, 'v1.2.3')
  assert.throws(() => parseCommand(['scan', 'owner/repo', '--ref=--upload-pack=x']), /not a valid branch or tag/)
  assert.throws(() => parseCommand(['scan', 'owner/repo', '--runtime', 'lxc']), /Unknown runtime/)
})

test('--allow-host is validated and passed to the URL parser', () => {
  assert.equal(parseCommand(['scan', 'https://git.example.org/a/b', '--allow-host', 'git.example.org']).target.host, 'git.example.org')
  assert.throws(() => parseCommand(['scan', 'owner/repo', '--allow-host', 'not a host']), /plain host name/)
})

test('--snyk and --no-snyk together is an error, not a silent choice', () => {
  assert.throws(() => parseCommand(['scan', 'owner/repo', '--snyk', '--no-snyk']), /not both/)
  assert.equal(parseCommand(['scan', 'owner/repo', '--no-snyk']).options.snyk, false)
  assert.equal(parseCommand(['scan', 'owner/repo']).options.snyk, null)
})

test('unknown options and commands are errors, not ignored', async () => {
  const err = sink()
  assert.equal(await main(['clone', 'owner/repo', '--yolo'], { stderr: err, stdout: sink() }), EXIT.ERROR)
  assert.match(err.text, /yolo/)
  assert.equal(await main(['frobnicate'], { stderr: sink(), stdout: sink() }), EXIT.ERROR)
})

test('error messages are sanitized before printing', async () => {
  const err = sink()
  await main(['clone', 'owner/repo', '--ref', 'x\u001B[2Ky'], { stderr: err, stdout: sink() })
  assert.doesNotMatch(err.text, /\u001B/)
})

test('verdict policy: high/critical fail, medium warns, low/info pass, for a complete scan', () => {
  const v = (f) => computeVerdict(f, { complete: true })
  assert.equal(v([]).verdict, 'pass')
  assert.equal(v([{ severity: 'info' }, { severity: 'low' }]).verdict, 'pass')
  assert.equal(v([{ severity: 'medium' }, { severity: 'low' }]).verdict, 'warn')
  assert.equal(v([{ severity: 'medium' }, { severity: 'high' }]).verdict, 'fail')
  assert.equal(v([{ severity: 'critical' }]).exitCode, EXIT.FAIL)
  assert.equal(v([{ severity: 'medium' }]).exitCode, EXIT.WARN)
})

test('verdict policy: an incomplete scan never passes', () => {
  assert.equal(computeVerdict([]).verdict, 'incomplete')
  assert.equal(computeVerdict([]).exitCode, EXIT.ERROR)
  assert.equal(computeVerdict([{ severity: 'medium' }]).verdict, 'incomplete')
  assert.equal(computeVerdict([{ severity: 'high' }]).verdict, 'fail') // bad news still counts
})

test('verdict policy: malformed severities fail closed and are counted as unknown', () => {
  for (const f of [{ severity: 'catastrophic' }, { severity: 'HIGH' }, {}, null, { severity: ['info'] }, { severity: { toString: () => 'low' } }]) {
    const r = computeVerdict([f], { complete: true })
    assert.equal(r.verdict, 'fail', JSON.stringify(f))
    assert.equal(r.counts.unknown, 1)
    assert.equal(r.counts.critical, 0)
  }
  assert.equal(computeVerdict('not an array', { complete: true }).verdict, 'fail')
})
