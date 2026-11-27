import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { parseCommand, main } from '../src/cli.js'
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
  const r = runBin('bouncer.js', ['clone', 'https://token@github.com/a/b'])
  assert.equal(r.status, EXIT.ERROR)
  assert.match(r.stderr, /credentials/)
})

test('`git bouncer <url>` means clone, and `git bouncer scan <url>` still works', () => {
  assert.equal(parseCommand(['owner/repo'], { asGitSubcommand: true }).command, 'clone')
  assert.equal(parseCommand(['scan', 'owner/repo'], { asGitSubcommand: true }).command, 'scan')
  const r = runBin('git-bouncer.js', ['--upload-pack=x'])
  assert.equal(r.status, EXIT.ERROR)
})

test('clone defaults the folder to the repo name and refuses option-like folders', () => {
  assert.equal(parseCommand(['clone', 'owner/repo']).dir, 'repo')
  assert.equal(parseCommand(['clone', 'owner/repo', 'my-copy']).dir, 'my-copy')
  assert.throws(() => parseCommand(['clone', 'owner/repo', '--', '-x']))
})

test('validates --ref and --runtime', () => {
  assert.equal(parseCommand(['scan', 'owner/repo', '--ref', 'v1.2.3']).options.ref, 'v1.2.3')
  assert.throws(() => parseCommand(['scan', 'owner/repo', '--ref', '--upload-pack=x']))
  assert.throws(() => parseCommand(['scan', 'owner/repo', '--runtime', 'lxc']), /Unknown runtime/)
})

test('unknown options and commands are errors, not ignored', async () => {
  const err = sink()
  assert.equal(await main(['clone', 'owner/repo', '--yolo'], { stderr: err, stdout: sink() }), EXIT.ERROR)
  assert.match(err.text, /yolo/)
  assert.equal(await main(['frobnicate'], { stderr: sink(), stdout: sink() }), EXIT.ERROR)
})

test('error messages are sanitized before printing', async () => {
  const err = sink()
  await main(['clone', 'owner/repo', '--ref', 'x\u001b[2Ky'], { stderr: err, stdout: sink() })
  assert.doesNotMatch(err.text, /\u001b/)
})

test('verdict policy: high/critical fail, medium warns, low/info pass', () => {
  assert.equal(computeVerdict([]).verdict, 'pass')
  assert.equal(computeVerdict([{ severity: 'info' }, { severity: 'low' }]).verdict, 'pass')
  assert.equal(computeVerdict([{ severity: 'medium' }, { severity: 'low' }]).verdict, 'warn')
  assert.equal(computeVerdict([{ severity: 'medium' }, { severity: 'high' }]).verdict, 'fail')
  assert.equal(computeVerdict([{ severity: 'critical' }]).exitCode, EXIT.FAIL)
  assert.equal(computeVerdict([{ severity: 'medium' }]).exitCode, EXIT.WARN)
})

test('verdict policy: an unknown severity counts as critical, never silently passes', () => {
  assert.equal(computeVerdict([{ severity: 'catastrophic' }]).verdict, 'fail')
  assert.equal(computeVerdict([{}]).verdict, 'fail')
})
