import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { shQuote, scanCommand, setupScript, createArgs, createCodespaceRuntime, OSV, DEVCONTAINER } from '../src/runtimes/codespace.js'

test('shQuote makes any value a single inert shell word', () => {
  assert.equal(shQuote("it's"), "'it'\\''s'")
  if (process.platform !== 'win32') {
    for (const v of ['$(touch /tmp/x)', '`id`', 'a b', "'; rm -rf ~; '", '\\n', '$HOME']) {
      assert.equal(execFileSync('sh', ['-c', `printf %s ${shQuote(v)}`], { encoding: 'utf8' }), v)
    }
  }
})

test('the scan command removes tokens and quotes every input', () => {
  const cmd = scanCommand({ url: 'https://github.com/a/b.git', ref: 'v1.0.0', nonce: 'f'.repeat(32) })
  for (const t of ['GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_CODESPACE_TOKEN']) assert.ok(cmd.includes(`-u ${t}`), t)
  assert.ok(cmd.includes("--url 'https://github.com/a/b.git'"))
  assert.ok(cmd.includes("--ref 'v1.0.0'"))
  assert.ok(cmd.includes('--osv-config "$HOME/bouncer/osv-scanner.toml"'))
})

test('the Codespace is created from git-bouncer itself with the pinned sandbox devcontainer', () => {
  const args = createArgs()
  assert.equal(args[args.indexOf('--repo') + 1], 'ylove/git-bouncer')
  assert.equal(args[args.indexOf('--devcontainer-path') + 1], DEVCONTAINER)
  assert.ok(args.includes('--retention-period') && args.includes('--idle-timeout'))
})

test('the sandbox devcontainer has a pinned image and no lifecycle commands', async () => {
  const text = await readFile(new URL(`../${DEVCONTAINER}`, import.meta.url), 'utf8')
  const conf = JSON.parse(text.replace(/^\s*\/\/.*$/gm, ''))
  assert.match(conf.image, /@sha256:[0-9a-f]{64}$/)
  for (const k of ['initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand', 'features', 'mounts', 'runArgs']) {
    assert.equal(conf[k], undefined, k)
  }
})

test('osv-scanner pins match the Dockerfile', async () => {
  const df = await readFile(new URL('../sandbox/Dockerfile', import.meta.url), 'utf8')
  assert.ok(df.includes(`OSV_VERSION=${OSV.version}`))
  assert.ok(df.includes(`OSV_SHA256_amd64=${OSV.sha256.amd64}`))
  assert.ok(df.includes(`OSV_SHA256_arm64=${OSV.sha256.arm64}`))
  assert.ok(setupScript().includes(OSV.sha256.amd64) && setupScript().includes('sha256sum -c'))
})

test('available() explains exactly what is missing', async () => {
  const fake = responses => async (cmd, args) => responses[args.slice(0, 2).join(' ')] ?? { code: 0, stdout: '', stderr: '' }
  const noScope = createCodespaceRuntime({ exec: fake({ 'api user/codespaces?per_page=1': { code: 1, stdout: '', stderr: 'This API operation needs the "codespace" scope.' } }) })
  assert.match((await noScope.available()).reason, /gh auth refresh -h github\.com -s codespace/)
  const notInstalled = createCodespaceRuntime({ exec: async () => ({ code: -1, stdout: '', stderr: '', error: Object.assign(new Error('x'), { code: 'ENOENT' }) }) })
  assert.match((await notInstalled.available()).reason, /not installed/)
  assert.equal((await createCodespaceRuntime({ exec: fake({}) }).available()).ok, true)
})

test('a failed setup still reports the Codespace so it gets deleted', async () => {
  const calls = []
  const exec = async (cmd, args) => {
    calls.push(args.slice(0, 2).join(' '))
    if (args[1] === 'create') return { code: 0, stdout: 'crispy-space-xyz\n', stderr: '' }
    if (args[1] === 'ssh') return { code: 1, stdout: '', stderr: 'boom' }
    return { code: 0, stdout: '', stderr: '' }
  }
  const rt = createCodespaceRuntime({ exec })
  await assert.rejects(rt.scan({ url: 'https://github.com/a/b.git', nonce: 'f'.repeat(32) }), e => e.session?.name === 'crispy-space-xyz')
  await rt.destroy({ name: 'crispy-space-xyz' })
  assert.ok(calls.includes('codespace delete'))
})
