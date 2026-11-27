import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { createGitHubApi, API_PATH, GitHubApiError } from '../src/idcheck/github-api.js'

// No test here touches the network or runs the real gh: both spawn and fetch are fakes.

/** A fake child_process.spawn. `answer(args)` returns {code, stdout} | {error} | {hang: true}. */
function fakeSpawn(answer) {
  const calls = []
  const spawn = (cmd, args, opts) => {
    calls.push({ cmd, args, opts })
    const child = new EventEmitter()
    child.stdout = opts.stdio[1] === 'pipe' ? new PassThrough() : null
    child.killed = false
    child.kill = () => { child.killed = true; return true }
    const a = answer(args)
    setImmediate(() => {
      if (a.error) {
        child.emit('error', Object.assign(new Error('spawn gh ENOENT'), { code: a.error }))
        child.emit('close', -2)
      } else if (!a.hang) {
        if (child.stdout) child.stdout.end(a.stdout ?? '')
        setImmediate(() => child.emit('close', a.code ?? 0))
      }
    })
    calls[calls.length - 1].child = child
    return child
  }
  return { spawn, calls }
}

const signedIn = args => (args[0] === 'auth' ? { code: 0 } : null)
const notSignedIn = args => (args[0] === 'auth' ? { code: 1 } : null)
const ghMissing = () => ({ error: 'ENOENT' })

const ghOutput = (status, body, reason = 'OK') =>
  `HTTP/2.0 ${status} ${reason}\nContent-Type: application/json; charset=utf-8\r\nX-Ratelimit-Remaining: 4999\r\n\r\n${typeof body === 'string' ? body : JSON.stringify(body)}`

function fakeFetch(respond) {
  const calls = []
  const fetch = async (url, init) => {
    calls.push({ url, init })
    return respond(url, init)
  }
  return { fetch, calls }
}
const noFetch = fakeFetch(() => { throw new Error('fetch should not be called') })

test('only a few exact, read-only API paths are allowed', () => {
  for (const ok of ['/repos/microsoft/vscode', '/repos/vercel/next.js', '/repos/a/.github', '/repos/a-b/c_d',
    '/repos/microsoft/vscode/releases/latest', '/users/torvalds', '/orgs/vercel']) {
    assert.match(ok, API_PATH, ok)
  }
  for (const bad of ['/repos/a/b/contents/README.md', '/repos/a/..', '/repos/a/../releases/latest', '/repos/a/.',
    '/repos/{owner}/{repo}', '/user', '/graphql', 'repos/a/b', 'https://api.github.com/repos/a/b', '/repos/a/b?per_page=100',
    '/repos/-a/b', '/users/a b', '/repos/a/b\n', '/repos/a/b/', '/orgs/a/../../user', '/users/a--b', '/repos/a/b#x']) {
    assert.doesNotMatch(bad, API_PATH, bad)
  }
})

test('an unexpected path is refused before gh or fetch is ever called', async () => {
  const gh = fakeSpawn(() => { throw new Error('spawn should not be called') })
  const api = createGitHubApi({ spawn: gh.spawn, fetch: noFetch.fetch })
  for (const bad of ['/repos/{owner}/{repo}', '/user', '--paginate', '/repos/a/b; rm -rf ~', 42, undefined]) {
    await assert.rejects(api(bad), GitHubApiError)
  }
  assert.equal(gh.calls.length, 0)
})

test('signed in to gh: uses "gh api" with an argument array, and the path after "--"', async () => {
  const gh = fakeSpawn(args => signedIn(args) ?? { code: 0, stdout: ghOutput(200, { full_name: 'microsoft/vscode' }) })
  const api = createGitHubApi({ spawn: gh.spawn, fetch: noFetch.fetch })
  assert.deepEqual(await api('/repos/microsoft/vscode'), { status: 200, json: { full_name: 'microsoft/vscode' } })
  assert.deepEqual(await api('/users/microsoft'), { status: 200, json: { full_name: 'microsoft/vscode' } })

  const [auth, first, second] = gh.calls
  assert.deepEqual(auth.args, ['auth', 'status', '--hostname', 'github.com'])
  assert.equal(gh.calls.length, 3, 'auth status is checked once, not before every request')
  assert.equal(first.cmd, 'gh')
  assert.deepEqual(first.args.slice(0, 6), ['api', '--hostname', 'github.com', '--method', 'GET', '--include'])
  assert.deepEqual(first.args.slice(-2), ['--', '/repos/microsoft/vscode'])
  assert.deepEqual(second.args.slice(-2), ['--', '/users/microsoft'])
  for (const call of gh.calls) {
    assert.ok(!call.opts.shell, 'never through a shell')
    assert.equal(call.opts.stdio[2], 'ignore', "gh's stderr is never captured or shown")
    assert.equal(call.opts.env.GH_PROMPT_DISABLED, '1')
  }
})

test('gh: HTTP errors come back as a status, not an exception', async () => {
  const body = { message: 'Not Found', status: '404' }
  const gh = fakeSpawn(args => signedIn(args) ?? { code: 1, stdout: ghOutput(404, body, 'Not Found') })
  const api = createGitHubApi({ spawn: gh.spawn, fetch: noFetch.fetch })
  assert.deepEqual(await api('/repos/micr0s0ft/vscode'), { status: 404, json: body })
})

test('gh: no HTTP response at all (network down) is an error', async () => {
  const gh = fakeSpawn(args => signedIn(args) ?? { code: 1, stdout: '' })
  const api = createGitHubApi({ spawn: gh.spawn, fetch: noFetch.fetch })
  await assert.rejects(api('/repos/a/b'), /no HTTP response/)
})

test('gh: a request that hangs is killed after the timeout', async () => {
  const gh = fakeSpawn(args => signedIn(args) ?? { hang: true })
  const api = createGitHubApi({ spawn: gh.spawn, fetch: noFetch.fetch, timeoutMs: 30 })
  await assert.rejects(api('/repos/a/b'), /timed out/)
  assert.equal(gh.calls.at(-1).child.killed, true)
})

test('gh: an oversized response is cut off', async () => {
  const gh = fakeSpawn(args => signedIn(args) ?? { code: 0, stdout: ghOutput(200, { pad: 'x'.repeat(5000) }) })
  const api = createGitHubApi({ spawn: gh.spawn, fetch: noFetch.fetch, maxBytes: 1000 })
  await assert.rejects(api('/repos/a/b'), /too large/)
})

for (const [why, answer] of [['gh is not installed', ghMissing], ['gh is not signed in', notSignedIn]]) {
  test(`falls back to anonymous fetch when ${why}`, async () => {
    const gh = fakeSpawn(args => answer(args) ?? { error: 'should not run gh api' })
    const http = fakeFetch(() => new Response(JSON.stringify({ login: 'torvalds' }), { status: 200 }))
    const api = createGitHubApi({ spawn: gh.spawn, fetch: http.fetch })
    assert.deepEqual(await api('/users/torvalds'), { status: 200, json: { login: 'torvalds' } })
    assert.equal(gh.calls.length, 1, 'only "gh auth status" ran')
    const [{ url, init }] = http.calls
    assert.equal(url, 'https://api.github.com/users/torvalds')
    assert.equal(init.method, 'GET')
    assert.equal(init.headers['User-Agent'], 'git-bouncer')
    assert.ok(!Object.keys(init.headers).some(h => /authorization|cookie/i.test(h)), 'anonymous means no credentials')
    assert.ok(init.signal, 'every request has a timeout')
  })
}

test('fetch: error statuses and non-JSON bodies are returned, not thrown', async () => {
  const http = fakeFetch(() => new Response('<html>rate limited</html>', { status: 429 }))
  const api = createGitHubApi({ spawn: fakeSpawn(ghMissing).spawn, fetch: http.fetch })
  assert.deepEqual(await api('/repos/a/b'), { status: 429, json: null })
})

test('fetch: oversized responses are refused, whether declared or not', async () => {
  const big = JSON.stringify({ pad: 'x'.repeat(5000) })
  const declared = fakeFetch(() => new Response(big, { status: 200, headers: { 'content-length': String(big.length) } }))
  const undeclared = fakeFetch(() => new Response(new Blob([big]).stream(), { status: 200 }))
  for (const http of [declared, undeclared]) {
    const api = createGitHubApi({ spawn: fakeSpawn(ghMissing).spawn, fetch: http.fetch, maxBytes: 1000 })
    await assert.rejects(api('/repos/a/b'), /unexpectedly large/)
  }
})

test('fetch: network errors and timeouts become GitHubApiError', async () => {
  const down = fakeFetch(() => { throw new TypeError('fetch failed') })
  const slow = fakeFetch((url, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(init.signal.reason))
  }))
  await assert.rejects(createGitHubApi({ spawn: fakeSpawn(ghMissing).spawn, fetch: down.fetch })('/repos/a/b'), /Could not reach/)
  await assert.rejects(createGitHubApi({ spawn: fakeSpawn(ghMissing).spawn, fetch: slow.fetch, timeoutMs: 30 })('/repos/a/b'), /in time/)
})

test('fetch: a redirect away from api.github.com is refused', async () => {
  const http = fakeFetch(() => {
    const res = new Response('{}', { status: 200 })
    Object.defineProperty(res, 'url', { value: 'https://evil.example/repos/a/b' })
    return res
  })
  const api = createGitHubApi({ spawn: fakeSpawn(ghMissing).spawn, fetch: http.fetch })
  await assert.rejects(api('/repos/a/b'), /another site/)
})
