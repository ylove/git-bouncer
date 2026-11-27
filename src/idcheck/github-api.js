// Read-only access to the GitHub REST API, for the ID check.
//
// Two ways in, chosen once per run:
//  - Through the GitHub CLI ("gh api") when gh is installed and signed in. gh adds your token to the
//    request itself, so git-bouncer never sees, stores or prints it, and you get the signed-in rate
//    limit (5,000 requests an hour).
//  - Otherwise anonymously, with fetch: no token, and a generic User-Agent, so nothing identifies you
//    except your IP address. GitHub allows 60 anonymous requests an hour per IP address.
//
// Either way: only a few exact, read-only paths are allowed (API_PATH), every request has a timeout,
// and responses are size-capped. A failure is thrown as GitHubApiError; the ID check turns that into a
// finding that says what couldn't be checked, so a network problem never crashes a scan.

import { spawn as nodeSpawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { which as findProgram } from '../proc.js'

export const TIMEOUT_MS = 10_000
export const MAX_RESPONSE_BYTES = 1024 * 1024 // a repo's metadata is about 6 KB

// Same rules as src/url.js. The repo part can't be "." or "..", which a URL parser would resolve
// ("/repos/a/.." is "/repos").
const OWNER = '[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}'
const REPO = '(?!\\.{1,2}(?:/|$))[A-Za-z0-9._-]{1,100}'
/**
 * The only requests the ID check ever makes. Anything else is refused before gh or fetch sees it.
 * Braces are never allowed: gh replaces "{owner}" and "{repo}" with values from the git repo in the
 * current folder, which would let the folder you happen to be in decide what gets looked up.
 */
export const API_PATH = new RegExp(`^/(?:repos/${OWNER}/${REPO}(?:/releases/latest)?|users/${OWNER}|orgs/${OWNER})$`)

export class GitHubApiError extends Error {
  constructor(message) {
    super(message)
    this.name = 'GitHubApiError'
  }
}

const HEADERS = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }

/**
 * @param {object} [deps]  injectable for tests, so no test ever touches the network
 * @returns {(path: string) => Promise<{status: number, json: any}>}
 *   status is the HTTP status (200, 404, 403, ...). json is the parsed body, or null if it wasn't JSON.
 */
export function createGitHubApi({ spawn = nodeSpawn, fetch = globalThis.fetch, which = findProgram, timeoutMs = TIMEOUT_MS, maxBytes = MAX_RESPONSE_BYTES } = {}) {
  let mode = null // a Promise of the gh program's absolute path, or null for anonymous; decided once
  return async function githubApi(path) {
    if (typeof path !== 'string' || !API_PATH.test(path)) throw new GitHubApiError('Refused an unexpected GitHub API path.')
    mode ??= findSignedInGh(spawn, which, timeoutMs)
    const gh = await mode
    return gh ? viaGh(spawn, gh, path, timeoutMs, maxBytes) : viaFetch(fetch, path, timeoutMs, maxBytes)
  }
}

/** The default client: gh if you're signed in, anonymous otherwise. */
export const githubApi = createGitHubApi()

// The environment gh runs with: yours, so it finds its own login, minus anything that would make it
// prompt, check for updates, or format its output for a terminal.
function ghEnv() {
  const env = { ...process.env, GH_PROMPT_DISABLED: '1', GH_NO_UPDATE_NOTIFIER: '1', NO_COLOR: '1' }
  delete env.GH_FORCE_TTY
  return env
}

// Every gh call:
//  - runs gh by its absolute path, found using absolute PATH entries only. A bare "gh" would let an
//    empty or "." PATH entry pick up a gh planted in the current folder (on Windows, the current folder
//    is searched before PATH anyway).
//  - runs in a fresh, private, empty folder (mkdtemp creates it readable by you only), never in a shared
//    one like /tmp, and never in whatever repo you're standing in.
//  - takes an argument array, never a shell string, and discards stderr (with GH_DEBUG set, gh logs
//    request details there).
function runGh(spawn, gh, args, { timeoutMs, maxBytes = 0 }) {
  return new Promise(resolve => {
    let child
    let cwd
    try {
      cwd = mkdtempSync(join(tmpdir(), 'git-bouncer-gh-'))
      child = spawn(gh, args, { stdio: ['ignore', maxBytes ? 'pipe' : 'ignore', 'ignore'], cwd, env: ghEnv(), windowsHide: true, shell: false })
    } catch {
      removeQuietly(cwd)
      resolve({ code: null, out: null, problem: 'gh could not be started' })
      return
    }
    const chunks = []
    let size = 0
    let finished = false
    const finish = (code, problem) => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      if (problem) child.kill()
      removeQuietly(cwd)
      resolve({ code, out: Buffer.concat(chunks).toString('utf8'), problem })
    }
    const timer = setTimeout(() => finish(null, 'timed out'), timeoutMs)
    child.stdout?.on('data', chunk => {
      size += chunk.length
      if (size > maxBytes) finish(null, 'response too large')
      else chunks.push(chunk)
    })
    child.on('error', () => finish(null, 'gh could not be started')) // e.g. gh isn't installed
    child.on('close', code => finish(code, null))
  })
}

// The folder is empty, so failing to remove it (Windows won't while a killed gh is still exiting) only
// leaves an empty folder behind. It must never turn into an exception inside an event handler.
function removeQuietly(dir) {
  if (!dir) return
  try {
    rmSync(dir, { recursive: true, force: true })
  } catch { /* an empty temp folder is left behind */ }
}

/** The absolute path of gh if it's installed and signed in to github.com, else null. */
async function findSignedInGh(spawn, which, timeoutMs) {
  const gh = await which('gh', process.env)
  if (!gh) return null
  // Exit code 0 means signed in to github.com. Its output (which names your account) is discarded.
  const { code, problem } = await runGh(spawn, gh, ['auth', 'status', '--hostname', 'github.com'], { timeoutMs })
  return !problem && code === 0 ? gh : null
}

async function viaGh(spawn, gh, path, timeoutMs, maxBytes) {
  const args = ['api', '--hostname', 'github.com', '--method', 'GET', '--include']
  for (const [name, value] of Object.entries(HEADERS)) args.push('-H', `${name}: ${value}`)
  args.push('--', path)
  const { out, problem } = await runGh(spawn, gh, args, { timeoutMs, maxBytes })
  if (problem) throw new GitHubApiError(`The GitHub CLI request failed (${problem}).`)
  // With --include, gh prints the status line and headers before the body, for errors (404, 403, ...)
  // too. That's how the HTTP status is known; gh's exit code is just 1 for any error.
  const status = /^HTTP\/[0-9.]+ ([1-5][0-9]{2})\b/.exec(out)
  if (!status) throw new GitHubApiError('The GitHub CLI request failed (no HTTP response; is the network up?).')
  const blank = /\r?\n\r?\n/.exec(out)
  return { status: Number(status[1]), json: parseJson(blank ? out.slice(blank.index + blank[0].length) : '') }
}

async function viaFetch(fetch, path, timeoutMs, maxBytes) {
  // A plain timer rather than AbortSignal.timeout(): that one's timer doesn't keep Node running, so a
  // request with nothing else holding the process open could end the program instead of timing out.
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new GitHubApiError('The GitHub API did not answer in time.')), timeoutMs)
  try {
    const res = await fetch(`https://api.github.com${path}`, {
      method: 'GET',
      headers: { ...HEADERS, 'User-Agent': 'git-bouncer' },
      redirect: 'follow', // GitHub redirects renamed repos (facebook/react -> react/react)
      signal: controller.signal,
    })
    if (res.url && new URL(res.url).origin !== 'https://api.github.com') throw new GitHubApiError('GitHub redirected the request to another site.')
    return { status: res.status, json: parseJson(await readCapped(res, maxBytes)) }
  } catch (e) {
    if (e instanceof GitHubApiError) throw e
    throw new GitHubApiError(controller.signal.aborted ? 'The GitHub API did not answer in time.' : 'Could not reach the GitHub API.')
  } finally {
    clearTimeout(timer)
  }
}

async function readCapped(res, maxBytes) {
  const declared = Number(res.headers.get('content-length'))
  if (declared > maxBytes) throw new GitHubApiError('The GitHub API response was unexpectedly large.')
  if (!res.body) return ''
  const reader = res.body.getReader()
  const chunks = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > maxBytes) {
      await reader.cancel()
      throw new GitHubApiError('The GitHub API response was unexpectedly large.')
    }
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function parseJson(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}
