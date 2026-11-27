// Stubbed GitHub API answers for the ID check tests. Nothing here touches the network.

import assert from 'node:assert/strict'
import { idCheck } from '../../src/idcheck/index.js'
import { KNOWN_OWNERS } from '../../src/idcheck/known.js'
import { parseRepoUrl } from '../../src/url.js'
import { computeVerdict, SEVERITIES } from '../../src/verdict.js'

// If anything tried the real API anyway, this makes it fail loudly instead of quietly depending on the
// internet. (Each test file runs in its own process, so this only affects the files that import it.)
globalThis.fetch = () => { throw new Error('unit tests must not use the network') }

export const NOW = Date.parse('2026-11-27T12:00:00Z')
const DAY = 24 * 60 * 60 * 1000
export const daysAgo = days => new Date(NOW - days * DAY).toISOString()

export const ESC = String.fromCharCode(0x1b)
export const RLO = String.fromCharCode(0x202e) // right-to-left override, the Trojan Source character

export const ok = json => ({ status: 200, json })
export const NOT_FOUND = { status: 404, json: { message: 'Not Found', status: '404' } }
export const RATE_LIMITED = { status: 403, json: { message: 'API rate limit exceeded for 203.0.113.7. (But here\'s the good news: Authenticated requests get a higher rate limit.)' } }

/** The real account ID for a listed owner; a stable made-up one for anybody else. */
export function idFor(login) {
  const key = login.toLowerCase()
  if (Object.hasOwn(KNOWN_OWNERS, key)) return KNOWN_OWNERS[key]
  return 500_000_000 + [...key].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 100_000_000, 7)
}

export const owned = (fullName, extra = {}) => ({ full_name: fullName, owner: { login: fullName.split('/')[0], id: idFor(fullName.split('/')[0]) }, ...extra })

export const repoJson = (fullName, extra = {}) => ({
  ...owned(fullName), name: fullName.split('/')[1], private: false, visibility: 'public', fork: false, archived: false,
  disabled: false, created_at: daysAgo(3000), stargazers_count: 5000, forks_count: 900, default_branch: 'main', ...extra,
  owner: { login: fullName.split('/')[0], id: idFor(fullName.split('/')[0]), type: 'Organization', ...extra.owner },
})
export const accountJson = (login, extra = {}) => ({ login, id: idFor(login), type: 'Organization', created_at: daysAgo(4000), ...extra })

/**
 * A stub for the GitHub API: a map from request path to answer. An answer that is an Error is thrown,
 * like a network failure. Requests for paths that aren't listed are recorded so the test can fail on them.
 */
export function stubApi(routes) {
  const calls = []
  const unexpected = []
  const api = async path => {
    calls.push(path)
    if (!Object.hasOwn(routes, path)) {
      unexpected.push(path)
      return NOT_FOUND
    }
    const answer = routes[path]
    if (answer instanceof Error) throw answer
    return answer
  }
  return { api, calls, unexpected }
}

/** The usual answers for an established GitHub repo: old account, old repo, a release. */
export function healthy(fullName, { repo = {}, owner = {}, org = {}, release = ok({ tag_name: 'v1.2.3', published_at: daysAgo(10) }) } = {}) {
  const [login] = fullName.split('/')
  return {
    [`/repos/${fullName}`]: ok(repoJson(fullName, repo)),
    [`/users/${login}`]: ok(accountJson(login, owner)),
    [`/orgs/${login}`]: ok({ login, is_verified: false, ...org }),
    [`/repos/${fullName}/releases/latest`]: release,
  }
}

/**
 * Parse the URL like the CLI does, run the ID check with stubbed API answers, check the output's
 * shape, and compute the verdict the way src/commands/check.js does: an incomplete ID check can't pass.
 */
export async function check(url, routes = {}, opts = {}) {
  const stub = stubApi(routes)
  const result = await idCheck(parseRepoUrl(url), { api: stub.api, now: NOW, iocs: [], ...opts })
  for (const f of result.findings) {
    assert.match(f.id, /^ID-[A-Z-]+$/)
    assert.ok(SEVERITIES.includes(f.severity), `${f.id} has severity ${f.severity}`)
    assert.equal(typeof f.title, 'string')
    assert.equal(typeof f.detail, 'string')
    assert.ok(f.detail.length > 20, `${f.id} explains itself`)
    assert.ok(!('evidence' in f) || typeof f.evidence === 'string', `${f.id} evidence is a string when present`)
  }
  assert.equal(typeof result.complete, 'boolean')
  assert.deepEqual(stub.unexpected, [], 'no unexpected GitHub API requests')
  const ids = result.findings.map(f => f.id)
  const byId = Object.fromEntries(result.findings.map(f => [f.id, f]))
  return { ...result, ids, byId, calls: stub.calls, verdict: computeVerdict(result.findings, { complete: result.complete }).verdict }
}

export const sev = (result, id) => result.byId[id]?.severity
