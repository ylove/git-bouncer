import { test } from 'node:test'
import assert from 'node:assert/strict'
import { KNOWN_OWNERS, FAMOUS_REPOS, NOT_THE_REAL_ONE, KNOWN_NEIGHBOURS } from '../src/idcheck/known.js'
import { createMatcher, MIN_LENGTH, loose } from '../src/idcheck/lookalike.js'

// The same rules url.js applies to GitHub owners and repo names.
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/
const REPO_NAME = /^[A-Za-z0-9._-]{1,100}$/
const OWNERS = Object.keys(KNOWN_OWNERS)
// The names the owner look-alike check compares against, as src/idcheck/index.js builds them.
const LOOKALIKE_NAMES = [...OWNERS, ...Object.keys(NOT_THE_REAL_ONE), ...Object.keys(KNOWN_NEIGHBOURS)]

test('known owners are valid, lowercase GitHub names, each pinned to a distinct account ID', () => {
  for (const [login, id] of Object.entries({ ...KNOWN_OWNERS, ...KNOWN_NEIGHBOURS })) {
    assert.match(login, GITHUB_OWNER, login)
    assert.equal(login, login.toLowerCase(), login)
    assert.ok(Number.isSafeInteger(id) && id > 0, `${login} has a numeric account ID`)
  }
  const ids = Object.values(KNOWN_OWNERS)
  assert.equal(new Set(ids).size, ids.length, 'two names pinned to the same account')
  for (const name of Object.keys(NOT_THE_REAL_ONE)) assert.ok(!Object.hasOwn(KNOWN_OWNERS, name), `${name} is both trusted and not`)
})

test('"facebook" is not trusted: its old account is now "meta", and the name belongs to someone else', () => {
  assert.ok(!Object.hasOwn(KNOWN_OWNERS, 'facebook'))
  for (const [repo, owners] of Object.entries(FAMOUS_REPOS)) assert.ok(!owners.includes('facebook'), repo)
  assert.equal(NOT_THE_REAL_ONE.facebook.formerId, KNOWN_OWNERS.meta, 'the account ID the name used to have is meta\'s')
})

test('every real owner of a famous repo is on the known-owner list', () => {
  // Otherwise a look-alike of that owner ("t0rvalds/linux") would slip past the owner check.
  for (const [repo, owners] of Object.entries(FAMOUS_REPOS)) {
    assert.match(repo, REPO_NAME, repo)
    assert.ok(loose(repo).length >= MIN_LENGTH, `${repo} is too short to compare without false alarms`)
    assert.ok(owners.length > 0, repo)
    for (const o of owners) assert.ok(Object.hasOwn(KNOWN_OWNERS, o.toLowerCase()), `${o} (owner of ${repo}) is missing from KNOWN_OWNERS`)
  }
})

test('famous repo names are unique once case and separators are ignored', () => {
  const seen = new Map()
  for (const repo of Object.keys(FAMOUS_REPOS)) {
    assert.ok(!seen.has(loose(repo)), `${repo} and ${seen.get(loose(repo))} are the same name`)
    seen.set(loose(repo), repo)
  }
})

test('known names that are one look-alike step from another known name are listed on purpose', () => {
  // Known names always count as exact matches, so a pair like this can't cause a false alarm. The test
  // is here so that adding one is a conscious decision, checked against the GitHub API, not an accident.
  const expectedPairs = [
    'containerd ~ containers', 'containers ~ containerd', 'data-dog ~ datadog', 'datadog ~ data-dog', 'fastai ~ fastapi', 'fastapi ~ fastai',
    // The brand next to its own sub-organization (compared by stem, so only one direction matches).
    'googlechrome ~ googlechromelabs', 'jupyter ~ jupyterlab', 'nginx ~ nginxinc', 'react ~ reactjs', 'vercel ~ vercel-labs', 'vercel-labs ~ vercel',
  ]
  const pairs = []
  for (const list of [LOOKALIKE_NAMES, Object.keys(FAMOUS_REPOS)]) {
    for (const name of list) {
      const hit = createMatcher(list.filter(n => n !== name))(name)
      if (hit) pairs.push(`${name} ~ ${hit.match}`)
    }
  }
  assert.deepEqual(pairs.sort(), expectedPairs.sort())
})

test('against the real list: the look-alikes from the issue are caught', () => {
  const find = createMatcher(LOOKALIKE_NAMES)
  assert.deepEqual(find('micr0s0ft'), { match: 'microsoft', kind: 'characters' })
  assert.deepEqual(find('rnicrosoft'), { match: 'microsoft', kind: 'characters' })
  assert.deepEqual(find('vercell'), { match: 'vercel', kind: 'extra' })
  assert.deepEqual(find('faceb00k'), { match: 'facebook', kind: 'characters' }, 'still caught, though facebook is no longer trusted')
  assert.deepEqual(find('0penai'), { match: 'openai', kind: 'characters' })
  assert.deepEqual(find('anthropic5'), { match: 'anthropics', kind: 'characters' })
  assert.deepEqual(find('t0rvalds'), { match: 'torvalds', kind: 'characters' })
  assert.deepEqual(find('metarnask'), { match: 'metamask', kind: 'characters' })
  assert.deepEqual(find('hugginface'), { match: 'huggingface', kind: 'missing' })
  assert.deepEqual(find('actlons'), { match: 'actions', kind: 'characters' })
  assert.deepEqual(find('amaz0n'), { match: 'amazon', kind: 'characters' })
})

test('against the real list: well-known names and real unrelated neighbours pass', () => {
  const find = createMatcher(LOOKALIKE_NAMES)
  for (const name of ['microsoft', 'Microsoft', 'facebook', 'meta', 'react', 'vercel', 'vuejs', 'nodejs', 'googlemaps', 'data-dog', 'DATA-DOG']) {
    assert.equal(find(name), null, name)
  }
  // Found by running the matcher over the owners of thousands of popular repos (see docs/id-check.md):
  // these real organizations were flagged until they were listed or the rules changed.
  for (const name of ['containers', 'fastai', 'golangci', 'googlechromelabs', 'jupyterlab', 'nginxinc', 'realpython', 'postgresapp', 'bitcoinjs', 'railsapps', '8483']) {
    assert.equal(find(name), null, name)
  }
  // Real accounts near a known name. Each one would be a false alarm under plain edit distance <= 1.
  for (const name of ['openaq', 'ample', 'docket', 'dockur', 'twister', 'discard', 'elastio', 'llama', 'interest', 'node', 'vue']) {
    assert.equal(find(name), null, name)
  }
})
