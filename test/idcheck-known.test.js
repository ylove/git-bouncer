import { test } from 'node:test'
import assert from 'node:assert/strict'
import { KNOWN_OWNERS, FAMOUS_REPOS } from '../src/idcheck/known.js'
import { createMatcher, MIN_LENGTH, loose } from '../src/idcheck/lookalike.js'

// The same rules url.js applies to GitHub owners and repo names.
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/
const REPO_NAME = /^[A-Za-z0-9._-]{1,100}$/

test('known owners are valid, lowercase GitHub names with no duplicates', () => {
  for (const o of KNOWN_OWNERS) {
    assert.match(o, GITHUB_OWNER, o)
    assert.equal(o, o.toLowerCase(), o)
  }
  assert.equal(new Set(KNOWN_OWNERS).size, KNOWN_OWNERS.length)
})

test('every real owner of a famous repo is on the known-owner list', () => {
  // Otherwise a look-alike of that owner ("t0rvalds/linux") would slip past the owner check.
  const known = new Set(KNOWN_OWNERS)
  for (const [repo, owners] of Object.entries(FAMOUS_REPOS)) {
    assert.match(repo, REPO_NAME, repo)
    assert.ok(loose(repo).length >= MIN_LENGTH, `${repo} is too short to compare without false alarms`)
    assert.ok(owners.length > 0, repo)
    for (const o of owners) assert.ok(known.has(o.toLowerCase()), `${o} (owner of ${repo}) is missing from KNOWN_OWNERS`)
  }
})

test('famous repo names are unique once case and separators are ignored', () => {
  const seen = new Map()
  for (const repo of Object.keys(FAMOUS_REPOS)) {
    assert.ok(!seen.has(loose(repo)), `${repo} and ${seen.get(loose(repo))} are the same name`)
    seen.set(loose(repo), repo)
  }
})

test('no known name is a look-alike of another known name', () => {
  // Known names always count as exact matches, so this can't cause a false alarm. It's here so that
  // adding a name that's one typo from another one is a conscious decision, not an accident.
  for (const list of [KNOWN_OWNERS, Object.keys(FAMOUS_REPOS)]) {
    for (const name of list) {
      const others = createMatcher(list.filter(n => n !== name))
      assert.equal(others(name), null, name)
    }
  }
})

test('against the real list: the look-alikes from the issue are caught', () => {
  const find = createMatcher(KNOWN_OWNERS)
  assert.deepEqual(find('micr0s0ft'), { match: 'microsoft', kind: 'characters' })
  assert.deepEqual(find('rnicrosoft'), { match: 'microsoft', kind: 'characters' })
  assert.deepEqual(find('vercell'), { match: 'vercel', kind: 'extra' })
  assert.deepEqual(find('faceb00k'), { match: 'facebook', kind: 'characters' })
  assert.deepEqual(find('0penai'), { match: 'openai', kind: 'characters' })
  assert.deepEqual(find('anthropic5'), { match: 'anthropics', kind: 'characters' })
  assert.deepEqual(find('t0rvalds'), { match: 'torvalds', kind: 'characters' })
  assert.deepEqual(find('metarnask'), { match: 'metamask', kind: 'characters' })
  assert.deepEqual(find('hugginface'), { match: 'huggingface', kind: 'missing' })
})

test('against the real list: well-known names and real unrelated neighbours pass', () => {
  const find = createMatcher(KNOWN_OWNERS)
  for (const name of ['microsoft', 'Microsoft', 'facebook', 'meta', 'react', 'vercel', 'vuejs', 'nodejs', 'googlemaps']) {
    assert.equal(find(name), null, name)
  }
  // Real accounts near a known name. Each one would be a false alarm under plain edit distance <= 1.
  for (const name of ['openaq', 'ample', 'docket', 'dockur', 'twister', 'discard', 'elastio', 'llama', 'interest', 'amazon', 'node', 'vue']) {
    assert.equal(find(name), null, name)
  }
})
