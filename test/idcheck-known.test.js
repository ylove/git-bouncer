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

test('known names that are one typo from another known name are listed on purpose', () => {
  // Known names always count as exact matches, so a pair like this can't cause a false alarm. The test
  // is here so that adding one is a conscious decision, checked against the GitHub API, not an accident.
  const expectedPairs = ['containers ~ containerd', 'containerd ~ containers', 'fastai ~ fastapi', 'fastapi ~ fastai']
  const pairs = []
  for (const list of [KNOWN_OWNERS, Object.keys(FAMOUS_REPOS)]) {
    for (const name of list) {
      const hit = createMatcher(list.filter(n => n !== name))(name)
      if (hit) pairs.push(`${name} ~ ${hit.match}`)
    }
  }
  assert.deepEqual(pairs.sort(), expectedPairs.sort())
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
  // Found by running the matcher over about 1,300 of GitHub's most-followed accounts and the owners of
  // about 1,200 of its most-starred repos. containers and fastai were flagged as look-alikes of
  // containerd and fastapi until they were added to the list. golangci was flagged as a look-alike of
  // golang until typos stopped being measured on the letter-pair-folded skeleton ("ci" -> "cl" -> "d").
  for (const name of ['containers', 'fastai', 'golangci']) assert.equal(find(name), null, name)
  // Real accounts near a known name. Each one would be a false alarm under plain edit distance <= 1.
  for (const name of ['openaq', 'ample', 'docket', 'dockur', 'twister', 'discard', 'elastio', 'llama', 'interest', 'amazon', 'node', 'vue']) {
    assert.equal(find(name), null, name)
  }
})
