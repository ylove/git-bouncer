import { test } from 'node:test'
import assert from 'node:assert/strict'
import { skeleton, loose, editDistance, createMatcher } from '../src/idcheck/lookalike.js'

test('skeleton: look-alike characters and separators collapse to the same name', () => {
  for (const name of ['microsoft', 'Microsoft', 'micr0s0ft', 'rnicrosoft', 'mlcrosoft', 'm1crosoft', 'micro-soft', 'MICRO_SOFT']) {
    assert.equal(skeleton(name), skeleton('microsoft'), name)
  }
  assert.equal(skeleton('faceb00k'), skeleton('facebook'))
  assert.equal(skeleton('tvvitter'), skeleton('twitter'))
  assert.equal(skeleton('c1oudflare'), skeleton('cloudflare')) // 1 -> l, then "cl" reads as "d"
  assert.equal(skeleton('ub3r'), skeleton('uber'))
  assert.equal(skeleton('n4s4'), skeleton('nasa'))
  assert.equal(skeleton('7witter'), skeleton('twitter'))
  assert.equal(skeleton('8itcoin'), skeleton('bitcoin'))
  assert.equal(skeleton('5tripe'), skeleton('stripe'))
  assert.notEqual(skeleton('vercell'), skeleton('vercel')) // a typo, not a look-alike character
  assert.equal(loose('Next.js'), 'nextjs')
})

test('editDistance counts a swap of two neighbouring letters as one edit', () => {
  assert.equal(editDistance('microsoft', 'microsoft'), 0)
  assert.equal(editDistance('vercell', 'vercel'), 1) // extra letter
  assert.equal(editDistance('gogle', 'google'), 1) // missing letter
  assert.equal(editDistance('mircosoft', 'microsoft'), 1) // swap (plain Levenshtein says 2)
  assert.equal(editDistance('micrasoft', 'microsoft'), 1) // changed letter
  assert.equal(editDistance('kitten', 'sitting'), 3)
  assert.equal(editDistance('', 'abc'), 3)
  assert.equal(editDistance('abc', ''), 3)
  // Plain edit distance underrates look-alike characters, which is why skeletons come first.
  assert.equal(editDistance('micr0s0ft', 'microsoft'), 2)
  assert.equal(editDistance(skeleton('micr0s0ft'), skeleton('microsoft')), 0)
})

const KNOWN = ['microsoft', 'facebook', 'vercel', 'google', 'googleapis', 'openai', 'apple', 'docker', 'twitter',
  'discord', 'elastic', 'ollama', 'pinterest', 'uber', 'vuejs', 'nodejs', 'aws', 'npm', 'kubernetes']
const find = createMatcher(KNOWN)

test('catches real-world look-alike tricks, and says which trick', () => {
  const cases = {
    micr0s0ft: ['microsoft', 'characters'],
    rnicrosoft: ['microsoft', 'characters'],
    m1crosoft: ['microsoft', 'characters'],
    'micro-soft': ['microsoft', 'separators'],
    faceb00k: ['facebook', 'characters'],
    'face-book': ['facebook', 'separators'],
    vercell: ['vercel', 'extra'],
    vercl: ['vercel', 'missing'],
    vecrel: ['vercel', 'swapped'],
    mircosoft: ['microsoft', 'swapped'],
    microsft: ['microsoft', 'missing'],
    micrasoft: ['microsoft', 'changed'],
    g00gle: ['google', 'characters'],
    gogle: ['google', 'missing'],
    goolge: ['google', 'swapped'],
    '0penai': ['openai', 'characters'],
    tvvitter: ['twitter', 'characters'],
    kubemetes: ['kubernetes', 'characters'], // "rn" written as "m"
    kubernetees: ['kubernetes', 'extra'],
    ub3r: ['uber', 'characters'],
    'node-js': ['nodejs', 'separators'],
  }
  for (const [name, [match, kind]] of Object.entries(cases)) {
    assert.deepEqual(find(name), { match, kind }, name)
  }
})

test('the real names themselves are never look-alikes, in any case', () => {
  for (const name of KNOWN) {
    assert.equal(find(name), null, name)
    assert.equal(find(name.toUpperCase()), null, name)
  }
  assert.equal(find('Microsoft'), null)
})

test('known names that are close to each other are both treated as exact', () => {
  // googleapis is one changed letter from "googleapps"-style names; both real Google orgs must pass.
  const f = createMatcher(['google', 'googleapis', 'googlemaps', 'vuejs', 'vitejs', 'nodejs', 'nestjs'])
  for (const name of ['google', 'googleapis', 'googlemaps', 'vuejs', 'vitejs', 'nodejs', 'nestjs']) assert.equal(f(name), null, name)
})

test('does not flag real, unrelated names that happen to be close (false positives)', () => {
  for (const name of [
    'openaq', // a real air-quality nonprofit: one changed letter from openai
    'ample', 'apply', // one changed letter from apple
    'docket', 'dockur', // one changed letter from docker
    'twister', 'discard', 'elastio', // one changed letter in a 7-letter name
    'llama', // ollama minus its first letter
    'interest', // pinterest minus its first letter
    'user', 'uberx', // short names: only look-alike characters count
    'vue', 'node', 'aws-js', // short or far from any known name
    'google-research-fan', 'vercel-templates-by-me', // brand plus words: not a look-alike (see docs/id-check.md)
    'someone', 'octocat', 'torvalds-fan',
  ]) {
    assert.equal(find(name), null, name)
  }
})

test('names shorter than four letters are never compared', () => {
  const f = createMatcher(['aws', 'npm', 'git'])
  for (const name of ['aws5', 'awz', 'nprn', 'g1t', 'gitt']) assert.equal(f(name), null, name)
})

test('the closest match wins when several known names are near', () => {
  const f = createMatcher(['vercel', 'vercel-labs'])
  assert.deepEqual(f('vercel-1abs'), { match: 'vercel-labs', kind: 'characters' })
  assert.deepEqual(f('vercell'), { match: 'vercel', kind: 'extra' })
})

test('handles empty and non-string input without throwing', () => {
  assert.equal(find(''), null)
  assert.equal(find(undefined), null)
  assert.equal(find(42), null)
})
