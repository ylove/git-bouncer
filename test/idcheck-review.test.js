// One regression test per finding in the adversarial review of PR #19, using the reviewer's repros.
// Every GitHub answer is a stub (helpers/idcheck-stubs.js), so nothing here touches the network.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { delimiter, join } from 'node:path'
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { which } from '../src/proc.js'
import { daysAgo, ok, NOT_FOUND, RATE_LIMITED, owned, repoJson, accountJson, healthy, check, sev, idFor } from './helpers/idcheck-stubs.js'

const FACEBOOK_NOW = 349478847 // the account that holds the name "facebook" since 2026-10-28
const CAMPAIGN = { campaign: 'Example campaign', source: 'https://example.com/report', repos: ['stevenleedig-ux/axios-http'] }

// [high] 1. "facebook" was allowlisted, though the name now belongs to a different account.

test('review 1: a repo served by the new "facebook" account is turned away, and gets no trust', async () => {
  const newFacebook = { login: 'facebook', id: FACEBOOK_NOW, type: 'Organization' }
  const r = await check('github.com/facebook/facebook.github.io', healthy('facebook/facebook.github.io', {
    repo: { owner: newFacebook, created_at: daysAgo(21) }, owner: { id: FACEBOOK_NOW, created_at: '2026-10-28T18:28:13Z' },
  }))
  assert.equal(sev(r, 'ID-OWNER-CHANGED-HANDS'), 'high')
  assert.match(r.byId['ID-OWNER-CHANGED-HANDS'].detail, /"meta"/)
  assert.equal(r.verdict, 'fail')

  const nativ3 = await check('github.com/facebook/react-nativ3', healthy('facebook/react-nativ3', {
    repo: { owner: newFacebook }, owner: { id: FACEBOOK_NOW, created_at: '2026-10-28T18:28:13Z' },
  }))
  assert.equal(sev(nativ3, 'ID-OWNER-CHANGED-HANDS'), 'high')
  assert.equal(sev(nativ3, 'ID-LOOKALIKE-REPO'), 'high', 'no allowlist exemption for a name that changed hands')
})

test('review 1: any listed name whose account ID no longer matches has changed hands', async () => {
  const r = await check('github.com/microsoft/vscode', healthy('microsoft/vscode', {
    repo: { owner: { login: 'microsoft', id: 424242 } }, owner: { id: 424242 },
  }))
  assert.equal(sev(r, 'ID-OWNER-CHANGED-HANDS'), 'high')
  assert.match(r.byId['ID-OWNER-CHANGED-HANDS'].evidence, /424242.*6154722/)
  assert.equal(sev(r, 'ID-IMPERSONATION'), 'medium', 'and the famous name is no longer vouched for')
})

test('review 1: offline, "facebook" is a warning, never an allowlist pass', async () => {
  const r = await check('github.com/facebook/react', { '/repos/facebook/react': new Error('offline') })
  assert.equal(sev(r, 'ID-IMPERSONATION'), 'medium')
  assert.match(r.byId['ID-LOOKALIKE-OWNER'].title, /isn't who the name suggests/)
  assert.equal(r.verdict, 'incomplete')
})

test('review 1: look-alikes of facebook are still caught', async () => {
  const r = await check('github.com/faceb00k/react', { '/repos/faceb00k/react': NOT_FOUND })
  assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'high')
})

// [high] 2. Fail-open: an API failure was one "low" finding, so the verdict could be a pass.

test('review 2: whatever stops the API, a new repo from a new account is never a pass', async () => {
  const fresh = healthy('fresh-recruiter/take-home', { repo: { created_at: daysAgo(1) }, owner: { created_at: daysAgo(2), type: 'User' }, release: NOT_FOUND })
  assert.equal((await check('github.com/fresh-recruiter/take-home', fresh)).verdict, 'warn')
  for (const answer of [RATE_LIMITED, new Error('offline'), { status: 502, json: null }, { status: 401, json: { message: 'Bad credentials' } }]) {
    const r = await check('github.com/fresh-recruiter/take-home', { '/repos/fresh-recruiter/take-home': answer })
    assert.equal(r.complete, false)
    assert.equal(r.verdict, 'incomplete', String(answer.status ?? answer.message))
  }
})

// [high] 3. False positives: a typo-style match got "high" even on long-established accounts.

test('review 3: real, long-established projects one typo from a listed name are a warning, not a failure', async () => {
  for (const [path, real] of [['androidx/androidx', 'android'], ['nestjsx/crud', 'nestjs'], ['pallet/pallet', 'pallets'],
    ['gyoogle/tech-interview-for-developer', 'google'], ['Red5/red5-server', 'redis']]) {
    const r = await check(`github.com/${path}`, healthy(path, { owner: { created_at: daysAgo(3000) }, org: { is_verified: true, blog: 'https://example.com' } }))
    assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'medium', path)
    assert.match(r.byId['ID-LOOKALIKE-OWNER'].title, new RegExp(`looks like "${real}": check it's who you meant`))
    assert.equal(r.verdict, 'warn', path)
  }
})

test('review 3: the same typo-style name on a young account, or when GitHub cannot say, is still turned away', async () => {
  const young = await check('github.com/androidx/androidx', healthy('androidx/androidx', { owner: { created_at: daysAgo(20) } }))
  assert.equal(sev(young, 'ID-LOOKALIKE-OWNER'), 'high')
  const unknown = await check('github.com/androidx/androidx', { '/repos/androidx/androidx': RATE_LIMITED })
  assert.equal(sev(unknown, 'ID-LOOKALIKE-OWNER'), 'high')
  assert.equal(unknown.verdict, 'fail')
})

test('review 3: disguised characters stay high, however old the account', async () => {
  const r = await check('github.com/micr0s0ft/tools', healthy('micr0s0ft/tools', { owner: { created_at: daysAgo(5000) } }))
  assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'high')
})

test('review 3: an all-digit name is a number, not a look-alike', async () => {
  const r = await check('github.com/8483/tool', healthy('8483/tool'))
  assert.ok(!r.ids.includes('ID-LOOKALIKE-OWNER'), '8483 is not "babe" (a look-alike of babel)')
})

// [medium] 4. A transfer redirect laundered an IOC-listed account and a look-alike repo name.

test('review 4: a redirect to an IOC-listed repo is caught, and the transfer is a warning', async () => {
  const r = await check('github.com/fresh-recruiter/axios-http', {
    '/repos/fresh-recruiter/axios-http': ok(repoJson('stevenleedig-ux/axios-http')),
    '/users/stevenleedig-ux': ok(accountJson('stevenleedig-ux', { type: 'User' })),
    '/repos/stevenleedig-ux/axios-http/releases/latest': NOT_FOUND,
  }, { iocs: [CAMPAIGN] })
  assert.equal(sev(r, 'ID-IOC-REPO'), 'critical')
  assert.match(r.byId['ID-IOC-REPO'].title, /redirects fresh-recruiter\/axios-http there/)
  assert.equal(sev(r, 'ID-MOVED'), 'medium')
  assert.match(r.byId['ID-MOVED'].evidence, /fresh-recruiter -> stevenleedig-ux/)
  assert.equal(r.verdict, 'fail')
})

test('review 4: a well-known name that redirects to a stranger gets no trust from the name', async () => {
  const r = await check('github.com/microsoft/vscode-websocket', {
    '/repos/microsoft/vscode-websocket': ok(repoJson('random-dev/vsc0de', { owner: { type: 'User' } })),
    '/users/random-dev': ok(accountJson('random-dev', { type: 'User' })),
    '/repos/random-dev/vsc0de/releases/latest': NOT_FOUND,
  })
  assert.equal(sev(r, 'ID-LOOKALIKE-REPO'), 'high')
  assert.equal(sev(r, 'ID-MOVED'), 'medium')
  assert.equal(r.verdict, 'fail')
})

test('review 4: a redirect to a look-alike owner is turned away', async () => {
  const r = await check('github.com/innocent/tools', {
    '/repos/innocent/tools': ok(repoJson('rnicrosoft/tools')),
    '/users/rnicrosoft': ok(accountJson('rnicrosoft')),
    '/orgs/rnicrosoft': ok({ login: 'rnicrosoft', is_verified: false }),
    '/repos/rnicrosoft/tools/releases/latest': NOT_FOUND,
  })
  assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'high')
  assert.match(r.byId['ID-LOOKALIKE-OWNER'].title, /redirects innocent\/tools there/)
})

// [medium] 5. Look-alikes that could be registered and still passed.

test('review 5: the bare brand, and the brand plus a company word, are warnings', async () => {
  for (const name of ['unsloth', 'mistral', 'deepseek', 'langchain', 'stability', 'uniswap-labs', 'microsoft-official', 'openai-official',
    'anthropics-ai', 'huggingface-official', 'nvidia-official', 'metamask-official', 'metamask-dev']) {
    const r = await check(`github.com/${name}/app`, healthy(`${name}/app`))
    assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'medium', name)
    assert.equal(r.verdict, 'warn', name)
  }
  // A young org with a bare brand name (mistral was 24 days old) gets the new-account warning too.
  const mistral = await check('github.com/mistral/le-chat', healthy('mistral/le-chat', { owner: { created_at: daysAgo(24) } }))
  assert.deepEqual(['ID-LOOKALIKE-OWNER', 'ID-NEW-OWNER'].map(id => sev(mistral, id)), ['medium', 'medium'])
})

test('review 5: a letter pair plus a typo, and two typos in a long name, are caught', async () => {
  for (const [name, real] of [['rnicrosft', 'microsoft'], ['rnongodbs', 'mongodb'], ['modelcontextptorocol', 'modelcontextprotocol']]) {
    const r = await check(`github.com/${name}/servers`, { [`/repos/${name}/servers`]: NOT_FOUND })
    assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'high', name)
    assert.match(r.byId['ID-LOOKALIKE-OWNER'].title, new RegExp(`"${real}"`))
  }
})

test('review 5: big orgs that were missing are listed, so actlons/checkout is turned away', async () => {
  const r = await check('github.com/actlons/checkout', healthy('actlons/checkout', { owner: { created_at: daysAgo(700) } }))
  assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'high')
  assert.match(r.byId['ID-LOOKALIKE-OWNER'].title, /"actions"/)
  for (const real of ['actions', 'apache', 'expo', 'foundry-rs', 'binance', 'ledgerhq']) {
    const pass = await check(`github.com/${real}/tool`, healthy(`${real}/tool`))
    assert.ok(!pass.ids.includes('ID-LOOKALIKE-OWNER'), real)
  }
})

test('review 5: an owner named after a famous project is a warning', async () => {
  for (const [name, famous] of [['nextjs', 'next.js'], ['vscode', 'vscode'], ['typescript', 'TypeScript'], ['claude-code', 'claude-code']]) {
    const r = await check(`github.com/${name}/starter`, healthy(`${name}/starter`))
    assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'medium', name)
    assert.match(r.byId['ID-LOOKALIKE-OWNER'].title, new RegExp(`named after the famous project ${famous.replace('.', '\\.')}`))
  }
})

// [medium] 6. The verified-org note reassured without saying which domain, even for borrowed brands.

test('review 6: a verified org that borrows a brand gets no reassuring note', async () => {
  const r = await check('github.com/openai-labs/chatgpt-web', healthy('openai-labs/chatgpt-web', {
    org: { is_verified: true, blog: 'me.edu.ge', name: 'OpenAI Labs' },
  }))
  assert.ok(!r.ids.includes('ID-VERIFIED-ORG'))
  assert.equal(r.facts.verifiedOrg, true)
  assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'medium')
  // The display name alone is enough to suppress it.
  const display = await check('github.com/ai-research-hub/chat', healthy('ai-research-hub/chat', { org: { is_verified: true, name: 'OpenAI Labs' } }))
  assert.ok(!display.ids.includes('ID-VERIFIED-ORG'))
})

test('review 6: the verified-org note names the website and links the org page, without vouching', async () => {
  const r = await check('github.com/vercel/next.js', healthy('vercel/next.js', { org: { is_verified: true, blog: 'https://vercel.com' } }))
  const note = r.byId['ID-VERIFIED-ORG']
  assert.match(note.detail, /https:\/\/vercel\.com/)
  assert.match(note.detail, /https:\/\/github\.com\/vercel/)
  assert.doesNotMatch(note.detail, /good sign/)
})

// [low] 7. A stranger's fork of a famous repo got no warning.

test("review 7: a stranger's fork of a famous repo is low, and medium when the fork or account is young", async () => {
  const fork = (forkDays, ownerDays) => check('github.com/hr-team-2026/react', healthy('hr-team-2026/react', {
    repo: { fork: true, parent: owned('react/react'), source: owned('react/react'), created_at: daysAgo(forkDays) },
    owner: { type: 'User', created_at: daysAgo(ownerDays) },
  }))
  assert.equal(sev(await fork(120, 400), 'ID-FORK-OF-FAMOUS'), 'low')
  assert.equal(sev(await fork(30, 400), 'ID-FORK-OF-FAMOUS'), 'medium')
  assert.equal(sev(await fork(120, 60), 'ID-FORK-OF-FAMOUS'), 'medium')
  assert.match((await fork(30, 400)).byId['ID-FORK-OF-FAMOUS'].detail, /can change any of its code/)
})

// [low] 8. gh was looked up with a shared temp folder as the working directory. (The spawn side is
// tested in idcheck-github-api.test.js: absolute path, and a fresh private folder per call.)

test('review 8: gh is only found on absolute PATH entries, so a planted ./gh is never used', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'git-bouncer-plant-'))
  try {
    const planted = join(dir, process.platform === 'win32' ? 'gh.exe' : 'gh')
    writeFileSync(planted, '#!/bin/sh\necho planted\n')
    chmodSync(planted, 0o755)
    assert.equal(await which('gh', { PATH: ['', '.', 'relative/bin'].join(delimiter), PATHEXT: '.EXE' }), null)
    const found = await which('gh', { PATH: dir, PATHEXT: '.EXE' })
    // Windows file names ignore case, and which() reports the extension as PATHEXT spells it.
    assert.equal(found?.toLowerCase(), planted.toLowerCase(), 'the same file is found from an absolute entry')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

// Prototype keys can't pose as listed names.
test('an owner called "constructor" or "toString" gets no special treatment', async () => {
  for (const name of ['constructor', 'toString', 'hasOwnProperty']) {
    const r = await check(`github.com/${name}/tool`, healthy(`${name}/tool`, { repo: { owner: { login: name, id: idFor(name) } } }))
    assert.ok(!r.ids.includes('ID-OWNER-CHANGED-HANDS'), name)
    assert.equal(r.verdict, 'pass', name)
  }
})
