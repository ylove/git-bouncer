import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { idCheck } from '../src/idcheck/index.js'
import { loadIocs, indexIocRepos, IOC_MODULE } from '../src/idcheck/known-bad.js'
import { NOW, daysAgo, ESC, RLO, ok, NOT_FOUND, RATE_LIMITED, owned, repoJson, accountJson, healthy, check, sev } from './helpers/idcheck-stubs.js'

// Unit tests never touch the network: every GitHub API answer is a stub (see helpers/idcheck-stubs.js).

// --- The acceptance criteria from issue #2 -----------------------------------------------------------

test('micr0s0ft/vscode is turned away at the ID check, even though the repo does not exist', async () => {
  const r = await check('github.com/micr0s0ft/vscode', { '/repos/micr0s0ft/vscode': NOT_FOUND })
  assert.equal(r.verdict, 'fail')
  assert.equal(sev(r, 'ID-LOOKALIKE-OWNER'), 'high')
  assert.match(r.byId['ID-LOOKALIKE-OWNER'].title, /"micr0s0ft" looks like "microsoft"/)
  assert.match(r.byId['ID-LOOKALIKE-OWNER'].detail, /impersonation of github\.com\/microsoft\/vscode/)
  assert.equal(sev(r, 'ID-NOT-FOUND'), 'high')
  assert.equal(r.complete, true, 'nothing more applies to a repo that does not exist')
  assert.deepEqual(r.calls, ['/repos/micr0s0ft/vscode'], 'stops asking once the repo is known not to exist')
})

test('the look-alike check needs no network: it still turns the repo away when GitHub is unreachable', async () => {
  const r = await check('github.com/micr0s0ft/vscode', { '/repos/micr0s0ft/vscode': new Error('getaddrinfo ENOTFOUND api.github.com') })
  assert.equal(r.verdict, 'fail')
  assert.equal(r.complete, false)
  assert.equal(r.ids[0], 'ID-LOOKALIKE-OWNER', 'the name checks come first')
  assert.equal(sev(r, 'ID-API-UNAVAILABLE'), 'low')
  assert.match(r.byId['ID-API-UNAVAILABLE'].detail, /couldn't reach the GitHub API/)
})

test('microsoft/vscode passes', async () => {
  const r = await check('github.com/microsoft/vscode', healthy('microsoft/vscode', {
    org: { is_verified: true, blog: 'https://opensource.microsoft.com' }, release: ok({ tag_name: '1.148.0', published_at: daysAgo(2) }),
  }))
  assert.equal(r.verdict, 'pass')
  assert.equal(r.complete, true)
  assert.deepEqual(r.ids, ['ID-VERIFIED-ORG', 'ID-LATEST-RELEASE'])
  assert.equal(r.facts.verifiedOrg, true)
  assert.equal(r.facts.orgWebsite, 'https://opensource.microsoft.com')
  assert.equal(r.facts.latestRelease, '1.148.0')
  assert.equal(r.facts.ownerType, 'Organization')
  assert.equal(r.facts.stars, 5000)
  assert.equal(r.facts.defaultBranch, 'main')
  assert.equal(r.facts.repoAgeDays, 3000)
})

test('facebook/react passes: GitHub redirects it to react/react, and the new "facebook" account is never consulted', async () => {
  // Real situation when this was written: the old "facebook" org is now "meta", React moved to the
  // "react" org, and a brand-new account holds the name "facebook". The redirect target is what you'd
  // clone, so its owner is the account that matters.
  const routes = {
    '/repos/facebook/react': ok(repoJson('react/react', { created_at: '2013-05-24T16:15:54Z' })),
    '/users/react': ok(accountJson('react', { created_at: '2009-07-08T09:38:38Z' })),
    '/orgs/react': ok({ login: 'react', is_verified: false }),
    '/repos/react/react/releases/latest': ok({ tag_name: 'v19.3.1', published_at: daysAgo(44) }),
  }
  const r = await check('github.com/facebook/react', routes)
  assert.equal(r.verdict, 'pass')
  assert.deepEqual(r.ids, ['ID-MOVED', 'ID-LATEST-RELEASE'])
  assert.equal(sev(r, 'ID-MOVED'), 'info', 'moved to an account git-bouncer knows, confirmed by its ID')
  assert.equal(r.facts.fullName, 'react/react')
  assert.ok(!r.calls.includes('/users/facebook'))
})

// --- Known-bad repos -----------------------------------------------------------------------------------

const CAMPAIGN = { campaign: 'Example campaign', source: 'https://example.com/report', repos: ['Carol-White-Super/cloud', 'stevenleedig-ux/axios-http'] }

test('a repo named in IOC reporting is critical, ignoring case', async () => {
  for (const path of ['Carol-White-Super/cloud', 'carol-white-super/CLOUD']) {
    const r = await check(`github.com/${path}`, { [`/repos/${path}`]: NOT_FOUND }, { iocs: [CAMPAIGN] })
    assert.equal(sev(r, 'ID-IOC-REPO'), 'critical', path)
    assert.match(r.byId['ID-IOC-REPO'].detail, /Example campaign.*https:\/\/example\.com\/report/)
    assert.equal(r.verdict, 'fail')
  }
})

test('another repo from an account named in IOC reporting is high', async () => {
  const r = await check('github.com/stevenleedig-ux/WinUI3_Home_Assessment', { '/repos/stevenleedig-ux/WinUI3_Home_Assessment': NOT_FOUND }, { iocs: [CAMPAIGN] })
  assert.equal(sev(r, 'ID-IOC-OWNER'), 'high')
  assert.ok(!r.ids.includes('ID-IOC-REPO'))
})

test('IOC repo names are github.com repos, so the same path on another host is not matched', async () => {
  const r = await check('gitlab.com/Carol-White-Super/cloud', {}, { iocs: [CAMPAIGN] })
  assert.ok(!r.ids.includes('ID-IOC-REPO'))
})

test('if the IOC snapshot is missing, the ID check is incomplete and says why', async () => {
  const r = await check('github.com/microsoft/vscode', healthy('microsoft/vscode'), { iocs: null })
  assert.equal(sev(r, 'ID-IOC-UNAVAILABLE'), 'low')
  assert.equal(r.complete, false)
  assert.equal(r.verdict, 'incomplete')
})

test('loadIocs returns null for a missing snapshot and loads a real module', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'git-bouncer-iocs-'))
  try {
    assert.equal(await loadIocs(pathToFileURL(join(dir, 'missing.js'))), null)
    const file = join(dir, 'iocs.mjs')
    writeFileSync(file, `export const IOC_SNAPSHOT_DATE = '2026-01-02'\nexport const IOCS = [${JSON.stringify(CAMPAIGN)}]\n`)
    const loaded = await loadIocs(pathToFileURL(file))
    assert.equal(loaded.date, '2026-01-02')
    assert.ok(indexIocRepos(loaded.campaigns).repos.has('carol-white-super/cloud'))
    writeFileSync(join(dir, 'broken.mjs'), 'export const IOCS = 42\n')
    await assert.rejects(loadIocs(pathToFileURL(join(dir, 'broken.mjs'))), /IOCS/, 'a broken snapshot is a bug, not a silent skip')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('the sandbox IOC snapshot is used by default', async () => {
  assert.ok(existsSync(fileURLToPath(IOC_MODULE)), 'sandbox/scanner/checks/iocs.js ships with git-bouncer')
  const snapshot = await loadIocs()
  const { repos } = indexIocRepos(snapshot.campaigns)
  const [first] = repos.values()
  const [owner, name] = first.repo.split('/')
  const r = await check(`github.com/${owner}/${name}`, { [`/repos/${owner}/${name}`]: NOT_FOUND }, { iocs: undefined })
  assert.equal(sev(r, 'ID-IOC-REPO'), 'critical')
  assert.equal(r.complete, true)
})

test('the IOC snapshot the host imports stays pure data: no imports, no I/O, no process access', () => {
  // The host executes this sandbox file (see the note at its top), so it must not grow side effects.
  const source = readFileSync(IOC_MODULE, 'utf8')
  const code = source.split('\n').filter(line => !line.trimStart().startsWith('//')).join('\n')
  for (const forbidden of [/^\s*import\b/m, /\bimport\s*\(/, /\brequire\s*\(/, /\bprocess\./, /\bglobalThis\b/, /\bfetch\s*\(/, /\beval\s*\(/, /\bFunction\s*\(/]) {
    assert.doesNotMatch(code, forbidden, `iocs.js must not use ${forbidden}`)
  }
})

// --- Impersonation and look-alike repo names --------------------------------------------------------------

test('a famous name under an unrelated owner, not a fork, is a warning', async () => {
  const r = await check('github.com/someone/react', healthy('someone/react', { owner: { type: 'User' } }))
  assert.equal(sev(r, 'ID-IMPERSONATION'), 'medium')
  assert.match(r.byId['ID-IMPERSONATION'].detail, /github\.com\/react\/react/)
  assert.equal(r.verdict, 'warn')
  // Case and separators don't make it a different name.
  const s = await check('github.com/someone/NextJS', healthy('someone/NextJS', { owner: { type: 'User' } }))
  assert.equal(sev(s, 'ID-IMPERSONATION'), 'medium')
})

test("a stranger's fork of the real project isn't impersonation, but it isn't the project either", async () => {
  for (const [parent, source] of [['react/react', 'react/react'], ['someone-else/react', 'react/react']]) {
    const r = await check('github.com/someone/react', healthy('someone/react', {
      repo: { fork: true, parent: owned(parent), source: owned(source) }, owner: { type: 'User' },
    }))
    assert.ok(!r.ids.includes('ID-IMPERSONATION'), `${parent} / ${source}`)
    assert.ok(!r.ids.includes('ID-FORK'), 'reported once, as a fork of a famous project')
    assert.equal(sev(r, 'ID-FORK-OF-FAMOUS'), 'low', 'an old account and an old fork')
    assert.equal(r.facts.forkParent, parent)
  }
})

test('a fork whose "parent" only has the right name, not the right account ID, is impersonation', async () => {
  const fakeParent = { full_name: 'react/react', owner: { login: 'react', id: 1 } }
  const r = await check('github.com/someone/react', healthy('someone/react', { repo: { fork: true, parent: fakeParent, source: fakeParent }, owner: { type: 'User' } }))
  assert.equal(sev(r, 'ID-IMPERSONATION'), 'medium')
})

test('a fork of something else with a famous name is still impersonation', async () => {
  const r = await check('github.com/someone/vscode', healthy('someone/vscode', {
    repo: { fork: true, parent: owned('attacker/vscode'), source: owned('attacker/vscode') }, owner: { type: 'User' },
  }))
  assert.equal(sev(r, 'ID-IMPERSONATION'), 'medium')
})

test('a famous name from another well-known owner is not impersonation', async () => {
  const r = await check('github.com/google/react', healthy('google/react'))
  assert.ok(!r.ids.includes('ID-IMPERSONATION'))
})

test('impersonation is still reported when GitHub cannot say whether it is a fork', async () => {
  const r = await check('github.com/someone/ollama', { '/repos/someone/ollama': RATE_LIMITED })
  assert.equal(sev(r, 'ID-IMPERSONATION'), 'medium')
  assert.match(r.byId['ID-IMPERSONATION'].detail, /could not ask GitHub whether it is a fork/)
  assert.match(r.byId['ID-API-UNAVAILABLE'].detail, /whether it is a fork of the original/)
  assert.equal(r.verdict, 'incomplete')
})

test('a famous repo name disguised with look-alike characters is turned away', async () => {
  const r = await check('github.com/someone/vsc0de', healthy('someone/vsc0de', { owner: { type: 'User' } }))
  assert.equal(sev(r, 'ID-LOOKALIKE-REPO'), 'high')
  assert.match(r.byId['ID-LOOKALIKE-REPO'].detail, /github\.com\/microsoft\/vscode/)
  assert.equal(r.verdict, 'fail')
})

test('a repo name one typo from a famous one is only context, because real repos are named like that', async () => {
  for (const [name, famous] of [['vscodee', 'vscode'], ['flasky', 'flask'], ['transformer', 'transformers']]) {
    const r = await check(`github.com/someone/${name}`, healthy(`someone/${name}`, { owner: { type: 'User' } }))
    assert.equal(sev(r, 'ID-SIMILAR-REPO'), 'low', name)
    assert.match(r.byId['ID-SIMILAR-REPO'].title, new RegExp(`"${famous}"`))
    assert.equal(r.verdict, 'pass', name)
  }
})

test('version suffixes and ordinary names are not look-alikes', async () => {
  for (const name of ['tensorflow2', 'react18', 'take-home-test', 'my-portfolio', 'dexTrader']) {
    const r = await check(`github.com/someone/${name}`, healthy(`someone/${name}`, { owner: { type: 'User' } }))
    assert.ok(!r.ids.some(id => /LOOKALIKE|SIMILAR|IMPERSONATION/.test(id)), `${name}: ${r.ids}`)
  }
  const r = await check('github.com/microsoft/vsc0de', healthy('microsoft/vsc0de'))
  assert.ok(!r.ids.includes('ID-LOOKALIKE-REPO'), "a well-known owner's own repo names are its business")
})

// --- Reputation ---------------------------------------------------------------------------------------------

test('a brand-new owner account and a brand-new repo are warnings, not failures', async () => {
  const r = await check('github.com/acme-hiring/take-home', healthy('acme-hiring/take-home', {
    repo: { created_at: daysAgo(2) }, owner: { created_at: daysAgo(5), type: 'User' }, release: NOT_FOUND,
  }))
  assert.equal(sev(r, 'ID-NEW-OWNER'), 'medium')
  assert.equal(sev(r, 'ID-NEW-REPO'), 'medium')
  assert.match(r.byId['ID-NEW-REPO'].detail, /take-home tests/)
  assert.match(r.byId['ID-NEW-OWNER'].detail, /not proof/)
  assert.equal(r.verdict, 'warn')
  assert.equal(r.facts.latestRelease, null)
})

test('age thresholds: owner under 30 days, repo under 14 days', async () => {
  const at = async (ownerDays, repoDays) => (await check('github.com/acme/tool', healthy('acme/tool', {
    repo: { created_at: daysAgo(repoDays) }, owner: { created_at: daysAgo(ownerDays) },
  }))).ids
  assert.ok((await at(29, 100)).includes('ID-NEW-OWNER'))
  assert.ok(!(await at(30, 100)).includes('ID-NEW-OWNER'))
  assert.ok((await at(400, 13)).includes('ID-NEW-REPO'))
  assert.ok(!(await at(400, 14)).includes('ID-NEW-REPO'))
  // A creation date in the future (a clock that's behind) counts as brand new, not as negative age.
  assert.ok((await at(-3, 100)).includes('ID-NEW-OWNER'))
})

test('archived and forked repos are reported as context', async () => {
  const r = await check('github.com/acme/old-tool', healthy('acme/old-tool', { repo: { archived: true, fork: true, parent: owned('upstream/old-tool') } }))
  assert.equal(sev(r, 'ID-ARCHIVED'), 'low')
  assert.equal(sev(r, 'ID-FORK'), 'info')
  assert.match(r.byId['ID-FORK'].title, /upstream\/old-tool/)
  assert.equal(r.verdict, 'pass')
})

test('lots of stars, almost no forks, on a young repo is a weak "bought stars" signal', async () => {
  const at = async (stars, forks, ageDays) => (await check('github.com/acme/tool', healthy('acme/tool', {
    repo: { stargazers_count: stars, forks_count: forks, created_at: daysAgo(ageDays) },
  }))).byId['ID-STARS-UNUSUAL']?.severity
  assert.equal(await at(3000, 4, 40), 'low')
  assert.equal(await at(3000, 40, 40), undefined, 'a normal fork ratio')
  assert.equal(await at(150, 0, 40), undefined, 'too few stars to judge')
  assert.equal(await at(3000, 4, 900), undefined, 'old repos: fake stars only pay off for a couple of months')
})

// --- When GitHub says no ------------------------------------------------------------------------------------

test('a private repo is not checked: git-bouncer only scans public repos', async () => {
  const r = await check('github.com/acme/secret', { '/repos/acme/secret': ok(repoJson('acme/secret', { private: true, visibility: 'private' })) })
  assert.equal(sev(r, 'ID-NOT-FOUND'), 'high')
  assert.match(r.byId['ID-NOT-FOUND'].detail, /private/)
})

test('a repo GitHub has blocked or disabled is turned away, not mistaken for a rate limit', async () => {
  for (const answer of [
    { status: 451, json: { message: 'Repository access blocked', block: { reason: 'dmca' } } },
    { status: 403, json: { message: 'Repository access blocked', block: { reason: 'tos' } } },
    ok(repoJson('acme/tool', { disabled: true })),
  ]) {
    const r = await check('github.com/acme/tool', { '/repos/acme/tool': answer })
    assert.equal(sev(r, 'ID-BLOCKED'), 'high', JSON.stringify(answer))
    assert.ok(!r.ids.includes('ID-API-UNAVAILABLE'))
  }
})

test('rate limits, server errors and network failures make the ID check incomplete, never a pass', async () => {
  for (const [answer, says] of [
    [RATE_LIMITED, /rate-limiting.*gh auth login/],
    [{ status: 429, json: null }, /rate-limiting/],
    [{ status: 500, json: { message: 'Server Error' } }, /HTTP 500/],
    [{ status: 401, json: { message: 'Bad credentials' } }, /gh auth login/],
    [{ status: 200, json: null }, /unexpected answer/],
    [new Error('socket hang up'), /couldn't reach/],
  ]) {
    const r = await check('github.com/acme/tool', { '/repos/acme/tool': answer })
    assert.deepEqual(r.ids, ['ID-API-UNAVAILABLE'], String(says))
    assert.equal(sev(r, 'ID-API-UNAVAILABLE'), 'low')
    assert.match(r.byId['ID-API-UNAVAILABLE'].detail, says)
    assert.match(r.byId['ID-API-UNAVAILABLE'].detail, /whether the repo exists/)
    assert.equal(r.complete, false)
    assert.equal(r.verdict, 'incomplete')
  }
})

test('if only the follow-up requests fail, the result lists exactly what was skipped', async () => {
  const routes = healthy('acme/tool')
  routes['/users/acme'] = RATE_LIMITED
  routes['/repos/acme/tool/releases/latest'] = new Error('timeout')
  delete routes['/orgs/acme']
  const r = await check('github.com/acme/tool', routes)
  assert.deepEqual(r.ids, ['ID-API-UNAVAILABLE'])
  assert.match(r.byId['ID-API-UNAVAILABLE'].detail, /how old the owner account is; the latest release/)
  assert.equal(r.verdict, 'incomplete')
})

// --- Other hosts and untrusted text ---------------------------------------------------------------------

test('other hosts get the name checks only, and the result says so', async () => {
  const plain = await check('codeberg.org/someone/tool')
  assert.deepEqual(plain.ids, ['ID-REDUCED'])
  assert.equal(plain.verdict, 'pass')
  assert.equal(plain.complete, true, 'the reduced scope is stated, not a failure someone can cause')
  assert.equal(plain.calls.length, 0, 'the GitHub API is never asked about another host')

  const famous = await check('gitlab.com/torvalds/linux')
  assert.equal(sev(famous, 'ID-IMPERSONATION'), 'medium', 'a famous owner name means nothing on another host')
  assert.match(famous.byId['ID-IMPERSONATION'].detail, /github\.com\/torvalds\/linux/)

  const lookalike = await check('gitlab.com/micr0s0ft/tools')
  assert.equal(sev(lookalike, 'ID-LOOKALIKE-OWNER'), 'high')
  assert.equal(lookalike.verdict, 'fail')
})

test('text that comes from the API is cleaned before it reaches a finding or a fact', async () => {
  const r = await check('github.com/acme/tool', healthy('acme/tool', {
    repo: { default_branch: `main${ESC}[2K`, fork: true, parent: owned(`up${ESC}]8;;https://evil.example/${ESC}\\stream/tool`) },
    release: ok({ tag_name: `v1.0${ESC}[1A${RLO}`, published_at: daysAgo(1) }),
    org: { is_verified: true, blog: `https://acme.example${ESC}[2J` },
  }))
  const unsafe = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(0x1f)}${String.fromCharCode(0x7f)}-${String.fromCharCode(0x9f)}${RLO}]`)
  const strings = [...r.findings.flatMap(f => Object.values(f)), ...Object.values(r.facts)].filter(v => typeof v === 'string')
  for (const text of strings) assert.doesNotMatch(text, unsafe, text)
  assert.match(r.byId['ID-FORK'].title, /up<ESC>stream\/tool/)
  assert.equal(r.facts.defaultBranch, 'main<ESC>')
  assert.equal(r.facts.latestRelease, 'v1.0<ESC><U+202E>')
  assert.equal(r.facts.orgWebsite, 'https://acme.example<ESC>')
})

test('a malformed target is a programming error', async () => {
  await assert.rejects(idCheck({}, { api: async () => NOT_FOUND }), TypeError)
  await assert.rejects(idCheck(null), TypeError)
})

test('every finding ID the ID check can produce is documented in docs/id-check.md', () => {
  const source = readFileSync(new URL('../src/idcheck/index.js', import.meta.url), 'utf8')
  const docs = readFileSync(new URL('../docs/id-check.md', import.meta.url), 'utf8')
  const ids = new Set(source.match(/'ID-[A-Z-]+'/g).map(s => s.slice(1, -1)))
  assert.ok(ids.size >= 21)
  for (const id of ids) assert.match(docs, new RegExp(`\\| \`${id}\` \\|`), `${id} is missing from the findings table`)
})
