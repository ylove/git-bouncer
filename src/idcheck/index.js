// The ID check: does this repository's identity hold up, before a single byte of it is downloaded?
//
// It runs on your machine, in this order:
//  1. Offline: is the owner or repo name a look-alike of a well-known one? (micr0s0ft/vscode)
//  2. Offline: is the repo, or its owner, named in public malware reporting?
//  3. GitHub API: is the account behind a well-known name still the well-known one? Does a famous
//     project name come from its real owner, or from a fork of it?
//  4. GitHub API: reputation context. Does it exist, how old are the account and the repo, is it a
//     fork, is it archived, does the organization have a verified domain, what's the latest release.
// Steps 1 and 2 need no network, so a disguised name is turned away even if the repo doesn't exist or
// GitHub can't be reached. Hosts other than github.com get steps 1 and 2 only, and the result says so.
//
// If GitHub redirects the repo (it was renamed or transferred), steps 1 to 3 run again on the name
// GitHub actually serves, because that's what git will download.
//
// Fail closed: findings start at their cautious severity, and only an answer from GitHub can soften
// them (a typo-style look-alike on a long-established account becomes a warning). If anything that
// applies couldn't be checked, the result says `complete: false`, and the verdict is "incomplete", not
// a pass. Findings have the same shape and severities as the sandbox scanner's (see src/verdict.js).
// Only a bug, such as a malformed target, throws, and src/run.js turns a crash into an error exit.

import { createMatcher, loose, stem, DISGUISE_KINDS, TYPO_KINDS } from './lookalike.js'
import { KNOWN_OWNERS, FAMOUS_REPOS, NOT_THE_REAL_ONE, KNOWN_NEIGHBOURS, LISTS_CHECKED } from './known.js'
import { loadIocs, indexIocRepos } from './known-bad.js'
import { githubApi } from './github-api.js'
import { clean } from '../ui/sanitize.js'

export const NEW_OWNER_DAYS = 30
export const NEW_REPO_DAYS = 14
// A typo-style look-alike name (androidx, gyoogle), or a stranger's fork of a famous repo, counts as a
// likely squat when the account or the fork is younger than this. Long-established accounts with a
// similar name are usually unrelated projects, so for them it's a warning instead of a failure.
export const YOUNG_DAYS = 90
// "Bought stars" heuristic: lots of stars, almost no forks, and a young repo. Fake stars are mostly
// used to promote short-lived malware repos, and boost a repo for about two months (He et al., "Six
// Million (Suspected) Fake Stars in GitHub", arXiv:2412.13459). It's a weak signal, so it's only "low".
const STARS_MIN = 200
const STARS_PER_FORK = 100
const STARS_MAX_AGE_DAYS = 180

const DAY_MS = 24 * 60 * 60 * 1000
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/
const GITHUB_FULL_NAME = /^([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})\/((?!\.{1,2}$)[A-Za-z0-9._-]{1,100})$/

// Lookups by name use Object.hasOwn, so an owner called "constructor" can't match Object.prototype.
const lookup = (table, name) => (Object.hasOwn(table, name.toLowerCase()) ? table[name.toLowerCase()] : undefined)
const OWNER_NAMES = [...Object.keys(KNOWN_OWNERS), ...Object.keys(NOT_THE_REAL_ONE)]
const findOwnerLookalike = createMatcher([...OWNER_NAMES, ...Object.keys(KNOWN_NEIGHBOURS)])
const findOwnerLookalikeStrict = createMatcher(OWNER_NAMES) // for a neighbour's name that changed hands
const findRepoLookalike = createMatcher(Object.keys(FAMOUS_REPOS))
const FAMOUS = new Map(Object.entries(FAMOUS_REPOS).map(([name, owners]) => [loose(name), {
  name, owners: owners.map(o => o.toLowerCase()), home: `${owners[0]}/${name}`,
}]))
// Brand names an untrusted organization shouldn't be able to borrow for a reassuring "verified" note.
const BRANDS = [...new Set(OWNER_NAMES.flatMap(n => [loose(n), stem(n, { glued: true })]))].filter(b => b.length >= 5)

// How a look-alike differs from the real name, in words.
const HOW = {
  separators: (name, real) => `"${name}" is "${real}" with extra "-", "_" or "." characters.`,
  characters: (name, real) => `"${name}" reads as "${real}" once look-alike characters are swapped back (0 for o, 1 for l or i, rn for m, vv for w, and so on).`,
  extra: (name, real) => `"${name}" is "${real}" with one extra character.`,
  missing: (name, real) => `"${name}" is "${real}" with one character missing.`,
  swapped: (name, real) => `"${name}" is "${real}" with two characters swapped.`,
  changed: (name, real) => `"${name}" is "${real}" with one character changed.`,
  'two-edits': (name, real) => `"${name}" is "${real}" with two characters different.`,
  stem: (name, real) => `"${name}" is the brand "${real}" with a word like "official", "labs" or "ai" added or left off.`,
}

/**
 * @param {{url: string, host: string, provider: string, owner: string, repo: string, path: string[], display: string}} target
 *   what parseRepoUrl() returns
 * @param {{api?: (path: string) => Promise<{status: number, json: any}>, now?: number,
 *          iocs?: Array<{campaign: string, source: string, repos?: string[]}>|null}} [opts]
 *   api: GitHub REST client (default: gh if signed in, else anonymous; see github-api.js).
 *   now: the current time in ms, for account and repo ages.
 *   iocs: campaigns to use instead of the IOC snapshot, same shape as its IOCS export; null acts as if
 *   the snapshot were missing. For tests.
 * @returns {Promise<{findings: Array<{id: string, severity: string, title: string, detail: string, evidence?: string}>,
 *                    facts: Record<string, string|number|boolean|null>, complete: boolean}>}
 *   complete: false when any check that applies couldn't run (the API was unreachable or rate-limited,
 *   or the IOC snapshot is missing). Pass it to computeVerdict(), so that the verdict is "incomplete".
 */
export async function idCheck(target, { api, now = Date.now(), iocs } = {}) {
  if (!target || typeof target.owner !== 'string' || typeof target.repo !== 'string' || typeof target.provider !== 'string') {
    throw new TypeError('idCheck needs the object returned by parseRepoUrl().')
  }
  const { owner, repo, host } = target
  const findings = []
  const facts = {}
  const shown = new Set()
  const add = (id, severity, title, detail, evidence) => {
    if (shown.has(`${id}\n${title}`)) return // the same finding for the typed and the redirected name
    shown.add(`${id}\n${title}`)
    findings.push(evidence ? { id, severity, title, detail, evidence } : { id, severity, title, detail })
  }
  // Offline, a listed name is trusted by name. Online, only if GitHub confirms it's the same account (ID).
  const trustedByName = lookup(KNOWN_OWNERS, owner) !== undefined

  // Hosts other than GitHub: names only. Account names there aren't GitHub's, so nothing is trusted.
  if (target.provider !== 'github') {
    ownerNameFindings(add, owner, repo, { age: null })
    repoNameFindings(add, owner, repo, { trusted: false })
    const famous = FAMOUS.get(loose(repo))
    if (famous) {
      add('ID-IMPERSONATION', 'medium', `"${repo}" has the name of a famous project, but this copy is on ${host}`,
        `The well-known ${famous.name} is at github.com/${famous.home}. git-bouncer can't tell whether this one is an official mirror, a fork, or someone else's code with a borrowed name, so don't trust it because of its name.`,
        `official: github.com/${famous.home}`)
    }
    add('ID-REDUCED', 'info', `Reduced ID check: ${host} isn't GitHub`,
      `git-bouncer can only look up accounts and repositories on GitHub. For ${host} it checked the names (look-alikes and famous project names), but not whether the repo exists, how old it or its owner is, whether it's a fork, or the known-bad list (which names github.com repos). Account names on ${host} are separate from GitHub's: an owner called "microsoft" there isn't necessarily Microsoft.`)
    // Complete: everything that can be checked for this host was. The reduced scope is permanent and
    // stated above, not a failure someone can cause.
    return { findings, facts, complete: true }
  }

  // The known-bad list (offline).
  const snapshot = iocs === undefined ? await loadIocs() : iocs && { campaigns: iocs, date: null }
  const iocIndex = snapshot ? indexIocRepos(snapshot.campaigns) : null
  const iocAsOf = snapshot?.date ? ` (snapshot of ${snapshot.date})` : ''
  const checkIoc = (o, r, via) => iocNameFindings(add, iocIndex, iocAsOf, o, r, via)

  // The GitHub API.
  api ??= githubApi
  const unchecked = []
  let apiProblem = null
  const call = path => askGitHub(api, path)
  const notChecked = (res, ...what) => {
    apiProblem ??= res.problem ?? { reason: 'the GitHub API gave an unexpected answer' }
    unchecked.push(...what)
  }
  const finish = () => {
    if (!snapshot) {
      add('ID-IOC-UNAVAILABLE', 'low', 'The known-bad repo list could not be loaded',
        "git-bouncer's snapshot of repositories named in public malware reporting is missing from this install, so this repo wasn't compared against it. The ID check is incomplete.")
    }
    if (unchecked.length) {
      add('ID-API-UNAVAILABLE', 'low', 'Part of the ID check could not run',
        `Because ${apiProblem.reason}, these weren't checked: ${unchecked.join('; ')}. The name checks still ran, but the ID check is incomplete.${apiProblem.hint ? ` ${apiProblem.hint}` : ''}`)
    }
    return { findings, facts, complete: Boolean(snapshot) && unchecked.length === 0 }
  }

  const repoRes = await call(`/repos/${owner}/${repo}`)
  const isPrivate = repoRes.ok && (repoRes.json.private === true || (repoRes.json.visibility && repoRes.json.visibility !== 'public'))
  if (repoRes.notFound || isPrivate) {
    ownerNameFindings(add, owner, repo, { age: null })
    repoNameFindings(add, owner, repo, { trusted: trustedByName })
    checkIoc(owner, repo)
    add('ID-NOT-FOUND', 'high', isPrivate ? `${owner}/${repo} is not a public repository` : `There is no public repository at github.com/${owner}/${repo}`,
      isPrivate
        ? 'Your GitHub login can see it, but it is private. git-bouncer only checks public repositories, because checking a private one would mean putting your credentials into the sandbox.'
        : 'It may be private, deleted, or never have existed. git-bouncer only checks public repositories. If someone sent you this link, check it with them through a channel you already trust.')
    return finish()
  }
  if (repoRes.blocked || (repoRes.ok && repoRes.json.disabled === true)) {
    ownerNameFindings(add, owner, repo, { age: null })
    repoNameFindings(add, owner, repo, { trusted: trustedByName })
    checkIoc(owner, repo)
    const reason = typeof repoRes.block?.reason === 'string' ? ` (reason given: ${clean(repoRes.block.reason, { max: 40 })})` : ''
    add('ID-BLOCKED', 'high', `GitHub has blocked or disabled ${owner}/${repo}`,
      `GitHub itself has taken this repository down${reason}. That happens for legal reasons, and also when GitHub finds malware or abuse. Don't get its code from anywhere else either.`)
    return finish()
  }
  if (!repoRes.ok) {
    // Nothing from GitHub, so nothing is softened: the names get their cautious severity.
    const famous = FAMOUS.get(loose(repo))
    notChecked(repoRes, 'whether the repo exists and is public',
      ...(trustedByName ? ['whether the account behind the name is still the one git-bouncer knows'] : []),
      ...(famous && !trustedByName ? ['whether it is a fork of the original'] : []),
      'how old the repo and its owner account are', 'stars, forks, archived status and releases')
    ownerNameFindings(add, owner, repo, { age: null })
    const former = lookup(NOT_THE_REAL_ONE, owner)
    if (former) add('ID-LOOKALIKE-OWNER', 'medium', `The account "${owner}" isn't who the name suggests`, `${former.why} (As of ${LISTS_CHECKED}.) Make sure this is really who you meant.`, `"${owner}"`)
    repoNameFindings(add, owner, repo, { trusted: trustedByName })
    checkIoc(owner, repo)
    if (famous && !trustedByName) impersonation(add, owner, repo, famous, ' git-bouncer could not ask GitHub whether it is a fork of the original.')
    return finish()
  }

  // What GitHub actually serves. After a rename or transfer, that's a different name than the link's.
  const r = repoRes.json
  const fullName = typeof r.full_name === 'string' && GITHUB_FULL_NAME.test(r.full_name) ? r.full_name : `${owner}/${repo}`
  const [servedOwner, servedRepo] = fullName.split('/')
  const servedId = Number.isSafeInteger(r.owner?.id) ? r.owner.id : null
  const ownerChanged = servedOwner.toLowerCase() !== owner.toLowerCase()
  const moved = fullName.toLowerCase() !== `${owner}/${repo}`.toLowerCase()
  const pinned = lookup(KNOWN_OWNERS, servedOwner)
  const neighbour = lookup(KNOWN_NEIGHBOURS, servedOwner)
  const former = lookup(NOT_THE_REAL_ONE, servedOwner)
  if ((pinned !== undefined || neighbour !== undefined || former?.formerId) && servedId === null) {
    notChecked({ problem: { reason: 'the GitHub API left out the account ID' } }, 'whether the account behind the name is the one git-bouncer knows')
  }
  const servedTrusted = pinned !== undefined && servedId === pinned
  const changedHands = servedId !== null && ((pinned !== undefined && servedId !== pinned) || (former?.formerId && servedId !== former.formerId))
  const neighbourChanged = neighbour !== undefined && servedId !== null && servedId !== neighbour
  facts.fullName = fullName
  facts.ownerId = servedId

  const [ownerRes, releaseRes] = await Promise.all([
    call(`/users/${servedOwner}`),
    call(`/repos/${servedOwner}/${servedRepo}/releases/latest`),
  ])
  let ownerAge = null
  let login = servedOwner
  if (ownerRes.ok) {
    const o = ownerRes.json
    login = typeof o.login === 'string' && GITHUB_OWNER.test(o.login) ? o.login : servedOwner
    const created = parseDate(o.created_at)
    ownerAge = created === null ? null : ageDays(created, now)
    facts.ownerType = o.type === 'Organization' ? 'Organization' : o.type === 'User' ? 'User' : null
    facts.ownerCreatedAt = created === null ? null : isoDate(created)
    facts.ownerAgeDays = ownerAge
  } else {
    notChecked(ownerRes, 'how old the owner account is')
  }
  let org = null
  if (facts.ownerType === 'Organization') {
    const orgRes = await call(`/orgs/${login}`)
    if (orgRes.ok) org = orgRes.json
    else notChecked(orgRes, 'whether the organization has a verified domain')
  }

  // 1 and 2 again, now with what GitHub said. The link's name first, then the served one if different.
  ownerNameFindings(add, owner, repo, { age: ownerChanged ? null : ownerAge, strict: !ownerChanged && neighbourChanged })
  if (ownerChanged) ownerNameFindings(add, servedOwner, servedRepo, { age: ownerAge, strict: neighbourChanged, via: `${owner}/${repo}` })
  if (changedHands) {
    const why = former && !pinned ? ` ${former.why}` : ''
    add('ID-OWNER-CHANGED-HANDS', 'high', `The name "${servedOwner}" now belongs to a different account`,
      `"${servedOwner}" is a well-known name on git-bouncer's list, but GitHub says the account holding it now is a different one (account ID ${servedId}, not ${pinned ?? former.formerId}, as of ${LISTS_CHECKED}).${why} Names on GitHub can be renamed, given up, and registered again by anyone. Don't trust this repo because of the name.`,
      `account ID ${servedId}, expected ${pinned ?? former.formerId}`)
  } else if (former && !former.formerId) {
    add('ID-LOOKALIKE-OWNER', 'medium', `The account "${servedOwner}" isn't who the name suggests`, `${former.why} Make sure this is really who you meant.`, `"${servedOwner}"`)
  }
  repoNameFindings(add, owner, repo, { trusted: ownerChanged ? trustedByName : servedTrusted })
  if (moved) repoNameFindings(add, servedOwner, servedRepo, { trusted: servedTrusted, via: `${owner}/${repo}` })
  checkIoc(owner, repo)
  if (moved) checkIoc(servedOwner, servedRepo, `${owner}/${repo}`)

  if (moved) {
    if (ownerChanged && !servedTrusted) {
      add('ID-MOVED', 'medium', `GitHub redirects ${owner}/${repo} to a different account: ${fullName}`,
        `The link names "${owner}", but the repository now belongs to "${servedOwner}", and git will download it from there. Repositories get transferred for good reasons, but a redirect can also hide where code really comes from. The checks in this report are about ${fullName}.`,
        `${owner} -> ${servedOwner}`)
    } else {
      add('ID-MOVED', 'info', `GitHub redirects ${owner}/${repo} to ${fullName}`,
        `The repository was renamed${ownerChanged ? ` or moved to ${servedOwner}, an account git-bouncer knows` : ''}. git follows the redirect, so you'd get ${fullName}, and the checks in this report are about that repository.`,
        fullName)
    }
  }

  // 3. A famous name that isn't the real project: impersonation, or a stranger's fork of it.
  const repoCreated = parseDate(r.created_at)
  const repoAge = repoCreated === null ? null : ageDays(repoCreated, now)
  const famous = FAMOUS.get(loose(repo)) ?? FAMOUS.get(loose(servedRepo))
  let forkReported = false
  if (famous && !servedTrusted) {
    const isTheReal = obj => {
      const m = typeof obj?.full_name === 'string' && GITHUB_FULL_NAME.exec(obj.full_name)
      return Boolean(m) && famous.owners.includes(m[1].toLowerCase()) && loose(m[2]) === loose(famous.name) &&
        obj.owner?.id === lookup(KNOWN_OWNERS, m[1])
    }
    const realOrigin = r.fork === true ? [r.parent, r.source].find(isTheReal) : null
    if (realOrigin) {
      forkReported = true
      const young = repoAge === null || repoAge < YOUNG_DAYS || ownerAge === null || ownerAge < YOUNG_DAYS
      add('ID-FORK-OF-FAMOUS', young ? 'medium' : 'low', `This is someone else's fork of ${clean(realOrigin.full_name, { max: 200 })}`,
        `"${servedOwner}" copied the real ${famous.name} into their own account. GitHub shows "forked from ${clean(realOrigin.full_name, { max: 200 })}" under it, but that isn't an endorsement: the fork's owner can change any of its code, and the original's maintainers never review it.${young ? ' The fork or its account is new, which is how borrowed-name malware usually looks.' : ''} If you wanted the real project, use https://github.com/${famous.home}.`,
        `fork of ${clean(realOrigin.full_name, { max: 200 })}`)
    } else {
      impersonation(add, servedOwner, servedRepo, famous, '')
    }
  }

  // 4. Reputation context.
  const stars = count(r.stargazers_count)
  const forks = count(r.forks_count)
  Object.assign(facts, {
    repoCreatedAt: repoCreated === null ? null : isoDate(repoCreated),
    repoAgeDays: repoAge,
    stars,
    forks,
    defaultBranch: typeof r.default_branch === 'string' ? clean(r.default_branch, { max: 200 }) : null,
    archived: r.archived === true,
    fork: r.fork === true,
  })
  if (r.fork === true) {
    const parent = typeof r.parent?.full_name === 'string' ? clean(r.parent.full_name, { max: 200 }) : null
    const source = typeof r.source?.full_name === 'string' ? clean(r.source.full_name, { max: 200 }) : null
    facts.forkParent = parent
    const origin = source && parent && source.toLowerCase() !== parent.toLowerCase() ? ` (which is itself a fork of ${source})` : ''
    if (!forkReported) {
      add('ID-FORK', 'info', parent ? `This repo is a fork of ${parent}` : 'This repo is a fork',
        `A fork starts as a copy of another repo${origin}, but its owner can change anything in it, so it doesn't inherit the original's reputation. The sandbox scan looks at this copy's actual content.`,
        parent ?? undefined)
    }
  }
  if (r.archived === true) {
    add('ID-ARCHIVED', 'low', 'The repo is archived',
      "Its owner has made it read-only: nobody is maintaining it or fixing problems in it anymore. That isn't an attack by itself, but it's worth knowing before you build on it.")
  }
  if (repoAge !== null && repoAge < NEW_REPO_DAYS) {
    add('ID-NEW-REPO', 'medium', `The repo was created ${daysAgo(repoAge)}`,
      `${fullName} was created on ${isoDate(repoCreated)}. Malicious repos are almost always new, but so are most real take-home tests, so this is a warning, not proof. Ask yourself whether you trust whoever sent you the link.`,
      `created ${isoDate(repoCreated)}`)
  }
  if (stars !== null && forks !== null && repoAge !== null && stars >= STARS_MIN && forks * STARS_PER_FORK < stars && repoAge < STARS_MAX_AGE_DAYS) {
    add('ID-STARS-UNUSUAL', 'low', `${stars} stars but only ${forks} fork${forks === 1 ? '' : 's'}, on a ${repoAge}-day-old repo`,
      'Stars can be bought, and fake stars rarely come with forks. Researchers found millions of suspected fake stars on GitHub, mostly promoting short-lived malware repos. This is a weak signal, not proof, but don\'t let the star count be the reason you trust this repo.',
      `${stars} stars, ${forks} forks`)
  }
  if (ownerAge !== null && ownerAge < NEW_OWNER_DAYS) {
    add('ID-NEW-OWNER', 'medium', `The account "${login}" was created ${daysAgo(ownerAge)}`,
      `"${login}" has existed since ${facts.ownerCreatedAt}. Brand-new accounts are how most throwaway malware repos get published, but real recruiters, bootcamps and take-home tests use fresh accounts too, so this is a warning, not proof. Check who sent you the link and whether the account has any history.`,
      `created ${facts.ownerCreatedAt}`)
  }
  if (org) {
    facts.verifiedOrg = org.is_verified === true
    const website = typeof org.blog === 'string' && org.blog ? clean(org.blog, { max: 200 }) : null
    const displayName = typeof org.name === 'string' ? org.name : ''
    facts.orgWebsite = website
    // A verified domain proves who controls the account, not that it's the brand its name suggests
    // ("openai-labs" verified a domain that has nothing to do with OpenAI). So the note is only shown
    // when the name doesn't borrow a well-known brand the account doesn't own.
    const borrowsBrand = !servedTrusted && BRANDS.some(b => loose(login).includes(b) || loose(displayName).includes(b))
    if (facts.verifiedOrg && !borrowsBrand) {
      add('ID-VERIFIED-ORG', 'info', `"${login}" is a verified organization`,
        `GitHub marks it as verified, which means it proved it controls a web domain. Its listed website is ${website ?? 'not given'}. Check which domain is verified on https://github.com/${login}: it should be the domain you'd expect for this publisher. Any organization can verify a domain it owns, so this tells you who runs the account, not whether to trust its code.`,
        website ?? undefined)
    }
  }
  if (releaseRes.ok) {
    const tag = typeof releaseRes.json.tag_name === 'string' ? clean(releaseRes.json.tag_name, { max: 100 }) : null
    const published = parseDate(releaseRes.json.published_at)
    facts.latestRelease = tag
    facts.latestReleaseAt = published === null ? null : isoDate(published)
    if (tag) {
      add('ID-LATEST-RELEASE', 'info', `Latest release: ${tag}`,
        `${published === null ? 'The newest release' : `Published ${isoDate(published)}`}. If you were told to use a particular version, compare it with this one.`,
        tag)
    }
  } else if (releaseRes.notFound) {
    facts.latestRelease = null // no releases: normal for small projects and take-home tests
  } else {
    notChecked(releaseRes, 'the latest release')
  }
  return finish()
}

/** Ask the API, and sort the answer into ok / not found / blocked / a problem that means "not checked". */
async function askGitHub(api, path) {
  let res
  try {
    res = await api(path)
  } catch {
    return { ok: false, problem: { reason: "git-bouncer couldn't reach the GitHub API" } }
  }
  const status = res && Number.isInteger(res.status) ? res.status : 0
  const json = res && res.json && typeof res.json === 'object' ? res.json : null
  if (status === 200 && json) return { ok: true, json }
  if (status === 404) return { ok: false, notFound: true }
  if ((status === 403 || status === 451) && json && (json.block || json.message === 'Repository access blocked')) return { ok: false, blocked: true, block: json.block }
  if (status === 429 || (status === 403 && json && /rate limit/i.test(String(json.message)))) {
    return { ok: false, problem: { reason: 'the GitHub API is rate-limiting requests from your network', hint: 'Anonymous requests are limited to 60 an hour, and any web page you visit can use them up. Signing in with "gh auth login" raises the limit, and git-bouncer then asks through gh, so it never sees your token.' } }
  }
  if (status === 401) return { ok: false, problem: { reason: 'GitHub rejected your gh login', hint: 'Run "gh auth login" again.' } }
  return { ok: false, problem: { reason: status && status !== 200 ? `the GitHub API answered with HTTP ${status}` : 'the GitHub API gave an unexpected answer' } }
}

/**
 * Is the owner name a look-alike of a well-known one, or named after a famous project?
 * Typo-style matches are only softened to a warning when GitHub says the account is long-established.
 * @param {{age: number|null, strict?: boolean, via?: string}} opts
 *   age: the account's age in days, when GitHub said and it's the same account; null = unknown.
 *   strict: ignore the neighbours list (the neighbour's name now belongs to someone else).
 *   via: the link's owner/repo, when this is the name GitHub redirected to.
 */
function ownerNameFindings(add, login, repo, { age, strict = false, via }) {
  let look = (strict ? findOwnerLookalikeStrict : findOwnerLookalike)(login)
  if (!look && lookup(KNOWN_OWNERS, login) === undefined && lookup(NOT_THE_REAL_ONE, login) === undefined) {
    const project = FAMOUS.get(loose(login)) ?? FAMOUS.get(stem(login))
    if (project && !project.owners.includes(login.toLowerCase())) look = { match: project.name, kind: 'project', project }
  }
  if (!look) return
  const real = look.match
  const after = via ? ` (GitHub redirects ${via} there)` : ''
  const evidence = `"${login}" vs "${real}"`
  if (look.kind === 'project') {
    add('ID-LOOKALIKE-OWNER', 'medium', `The owner "${login}" is named after the famous project ${real}${after}`,
      `${real} is published by github.com/${look.project.home}. An account named after a famous project isn't necessarily its maintainers. Make sure "${login}" is really who you meant.`, evidence)
    return
  }
  const famous = FAMOUS.get(loose(repo))
  const disguised = DISGUISE_KINDS.includes(look.kind)
  const typo = TYPO_KINDS.includes(look.kind)
  const old = age !== null && age >= YOUNG_DAYS
  if (disguised || (typo && !old)) {
    const ageNote = typo ? (age === null ? " git-bouncer couldn't check how old the account is." : ` The account is only ${age} day${age === 1 ? '' : 's'} old.`) : ''
    const repoToo = famous && famous.owners.includes(real.toLowerCase())
      ? ` And "${famous.name}" is the name of ${real}'s famous project, which makes this look like deliberate impersonation of github.com/${famous.home}.`
      : ''
    add('ID-LOOKALIKE-OWNER', 'high', `The owner "${login}" looks like "${real}", but it isn't${after}`,
      `${HOW[look.kind](login, real)}${ageNote} Look-alike account names are a common way to pass off malware as code from a publisher you trust.${repoToo} If you expected ${real}, find the repository from ${real}'s own website or documentation instead of from a link.`,
      evidence)
    return
  }
  const ageNote = old ? ` The account has existed for ${age} days, so it may well be an unrelated project with a similar name. Old accounts can also be bought or reused to look trustworthy, though.` : ''
  add('ID-LOOKALIKE-OWNER', 'medium', `The owner "${login}" looks like "${real}": check it's who you meant${after}`,
    `${HOW[look.kind](login, real)}${ageNote} Make sure "${login}" is really the publisher you meant, and not someone borrowing ${real}'s name.`,
    evidence)
}

/** Is the repo name a disguised or misspelled famous project name? Skipped for a trusted owner's repos. */
function repoNameFindings(add, owner, repo, { trusted, via }) {
  if (trusted || FAMOUS.has(loose(repo))) return // an exact famous name is the impersonation check's job
  const look = findRepoLookalike(repo)
  const real = look && FAMOUS.get(loose(look.match))
  // "tensorflow2" or "react18" is a version, not a disguise.
  if (!real || loose(repo).replace(/[0-9]+$/, '') === loose(real.name)) return
  const after = via ? ` (GitHub redirects ${via} there)` : ''
  if (look.kind === 'characters') {
    add('ID-LOOKALIKE-REPO', 'high', `The repo name "${repo}" is disguised to look like "${real.name}"${after}`,
      `${HOW.characters(repo, real.name)} Nobody types a famous project's name that way by accident. The real ${real.name} is github.com/${real.home}.`,
      `"${repo}" vs "${real.name}"`)
  } else {
    add('ID-SIMILAR-REPO', 'low', `The repo name "${repo}" is close to the famous "${real.name}"${after}`,
      `${HOW[look.kind](repo, real.name)} That can be an honest name, or a way to borrow a famous project's reputation. If you expected ${real.name}, the real one is github.com/${real.home}.`,
      `"${repo}" vs "${real.name}"`)
  }
}

/** Known-bad repos and accounts from public reporting. The reported names are github.com repos. */
function iocNameFindings(add, index, asOf, owner, repo, via) {
  if (!index) return
  const hit = index.repos.get(`${owner}/${repo}`.toLowerCase())
  const ownerHit = !hit && index.owners.get(owner.toLowerCase())
  const after = via ? ` (GitHub redirects ${via} there)` : ''
  if (hit) {
    add('ID-IOC-REPO', 'critical', `${owner}/${repo} is named in public malware reporting${after}`,
      `This exact repository is listed in reporting on the "${hit.campaign.campaign}" campaign${asOf}. Don't clone it, open it in an editor, or run anything from it. If someone sent it to you as a job task, that's how this campaign works. Source: ${hit.campaign.source}`,
      hit.campaign.source)
  } else if (ownerHit) {
    add('ID-IOC-OWNER', 'high', `The account "${owner}" published a repo named in public malware reporting${after}`,
      `${ownerHit.repo} is listed in reporting on the "${ownerHit.campaign.campaign}" campaign${asOf}. This is another repository from the same account. Accounts like this usually exist only to spread malware. Source: ${ownerHit.campaign.source}`,
      ownerHit.campaign.source)
  }
}

function impersonation(add, owner, repo, famous, extra) {
  add('ID-IMPERSONATION', 'medium', `"${repo}" has the name of a famous project, but this isn't it`,
    `The well-known ${famous.name} is github.com/${famous.home}. This one belongs to "${owner}" and isn't a GitHub fork of it, so it can contain anything.${extra} That's normal for a practice or tutorial repo, but don't trust it because of its name. If you wanted the real project, use https://github.com/${famous.home}.`,
    `official: github.com/${famous.home}`)
}

function parseDate(value) {
  if (typeof value !== 'string') return null
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}
const ageDays = (then, now) => Math.max(0, Math.floor((now - then) / DAY_MS)) // a clock that's behind can't make age negative
const isoDate = ms => new Date(ms).toISOString().slice(0, 10)
const daysAgo = days => (days === 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`)
const count = value => (Number.isSafeInteger(value) && value >= 0 ? value : null)
