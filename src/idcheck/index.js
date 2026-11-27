// The ID check: does this repository's identity hold up, before a single byte of it is downloaded?
//
// It runs on your machine, in this order:
//  1. Offline: is the owner or repo name a look-alike of a well-known one? (micr0s0ft/vscode)
//  2. Offline: is the repo named in public malware reporting?
//  3. GitHub API: does a famous project name come from its real owner, or a GitHub fork of it?
//  4. GitHub API: reputation context. Does it exist, how old are the account and the repo, is it a
//     fork, is it archived, does the organization have a verified domain, what's the latest release.
// Steps 1 and 2 need no network, so a look-alike is turned away even if the repo doesn't exist or
// GitHub can't be reached. Hosts other than github.com get steps 1 and 2 only, and the result says so.
//
// Findings have the same shape and severities as the sandbox scanner's (see src/verdict.js):
// critical/high turn the repo away, medium is a warning, low/info are context that never blocks.
// API failures (not found, rate limits, network errors) become findings that say what wasn't checked.
// Only a bug, such as a malformed target, throws, and src/run.js turns a crash into an error exit,
// never a pass.

import { createMatcher, loose } from './lookalike.js'
import { KNOWN_OWNERS, FAMOUS_REPOS } from './known.js'
import { loadIocs, indexIocRepos } from './known-bad.js'
import { githubApi } from './github-api.js'
import { clean } from '../ui/sanitize.js'

export const NEW_OWNER_DAYS = 30
export const NEW_REPO_DAYS = 14
// "Bought stars" heuristic: lots of stars, almost no forks, and a young repo. Fake stars are mostly
// used to promote short-lived malware repos, and boost a repo for about two months (He et al., "Six
// Million (Suspected) Fake Stars in GitHub", arXiv:2412.13459). It's a weak signal, so it's only "low".
const STARS_MIN = 200
const STARS_PER_FORK = 100
const STARS_MAX_AGE_DAYS = 180

const DAY_MS = 24 * 60 * 60 * 1000
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/
const GITHUB_FULL_NAME = /^([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})\/((?!\.{1,2}$)[A-Za-z0-9._-]{1,100})$/

const findOwnerLookalike = createMatcher(KNOWN_OWNERS)
const findRepoLookalike = createMatcher(Object.keys(FAMOUS_REPOS))
const KNOWN_OWNER_SET = new Set(KNOWN_OWNERS)
const FAMOUS = new Map(Object.entries(FAMOUS_REPOS).map(([name, owners]) => [loose(name), {
  name, owners: owners.map(o => o.toLowerCase()), home: `${owners[0]}/${name}`,
}]))

// How a look-alike differs from the real name, in words.
const HOW = {
  separators: (name, real) => `"${name}" is "${real}" with extra "-", "_" or "." characters.`,
  characters: (name, real) => `"${name}" reads as "${real}" once look-alike characters are swapped back (0 for o, 1 for l or i, rn for m, vv for w, and so on).`,
  extra: (name, real) => `"${name}" is "${real}" with one extra character.`,
  missing: (name, real) => `"${name}" is "${real}" with one character missing.`,
  swapped: (name, real) => `"${name}" is "${real}" with two characters swapped.`,
  changed: (name, real) => `"${name}" is "${real}" with one character changed.`,
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
 *                    facts: Record<string, string|number|boolean|null>}>}
 */
export async function idCheck(target, { api, now = Date.now(), iocs } = {}) {
  if (!target || typeof target.owner !== 'string' || typeof target.repo !== 'string' || typeof target.provider !== 'string') {
    throw new TypeError('idCheck needs the object returned by parseRepoUrl().')
  }
  const findings = []
  const facts = {}
  const add = (id, severity, title, detail, evidence) => findings.push(evidence ? { id, severity, title, detail, evidence } : { id, severity, title, detail })
  const { owner, repo, host } = target
  const onGitHub = target.provider === 'github'
  const famous = FAMOUS.get(loose(repo)) // a famous project's name, ignoring case and separators
  // Known owner names are GitHub accounts. On another host, the same name can belong to anyone.
  const ownerIsKnown = onGitHub && KNOWN_OWNER_SET.has(owner.toLowerCase())

  // 1. Look-alike names (offline).
  const ownerLook = findOwnerLookalike(owner)
  if (ownerLook) {
    const real = ownerLook.match
    const repoToo = famous && famous.owners.includes(real)
      ? ` And "${famous.name}" is the name of ${real}'s famous project, which makes this look like deliberate impersonation of github.com/${famous.home}.`
      : ''
    add('ID-LOOKALIKE-OWNER', 'high', `The owner "${owner}" looks like "${real}", but it isn't`,
      `${HOW[ownerLook.kind](owner, real)} Look-alike account names are a common way to pass off malware as code from a publisher you trust.${repoToo} If you expected ${real}, find the repository from ${real}'s own website or documentation instead of from a link.`,
      `"${owner}" vs "${real}"`)
  }
  if (!famous && !ownerIsKnown) {
    const repoLook = findRepoLookalike(repo)
    const real = repoLook && FAMOUS.get(loose(repoLook.match))
    // "tensorflow2" or "react18" is a version, not a disguise.
    if (real && loose(repo).replace(/[0-9]+$/, '') !== loose(real.name)) {
      if (repoLook.kind === 'characters') {
        add('ID-LOOKALIKE-REPO', 'high', `The repo name "${repo}" is disguised to look like "${real.name}"`,
          `${HOW.characters(repo, real.name)} Nobody types a famous project's name that way by accident. The real ${real.name} is github.com/${real.home}.`,
          `"${repo}" vs "${real.name}"`)
      } else {
        add('ID-SIMILAR-REPO', 'low', `The repo name "${repo}" is close to the famous "${real.name}"`,
          `${HOW[repoLook.kind](repo, real.name)} That can be an honest name, or a way to borrow a famous project's reputation. If you expected ${real.name}, the real one is github.com/${real.home}.`,
          `"${repo}" vs "${real.name}"`)
      }
    }
  }

  // 2. Known-bad repos from public reporting (offline). The reported names are github.com repos.
  if (onGitHub) {
    const snapshot = iocs === undefined ? await loadIocs() : iocs && { campaigns: iocs, date: null }
    if (!snapshot) {
      add('ID-IOC-UNAVAILABLE', 'low', 'The known-bad repo list could not be loaded',
        "git-bouncer's snapshot of repositories named in public malware reporting is missing from this install, so this repo wasn't compared against it. Every other check still ran.")
    } else {
      const index = indexIocRepos(snapshot.campaigns)
      const asOf = snapshot.date ? ` (snapshot of ${snapshot.date})` : ''
      const hit = index.repos.get(`${owner}/${repo}`.toLowerCase())
      const ownerHit = !hit && index.owners.get(owner.toLowerCase())
      if (hit) {
        add('ID-IOC-REPO', 'critical', `${owner}/${repo} is named in public malware reporting`,
          `This exact repository is listed in reporting on the "${hit.campaign.campaign}" campaign${asOf}. Don't clone it, open it in an editor, or run anything from it. If someone sent it to you as a job task, that's how this campaign works. Source: ${hit.campaign.source}`,
          hit.campaign.source)
      } else if (ownerHit) {
        add('ID-IOC-OWNER', 'high', `The account "${owner}" published a repo named in public malware reporting`,
          `${ownerHit.repo} is listed in reporting on the "${ownerHit.campaign.campaign}" campaign${asOf}. This is another repository from the same account. Accounts like this usually exist only to spread malware. Source: ${ownerHit.campaign.source}`,
          ownerHit.campaign.source)
      }
    }
  }

  if (!onGitHub) {
    if (famous) {
      add('ID-IMPERSONATION', 'medium', `"${repo}" has the name of a famous project, but this copy is on ${host}`,
        `The well-known ${famous.name} is at github.com/${famous.home}. git-bouncer can't tell whether this one is an official mirror, a fork, or someone else's code with a borrowed name, so don't trust it because of its name.`,
        `official: github.com/${famous.home}`)
    }
    add('ID-REDUCED', 'info', `Reduced ID check: ${host} isn't GitHub`,
      `git-bouncer can only look up accounts and repositories on GitHub. For ${host} it checked the names (look-alikes and famous project names), but not whether the repo exists, how old it or its owner is, whether it's a fork, or the known-bad list (which names github.com repos). Account names on ${host} are separate from GitHub's: an owner called "microsoft" there isn't necessarily Microsoft.`)
    return { findings, facts }
  }

  // 3 and 4 need the GitHub API.
  api ??= githubApi
  const unchecked = []
  let apiProblem = null
  const call = async path => {
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
      return { ok: false, problem: { reason: 'the GitHub API is rate-limiting requests from your network', hint: "Anonymous requests are limited to 60 an hour. Signing in with \"gh auth login\" raises the limit, and git-bouncer then asks through gh, so it never sees your token." } }
    }
    if (status === 401) return { ok: false, problem: { reason: 'GitHub rejected your gh login', hint: 'Run "gh auth login" again.' } }
    return { ok: false, problem: { reason: status && status !== 200 ? `the GitHub API answered with HTTP ${status}` : 'the GitHub API gave an unexpected answer' } }
  }
  const notChecked = (res, ...what) => {
    apiProblem ??= res.problem ?? { reason: 'the GitHub API gave an unexpected answer' }
    unchecked.push(...what)
  }

  const repoRes = await call(`/repos/${owner}/${repo}`)
  if (repoRes.notFound || (repoRes.ok && (repoRes.json.private === true || (repoRes.json.visibility && repoRes.json.visibility !== 'public')))) {
    const isPrivate = repoRes.ok
    add('ID-NOT-FOUND', 'high', isPrivate ? `${owner}/${repo} is not a public repository` : `There is no public repository at github.com/${owner}/${repo}`,
      isPrivate
        ? 'Your GitHub login can see it, but it is private. git-bouncer only checks public repositories, because checking a private one would mean putting your credentials into the sandbox.'
        : 'It may be private, deleted, or never have existed. git-bouncer only checks public repositories. If someone sent you this link, check it with them through a channel you already trust.')
    return { findings, facts }
  }
  if (repoRes.blocked || (repoRes.ok && repoRes.json.disabled === true)) {
    const reason = typeof repoRes.block?.reason === 'string' ? ` (reason given: ${clean(repoRes.block.reason, { max: 40 })})` : ''
    add('ID-BLOCKED', 'high', `GitHub has blocked or disabled ${owner}/${repo}`,
      `GitHub itself has taken this repository down${reason}. That happens for legal reasons, and also when GitHub finds malware or abuse. Don't get its code from anywhere else either.`)
    return { findings, facts }
  }
  if (!repoRes.ok) {
    notChecked(repoRes, 'whether the repo exists and is public', ...(famous && !ownerIsKnown ? ['whether it is a fork of the original'] : []),
      'how old the repo and its owner account are', 'stars, forks, archived status and releases')
    if (famous && !ownerIsKnown) impersonation(add, owner, repo, famous, ' git-bouncer could not ask GitHub whether it is a fork of the original.')
    reportUnchecked(add, unchecked, apiProblem)
    return { findings, facts }
  }

  const r = repoRes.json
  const fullName = typeof r.full_name === 'string' && GITHUB_FULL_NAME.test(r.full_name) ? r.full_name : `${owner}/${repo}`
  const [apiOwner, apiRepo] = fullName.split('/')
  facts.fullName = fullName
  if (fullName.toLowerCase() !== `${owner}/${repo}`.toLowerCase()) {
    add('ID-MOVED', 'info', `GitHub redirects ${owner}/${repo} to ${fullName}`,
      `The repository was renamed or moved to another account. git follows the redirect, so you'd get ${fullName}, and the checks below are about that repository.`,
      fullName)
  }

  // 3. Impersonation: a famous name that isn't the real project, a redirect to it, or a fork of it.
  if (famous && !ownerIsKnown) {
    const isTheReal = name => {
      const m = typeof name === 'string' && GITHUB_FULL_NAME.exec(name)
      return Boolean(m) && famous.owners.includes(m[1].toLowerCase()) && loose(m[2]) === loose(famous.name)
    }
    const forkOfReal = r.fork === true && (isTheReal(r.parent?.full_name) || isTheReal(r.source?.full_name))
    if (!isTheReal(fullName) && !forkOfReal) impersonation(add, owner, repo, famous, '')
  }

  // 4. Reputation context.
  const repoCreated = parseDate(r.created_at)
  const repoAge = repoCreated === null ? null : ageDays(repoCreated, now)
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
    add('ID-FORK', 'info', parent ? `This repo is a fork of ${parent}` : 'This repo is a fork',
      `A fork starts as a copy of another repo${origin}, but its owner can change anything in it, so it doesn't inherit the original's reputation. The sandbox scan looks at this copy's actual content.`,
      parent ?? undefined)
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

  const [ownerRes, releaseRes] = await Promise.all([
    call(`/users/${apiOwner}`),
    call(`/repos/${apiOwner}/${apiRepo}/releases/latest`),
  ])
  if (ownerRes.ok) {
    const o = ownerRes.json
    const login = typeof o.login === 'string' && GITHUB_OWNER.test(o.login) ? o.login : apiOwner
    const created = parseDate(o.created_at)
    facts.ownerType = o.type === 'Organization' ? 'Organization' : o.type === 'User' ? 'User' : null
    facts.ownerCreatedAt = created === null ? null : isoDate(created)
    facts.ownerAgeDays = created === null ? null : ageDays(created, now)
    if (created !== null && facts.ownerAgeDays < NEW_OWNER_DAYS) {
      add('ID-NEW-OWNER', 'medium', `The account "${login}" was created ${daysAgo(facts.ownerAgeDays)}`,
        `"${login}" has existed since ${isoDate(created)}. Brand-new accounts are how most throwaway malware repos get published, but real recruiters, bootcamps and take-home tests use fresh accounts too, so this is a warning, not proof. Check who sent you the link and whether the account has any history.`,
        `created ${isoDate(created)}`)
    }
    if (facts.ownerType === 'Organization') {
      const orgRes = await call(`/orgs/${login}`)
      if (orgRes.ok) {
        facts.verifiedOrg = orgRes.json.is_verified === true
        if (facts.verifiedOrg) {
          add('ID-VERIFIED-ORG', 'info', `"${login}" has a verified domain on GitHub`,
            'GitHub has confirmed that this organization controls the website domain it lists. That is a good sign it is who it says it is, but any organization can verify a domain it owns, so check that it is the domain you expect.')
        }
      } else if (!orgRes.notFound) {
        notChecked(orgRes, 'whether the organization has a verified domain')
      }
    }
  } else {
    notChecked(ownerRes, 'how old the owner account is')
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
  reportUnchecked(add, unchecked, apiProblem)
  return { findings, facts }
}

function impersonation(add, owner, repo, famous, extra) {
  add('ID-IMPERSONATION', 'medium', `"${repo}" has the name of a famous project, but this isn't it`,
    `The well-known ${famous.name} is github.com/${famous.home}. This one belongs to "${owner}" and isn't a GitHub fork of it, so it can contain anything.${extra} That's normal for a practice or tutorial repo, but don't trust it because of its name. If you wanted the real project, use https://github.com/${famous.home}.`,
    `official: github.com/${famous.home}`)
}

function reportUnchecked(add, unchecked, problem) {
  if (!unchecked.length) return
  add('ID-API-UNAVAILABLE', 'low', 'Part of the ID check could not run',
    `Because ${problem.reason}, these weren't checked: ${unchecked.join('; ')}. The name checks still ran.${problem.hint ? ` ${problem.hint}` : ''}`)
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
