// Repository URL and ref validation.
//
// Rule of thumb for security-sensitive input: don't try to spot bad values, describe exactly
// what a good value looks like and refuse everything else. Every accepted form is converted
// to ONE canonical https URL before anything else sees it.

export class UsageError extends Error {
  constructor(message, hint) {
    super(message)
    this.name = 'UsageError'
    this.hint = hint
  }
}

const KNOWN_HOSTS = {
  'github.com': 'github',
  'gitlab.com': 'gitlab',
  'bitbucket.org': 'bitbucket',
  'codeberg.org': 'codeberg',
}

// GitHub's own rules: owners are 1-39 alphanumerics or single hyphens (no leading hyphen).
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/
const REPO_NAME = /^[A-Za-z0-9._-]{1,100}$/
const PATH_SEGMENT = /^[A-Za-z0-9._~-]{1,100}$/
// ASCII hostnames only. Unicode (IDN) hosts are refused: "gіthub.com" with a Cyrillic "і"
// looks identical to the real thing.
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

const NON_ASCII = /[^\x21-\x7e]/
const DOT_SEGMENT = /(^|[/:])(\.|%2e){1,2}(\/|$)/i
// eslint-disable-next-line no-control-regex
const CONTROL_OR_SPACE = /[\u0000- \u007f-\u009f​-‏‪-‮⁦-⁩﻿]/

/**
 * Parse anything a person might paste as a repo and return a canonical https form.
 *
 * Accepted:
 *   https://github.com/owner/repo(.git)(/)     github.com/owner/repo     owner/repo
 *   git@github.com:owner/repo.git              ssh://git@github.com/owner/repo.git
 *   https://gitlab.com/group/subgroup/repo     (and other https hosts, with a reduced ID check)
 *
 * @returns {{url: string, host: string, provider: string, owner: string, repo: string, path: string[], display: string}}
 */
export function parseRepoUrl(input) {
  if (typeof input !== 'string' || input.length === 0) throw new UsageError('No repository given.', 'Example: bouncer clone https://github.com/owner/repo')
  if (input.length > 500) throw new UsageError('That repository URL is too long.')
  if (input.startsWith('-')) {
    // git reads anything starting with "-" as an option: "--upload-pack=<command>" runs a command.
    // (Not echoed back: it may contain control characters.)
    throw new UsageError('That looks like an option, not a repository.', 'Repository URLs never start with "-".')
  }
  if (CONTROL_OR_SPACE.test(input)) throw new UsageError('The repository URL contains spaces, control characters or invisible characters.')
  if (NON_ASCII.test(input)) {
    // new URL() would quietly turn "gіthub.com" (Cyrillic і) into punycode, so refuse before parsing.
    throw new UsageError('The repository URL contains non-ASCII characters.', 'Look-alike letters from other alphabets are a common way to impersonate a real site. Type the URL by hand.')
  }
  if (DOT_SEGMENT.test(input)) {
    // URL parsing silently resolves "/./" and "/../"; refuse instead of guessing what was meant.
    throw new UsageError('The repository URL contains "." or ".." path segments.')
  }

  let host
  let pathPart

  const scp = input.match(/^([A-Za-z0-9._-]+)@([^:/]+):(.+)$/) // git@github.com:owner/repo.git
  if (scp && !input.includes('://')) {
    host = scp[2].toLowerCase()
    pathPart = scp[3]
  } else if (/^[a-z][a-z0-9+.-]*:/i.test(input)) {
    let u
    try { u = new URL(input) } catch { throw new UsageError(`"${shorten(input)}" is not a valid URL.`) }
    const scheme = u.protocol.slice(0, -1).toLowerCase()
    if (scheme === 'http') throw new UsageError('Plain http is not allowed.', 'Use the https:// URL. Over http, anyone on the network can swap the code in transit.')
    if (scheme !== 'https' && scheme !== 'ssh') {
      throw new UsageError(`The "${scheme}:" transport is not allowed.`, 'Only https:// (and git@/ssh:// GitHub-style URLs, which are converted to https) are accepted. Other transports like file:// and ext:: have been used to attack git.')
    }
    if (scheme === 'https' && (u.username || u.password)) {
      throw new UsageError('That URL has a username, password or token in it.', 'Never put credentials in a clone URL: they end up in shell history, logs and .git/config. git-bouncer only checks public repositories, so no credentials are needed.')
    }
    if (u.port) throw new UsageError('Custom ports are not supported.')
    if (u.search || u.hash) throw new UsageError('The URL has a query string or #fragment; paste the plain repository URL.')
    host = u.hostname.toLowerCase()
    pathPart = decodeURIComponentSafe(u.pathname.replace(/^\//, ''))
  } else {
    // "github.com/owner/repo" or "owner/repo"
    const parts = input.split('/')
    if (parts.length >= 3 && parts[0].includes('.')) {
      host = parts[0].toLowerCase()
      pathPart = parts.slice(1).join('/')
    } else if (parts.length === 2) {
      host = 'github.com'
      pathPart = input
    } else {
      throw new UsageError(`"${shorten(input)}" doesn't look like a repository.`, 'Example: bouncer clone https://github.com/owner/repo')
    }
  }

  if (host === 'www.github.com') host = 'github.com'
  if (!HOSTNAME.test(host) || host.split('.').some(label => label.startsWith('xn--'))) {
    throw new UsageError(`"${shorten(host)}" is not an allowed host name.`, 'Only plain ASCII host names are accepted. Look-alike Unicode domains are a common phishing trick.')
  }

  const segments = pathPart.replace(/\/+$/, '').replace(/\.git$/, '').split('/')
  if (segments.some(s => s === '' || s === '.' || s === '..' || s.startsWith('-') || !PATH_SEGMENT.test(s))) {
    throw new UsageError(`"${shorten(pathPart)}" is not a valid repository path.`)
  }

  const provider = KNOWN_HOSTS[host] || 'other'
  if (provider === 'github' || provider === 'bitbucket' || provider === 'codeberg') {
    if (segments.length !== 2) {
      const hint = segments.length > 2 && ['tree', 'blob', 'commit', 'pull', 'releases'].includes(segments[2])
        ? `That's a link to a page inside the repo. Use https://${host}/${segments[0]}/${segments[1]}${segments[2] === 'tree' && segments[3] ? ` --ref ${segments.slice(3).join('/')}` : ''}`
        : `Expected https://${host}/<owner>/<repo>.`
      throw new UsageError('That isn\'t a repository URL.', hint)
    }
  } else if (segments.length < 2) {
    throw new UsageError('Expected at least <owner>/<repo> in the URL path.')
  }
  const owner = segments[0]
  const repo = segments[segments.length - 1]
  if (provider === 'github' && !GITHUB_OWNER.test(owner)) throw new UsageError(`"${shorten(owner)}" is not a valid GitHub user or organization name.`)
  if (!REPO_NAME.test(repo)) throw new UsageError(`"${shorten(repo)}" is not a valid repository name.`)

  const path = segments
  const url = `https://${host}/${path.join('/')}.git`
  return { url, host, provider, owner, repo, path, display: `${host}/${path.join('/')}` }
}

const FULL_SHA = /^[0-9a-f]{40}$/
/**
 * Validate a branch, tag or commit. Follows `git check-ref-format` rules, plus: no leading "-"
 * (option injection), and commits must be full 40-character SHAs (short ones are ambiguous).
 */
export function validateRef(ref) {
  if (ref === undefined || ref === null) return null
  if (typeof ref !== 'string' || ref.length === 0 || ref.length > 200) throw new UsageError('--ref must be a branch, tag or full commit SHA.')
  if (FULL_SHA.test(ref)) return ref
  if (/^[0-9a-f]{7,39}$/.test(ref)) throw new UsageError('Short commit SHAs are ambiguous; use the full 40-character SHA.')
  const bad =
    ref.startsWith('-') || ref.startsWith('/') || ref.endsWith('/') || ref.endsWith('.') || ref.endsWith('.lock') ||
    ref.includes('..') || ref.includes('//') || ref.includes('@{') || ref === '@' ||
    !/^[A-Za-z0-9._/-]+$/.test(ref) || ref.split('/').some(c => c.startsWith('.'))
  if (bad) throw new UsageError(`"${shorten(ref)}" is not a valid branch or tag name.`)
  return ref
}

function decodeURIComponentSafe(s) {
  try { return decodeURIComponent(s) } catch { throw new UsageError('The URL has invalid percent-encoding.') }
}

function shorten(s) {
  const str = String(s)
  return str.length > 60 ? `${str.slice(0, 57)}...` : str
}
