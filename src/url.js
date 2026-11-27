// Repository URL and ref validation.
//
// Rule of thumb for security-sensitive input: don't try to spot bad values, describe exactly
// what a good value looks like and refuse everything else. Every accepted form is converted
// to ONE canonical https URL before anything else sees it.
//
// Hosts are an allowlist too. github.com, gitlab.com, bitbucket.org and codeberg.org are accepted;
// any other host has to be named explicitly with --allow-host. That one rule shuts out look-alike
// domains (github.com.evil.example, githb.com) and internal addresses (metadata.google.internal)
// that a cloud sandbox could otherwise be pointed at.

export class UsageError extends Error {
  constructor(message, hint) {
    super(message)
    this.name = 'UsageError'
    this.hint = hint
  }
}

export const KNOWN_HOSTS = Object.freeze({
  'github.com': 'github',
  'gitlab.com': 'gitlab',
  'bitbucket.org': 'bitbucket',
  'codeberg.org': 'codeberg',
})

// GitHub's own rules: owners are 1-39 alphanumerics or single hyphens (no leading hyphen).
const GITHUB_OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/
const REPO_NAME = /^[A-Za-z0-9._-]{1,100}$/
const PATH_SEGMENT = /^[A-Za-z0-9._~-]{1,100}$/
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/
// Names that only make sense inside a private network, plus wildcard-DNS services that resolve any
// name to any IP (169.254.169.254.nip.io is the cloud metadata server).
const INTERNAL_HOST = /(^|\.)(localhost|local|internal|intranet|lan|home|corp|home\.arpa|nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me)$/

// Printable ASCII only, no spaces. "%" and "\" are refused too: URL parsers decode or reinterpret
// them (the full-width "%EF%BD%87ithub.com" becomes github.com), and repo URLs never need either.
const ALLOWED_CHARS = /^[!-~]+$/
const FORBIDDEN_CHARS = /[%\\"'<>^`{|}]/
const DOT_SEGMENT = /(^|[/:])\.{1,2}(\/|$)/

/**
 * Parse anything a person might paste as a repo and return a canonical https form.
 *
 * Accepted:
 *   https://github.com/owner/repo(.git)(/)     github.com/owner/repo     owner/repo
 *   git@github.com:owner/repo.git              ssh://git@github.com/owner/repo.git
 *   https://gitlab.com/group/subgroup/repo
 *   any other https host, only if it's passed in `allowHosts` (from --allow-host)
 *
 * @param {string} input
 * @param {{allowHosts?: string[]}} [opts]
 * @returns {{url: string, host: string, provider: string, owner: string, repo: string, path: string[], display: string}}
 */
export function parseRepoUrl(input, { allowHosts = [] } = {}) {
  if (typeof input !== 'string' || input.length === 0) throw new UsageError('No repository given.', 'Example: bouncer clone https://github.com/owner/repo')
  if (input.length > 500) throw new UsageError('That repository URL is too long.')
  if (input.startsWith('-')) {
    // git reads anything starting with "-" as an option: "--upload-pack=<command>" runs a command.
    // (Not echoed back: it may contain control characters.)
    throw new UsageError('That looks like an option, not a repository.', 'Repository URLs never start with "-".')
  }
  if (!ALLOWED_CHARS.test(input)) {
    // Covers spaces, control characters, invisible characters and look-alike letters from other
    // alphabets ("g<Cyrillic i>thub.com"), before any parser can "helpfully" normalize them.
    throw new UsageError('The repository URL contains spaces, control characters or non-ASCII characters.',
      'Look-alike letters from other alphabets are a common way to impersonate a real site. Type the URL by hand.')
  }
  if (FORBIDDEN_CHARS.test(input)) throw new UsageError('The repository URL contains characters that never appear in a repository URL (like % or a backslash).')
  if (DOT_SEGMENT.test(input)) throw new UsageError('The repository URL contains "." or ".." path segments.')

  let host
  let pathPart
  let query = ''

  const scp = input.match(/^([^@/:]+)@([^:/]+):(.+)$/) // git@github.com:owner/repo.git
  if (scp && !input.includes('://')) {
    if (scp[1] !== 'git') throw new UsageError('Only the "git@" user is accepted in SSH-style URLs.')
    host = scp[2].toLowerCase()
    pathPart = scp[3]
    if (!KNOWN_HOSTS[host]) throw new UsageError('SSH-style URLs are only converted for github.com, gitlab.com, bitbucket.org and codeberg.org.')
  } else if (/^[a-z][a-z0-9+.-]*:/i.test(input)) {
    let u
    try { u = new URL(input) } catch { throw new UsageError('That is not a valid URL.') }
    const scheme = u.protocol.slice(0, -1).toLowerCase()
    if (scheme === 'http') throw new UsageError('Plain http is not allowed.', 'Use the https:// URL. Over http, anyone on the network can swap the code in transit.')
    if (scheme !== 'https' && scheme !== 'ssh') {
      throw new UsageError(`The "${scheme}:" transport is not allowed.`, 'Only https:// URLs are accepted (git@ and ssh:// URLs for known hosts are converted to https). Other transports like file:// and ext:: have been used to attack git.')
    }
    if (scheme === 'https' && (u.username || u.password)) {
      throw new UsageError('That URL has a username, password or token in it.', 'Never put credentials in a clone URL: they end up in shell history, logs and .git/config. git-bouncer only checks public repositories, so no credentials are needed.')
    }
    if (scheme === 'ssh' && (u.username !== 'git' || u.password)) throw new UsageError('Only ssh://git@<host>/... is accepted for SSH URLs (no other user, no password).')
    if (u.port) throw new UsageError('Custom ports are not supported.')
    if (u.hash) throw new UsageError('The URL has a #fragment; paste the plain repository URL.')
    query = u.search
    host = u.hostname.toLowerCase()
    pathPart = u.pathname.replace(/^\//, '')
    if (scheme === 'ssh' && !KNOWN_HOSTS[host]) throw new UsageError('SSH-style URLs are only converted for github.com, gitlab.com, bitbucket.org and codeberg.org.')
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
      throw new UsageError("That doesn't look like a repository.", 'Example: bouncer clone https://github.com/owner/repo')
    }
  }

  if (host === 'www.github.com') host = 'github.com'
  checkHost(host, allowHosts)

  const provider = KNOWN_HOSTS[host] || 'other'
  const segments = pathPart.replace(/\/+$/, '').replace(/\.git$/, '').split('/')

  // Links to pages inside a repo: explain instead of guessing.
  const pageAt = provider === 'gitlab' ? segments.indexOf('-') : (['github', 'bitbucket', 'codeberg'].includes(provider) && segments.length > 2 ? 2 : -1)
  if (pageAt > 0) {
    const repoPath = segments.slice(0, pageAt).join('/')
    const kind = segments[pageAt + (provider === 'gitlab' ? 1 : 0)]
    const hint = kind === 'tree' || kind === 'blob'
      ? `That's a link to a page inside the repo. Use https://${host}/${repoPath} and pass the branch or tag with --ref <name>.`
      : `That's a link to a page inside the repo. Use https://${host}/${repoPath}`
    throw new UsageError("That isn't a repository URL.", hint)
  }
  if (query) {
    throw new UsageError('The URL has a query string (?...).', `Paste the plain repository URL, e.g. https://${host}/${segments.join('/')}`)
  }
  if (segments.some(s => s === '' || s.startsWith('-') || !PATH_SEGMENT.test(s))) {
    throw new UsageError('That is not a valid repository path.')
  }
  if (['github', 'bitbucket', 'codeberg'].includes(provider) && segments.length !== 2) {
    throw new UsageError("That isn't a repository URL.", `Expected https://${host}/<owner>/<repo>.`)
  }
  if (segments.length < 2) throw new UsageError('Expected at least <owner>/<repo> in the URL path.')

  const owner = segments[0]
  const repo = segments[segments.length - 1]
  if (provider === 'github' && !GITHUB_OWNER.test(owner)) throw new UsageError('That is not a valid GitHub user or organization name.')
  if (!REPO_NAME.test(repo)) throw new UsageError('That is not a valid repository name.')

  const url = `https://${host}/${segments.join('/')}.git`
  return { url, host, provider, owner, repo, path: segments, display: `${host}/${segments.join('/')}` }
}

function checkHost(host, allowHosts) {
  if (!HOSTNAME.test(host) || host.split('.').some(label => label.startsWith('xn--'))) {
    throw new UsageError('That is not an allowed host name.', 'Only plain ASCII host names are accepted. Look-alike Unicode domains are a common phishing trick.')
  }
  if (KNOWN_HOSTS[host]) return
  const explicitlyAllowed = allowHosts.includes(host)
  const lookalike = Object.keys(KNOWN_HOSTS).find(k =>
    host.startsWith(`${k}.`) || host.startsWith(`${k}-`) || hostDistance(host, k) <= 2 ||
    // Same name, different domain (bitbucket.com). --allow-host can override only this rule, so a
    // GitHub Enterprise server like github.mycompany.com can still be named explicitly.
    (!explicitlyAllowed && host.split('.')[0] === k.split('.')[0]))
  if (lookalike) {
    throw new UsageError(`"${host}" is not ${lookalike}.`, `It looks like ${lookalike}, which is how phishing links work. If you meant ${lookalike}, type it exactly.`)
  }
  if (INTERNAL_HOST.test(host)) throw new UsageError(`"${host}" is an internal or wildcard-DNS host name, which is never allowed.`)
  if (!explicitlyAllowed) {
    throw new UsageError(`"${host}" is not a host git-bouncer knows.`, `Known hosts: ${Object.keys(KNOWN_HOSTS).join(', ')}. To check a repo on your own server, pass --allow-host ${host}.`)
  }
}

/** Edit distance between two short host names (bounded: this only compares against 4 hosts). */
function hostDistance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i])
  for (let j = 1; j <= b.length; j++) d[0][j] = j
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
    }
  }
  return d[a.length][b.length]
}

const FULL_SHA = /^[0-9a-f]{40}$/
/**
 * Validate a branch, tag or commit.
 * A stricter subset of `git check-ref-format`: no leading "-" (option injection) and a limited
 * character set. A full 40-character lowercase SHA means "this exact commit"; anything else is fetched
 * as a branch or tag name. (git can't fetch an abbreviated SHA from a remote anyway.)
 */
export function validateRef(ref) {
  if (ref === undefined || ref === null) return null
  if (typeof ref !== 'string' || ref.length === 0 || ref.length > 200) throw new UsageError('--ref must be a branch, tag or full commit SHA.')
  if (FULL_SHA.test(ref)) return ref
  const parts = ref.split('/')
  const bad =
    ref.startsWith('-') || ref.endsWith('.') || ref === '@' || ref.includes('..') || ref.includes('@{') ||
    !/^[A-Za-z0-9._/+@-]+$/.test(ref) ||
    parts.some(c => c === '' || c.startsWith('.') || c.endsWith('.lock'))
  if (bad) throw new UsageError('That is not a valid branch or tag name.')
  return ref
}
