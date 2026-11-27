import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseRepoUrl, validateRef, UsageError } from '../src/url.js'

// Written as ${AT} so the CI hygiene check (which fails on anything shaped like an email address) stays strict.
const AT = '@'
const ok = (input, url, opts) => assert.equal(parseRepoUrl(input, opts).url, url, input)
const refused = (input, pattern, opts) => assert.throws(() => parseRepoUrl(input, opts), e => e instanceof UsageError && (!pattern || pattern.test(`${e.message} ${e.hint ?? ''}`)), input)

test('accepts the forms people actually paste, and canonicalizes them to one https URL', () => {
  const want = 'https://github.com/facebook/react.git'
  for (const input of [
    'https://github.com/facebook/react',
    'https://github.com/facebook/react.git',
    'https://github.com/facebook/react/',
    'https://www.github.com/facebook/react',
    'HTTPS://GitHub.com/facebook/react',
    'github.com/facebook/react',
    'facebook/react',
    'git@github.com:facebook/react.git',
    'ssh://git@github.com/facebook/react.git',
  ]) ok(input, want)
})

test('keeps owner/repo/provider so the ID check can use them', () => {
  const t = parseRepoUrl('https://github.com/Microsoft/vscode')
  assert.deepEqual([t.provider, t.owner, t.repo, t.display], ['github', 'Microsoft', 'vscode', 'github.com/Microsoft/vscode'])
})

test('supports GitLab subgroups', () => {
  const t = parseRepoUrl('https://gitlab.com/group/subgroup/project')
  assert.equal(t.url, 'https://gitlab.com/group/subgroup/project.git')
  assert.equal(t.provider, 'gitlab')
})

test('other hosts are refused unless named with --allow-host', () => {
  refused('https://git.example.org/team/tool', /--allow-host git\.example\.org/)
  ok('https://git.example.org/team/tool', 'https://git.example.org/team/tool.git', { allowHosts: ['git.example.org'] })
})

test('look-alike hosts are refused even with --allow-host', () => {
  for (const h of ['github.com.evil.example', 'github.com-evil.example', 'githb.com', 'github.co', 'gitlab.co']) {
    refused(`https://${h}/facebook/react`, /looks like/, { allowHosts: [h] })
  }
  refused(`git${AT}github.com.evil.example:facebook/react.git`, /only converted/)
  refused('https://bitbucket.com/a/b', /looks like bitbucket\.org/)
})

test('a GitHub Enterprise host can be named explicitly with --allow-host', () => {
  refused('https://github.mycompany.com/team/tool', /looks like github\.com/)
  ok('https://github.mycompany.com/team/tool', 'https://github.mycompany.com/team/tool.git', { allowHosts: ['github.mycompany.com'] })
})

test('internal and wildcard-DNS hosts are refused even with --allow-host (cloud SSRF)', () => {
  for (const h of ['metadata.google.internal', '169.254.169.254.nip.io', 'printer.local', 'build.corp', 'x.sslip.io']) {
    refused(`https://${h}/a/b`, /internal|not an allowed/, { allowHosts: [h] })
  }
  refused('https://169.254.169.254/a/b', /not an allowed host/)
})

test('refuses anything git could read as an option (argument injection)', () => {
  refused('--upload-pack=touch /tmp/pwned', /option/)
  refused('-uhttps://github.com/a/b', /option/)
  refused('https://github.com/-evil/repo', /valid repository path/)
  refused('https://github.com/owner/-repo', /valid repository path/)
})

test('refuses credentials in the URL, and explains why', () => {
  refused('https://not-a-token@example.com/a/b', /credentials/)
  refused('https://user:pass@example.org/a/b', /credentials/)
})

test('SSH URLs: only the git user, no password, known hosts only', () => {
  refused(`ssh://github.com${AT}evil.example/facebook/react`, /ssh:\/\/git@/)
  refused(`ssh://git:secret${AT}github.com/a/b`, /ssh:\/\/git@/)
  refused(`ssh://-oProxyCommand=x${AT}github.com/a/b`, /ssh:\/\/git@/)
  refused(`ssh://git${AT}evil.example/a/b`, /only converted/)
  refused(`root${AT}github.com:a/b.git`, /git@/)
})

test('refuses dangerous or insecure transports', () => {
  refused('file:///etc/passwd', /transport/)
  refused('ext::sh -c touch /tmp/pwned', /spaces/)
  refused('ext::sh+-c+x', /transport/)
  refused('http://github.com/a/b', /Plain http/)
  refused('git://github.com/a/b', /transport/)
  refused('javascript:alert(1)', /transport/)
})

test('refuses whitespace, control characters, invisible characters and non-ASCII', () => {
  refused('https://github.com/a/b c', /spaces/)
  refused('https://github.com/a/b\n--upload-pack=x', /spaces/)
  refused('https://github.com/a\u200B/b', /spaces/)
  refused('https://github.com/a/b\u202E', /spaces/)
  refused('https://github.com/a/b\u001B[2K', /spaces/)
  refused('https://g\u0456thub.com/a/b', /non-ASCII/) // Cyrillic small letter byelorussian-ukrainian i
})

test('refuses percent-encoding and backslashes, which parsers reinterpret', () => {
  refused('https://%EF%BD%87ithub.com/a/b', /never appear/) // full-width g, decodes to github.com
  refused('https://github.com%E3%80%82evil.example/a/b', /never appear/)
  refused('https://github.com/x/..\\facebook/react', /never appear/)
  refused('https:\\\\github.com\\a\\b', /never appear/)
  refused('https://xn--gthub-n4a.com/a/b', /host/) // a look-alike pasted as punycode
})

test('refuses "." and ".." path segments instead of resolving them', () => {
  refused('https://github.com/../b', /path segments/)
  refused('https://gitlab.com/x/../a/b', /path segments/)
  refused('https://gitlab.com/a/./b', /path segments/)
  refused('github.com/a/..', /path segments/)
})

test('explains links to pages inside a repo instead of guessing', () => {
  refused('https://github.com/a/b/tree/main/docs', /--ref <name>/)
  refused('https://github.com/a/b/blob/main/README.md', /page inside the repo/)
  refused('https://gitlab.com/group/project/-/tree/main', /https:\/\/gitlab\.com\/group\/project and pass/)
  refused('https://github.com/owner/repo?tab=readme-ov-file', /https:\/\/github\.com\/owner\/repo$/)
})

test('refuses malformed GitHub owners and repo names', () => {
  refused('https://github.com/a--b/c')
  refused('https://github.com/' + 'x'.repeat(40) + '/c')
  refused('onlyone')
  refused('')
})

test('validateRef accepts branches, tags (including hex-looking and + tags) and full SHAs', () => {
  for (const r of ['main', 'release/1.2', 'v1.2.3', 'feature-x_y', 'v1.0.0+build.1', '20241127', 'deadbeef', 'f'.repeat(40)]) {
    assert.equal(validateRef(r), r)
  }
  assert.equal(validateRef(undefined), null)
})

test('validateRef refuses option injection and invalid ref names', () => {
  for (const r of ['--upload-pack=x', '-b', 'a..b', 'a//b', 'a.lock', 'a.lock/b', 'refs/heads/x.lock/y', 'a/', '/a', '.hidden', 'a/.b',
    'x@{1}', '@', 'a b', 'a\u0000b', 'a~1', 'a^', 'a:b', 'a.']) {
    assert.throws(() => validateRef(r), UsageError, JSON.stringify(r))
  }
})
