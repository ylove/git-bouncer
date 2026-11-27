import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseRepoUrl, validateRef, UsageError } from '../src/url.js'

const ok = (input, url) => assert.equal(parseRepoUrl(input).url, url, input)
const refused = (input, pattern) => assert.throws(() => parseRepoUrl(input), e => e instanceof UsageError && (!pattern || pattern.test(`${e.message} ${e.hint ?? ''}`)), input)

test('accepts the forms people actually paste, and canonicalizes them to one https URL', () => {
  const want = 'https://github.com/facebook/react.git'
  for (const input of [
    'https://github.com/facebook/react',
    'https://github.com/facebook/react.git',
    'https://github.com/facebook/react/',
    'https://www.github.com/facebook/react',
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

test('supports GitLab subgroups and other https hosts', () => {
  const t = parseRepoUrl('https://gitlab.com/group/subgroup/project')
  assert.equal(t.url, 'https://gitlab.com/group/subgroup/project.git')
  assert.equal(t.provider, 'gitlab')
  assert.equal(parseRepoUrl('https://git.example.org/team/tool').provider, 'other')
})

test('refuses anything git could read as an option (argument injection)', () => {
  refused('--upload-pack=touch /tmp/pwned', /option/)
  refused('-uhttps://github.com/a/b', /option/)
  refused('https://github.com/-evil/repo')
  refused('https://github.com/owner/-repo')
})

test('refuses credentials in the URL, and explains why', () => {
  refused('https://ghp_abc123@github.com/a/b', /credentials/)
  refused('https://user:pass@github.com/a/b', /credentials/)
})

test('refuses dangerous or insecure transports', () => {
  refused('file:///etc/passwd', /transport/)
  refused('ext::sh -c touch% /tmp/pwned', /spaces/)
  refused('ext::sh%20-c%20touch', /transport/)
  refused('http://github.com/a/b', /http/)
  refused('git://github.com/a/b', /transport/)
  refused('javascript:alert(1)', /transport/)
})

test('refuses whitespace, control characters and invisible characters', () => {
  refused('https://github.com/a/b c')
  refused('https://github.com/a/b\n--upload-pack=x')
  refused('https://github.com/a​/b')
  refused('https://github.com/a/b‮')
  refused('https://github.com/a/b\u001b[2K')
})

test('refuses Unicode look-alike hosts and odd URL parts', () => {
  refused('https://gіthub.com/a/b', /non-ASCII/) // Cyrillic "і"
  refused('https://xn--gthub-n4a.com/a/b', /host/) // the same look-alike, pasted as punycode
  refused('https://github.com:8443/a/b', /port/)
  refused('https://github.com/a/b?x=1', /query/)
  refused('https://github.com/a/b#readme', /query/)
})

test('refuses path traversal, including percent-encoded', () => {
  refused('https://github.com/../b')
  refused('https://example.com/a/%2e%2e/b')
  refused('https://example.com/a/./b', /path segments/)
  refused('https://example.com/x/../a/b', /path segments/)
  refused('github.com/a/..', /path segments/)
})

test('explains page links inside a repo instead of guessing', () => {
  refused('https://github.com/a/b/tree/main', /--ref main/)
  refused('https://github.com/a/b/blob/main/README.md', /page inside the repo/)
})

test('refuses malformed GitHub owners and repo names', () => {
  refused('https://github.com/a--b/c')
  refused('https://github.com/' + 'x'.repeat(40) + '/c')
  refused('onlyone')
  refused('')
})

test('validateRef accepts branches, tags and full SHAs', () => {
  for (const r of ['main', 'release/1.2', 'v1.2.3', 'feature-x_y', 'a'.repeat(40).replace(/a/g, 'f')]) assert.equal(validateRef(r), r)
  assert.equal(validateRef(undefined), null)
})

test('validateRef refuses option injection and invalid ref names', () => {
  for (const r of ['--upload-pack=x', '-b', 'a..b', 'a//b', 'a.lock', 'a/', '/a', '.hidden', 'a/.b', 'x@{1}', '@', 'a b', 'a\u0000b', 'a~1', 'a^', 'a:b']) {
    assert.throws(() => validateRef(r), UsageError, JSON.stringify(r))
  }
})

test('validateRef refuses short SHAs, which are ambiguous', () => {
  assert.throws(() => validateRef('abc1234'), /full 40-character SHA/)
})
