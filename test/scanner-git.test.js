// Git-level checks, using real git plumbing to build repos that would be awkward (or dangerous)
// to create as files: escaping symlinks, case collisions, .git look-alikes and odd submodules.
// Entries are written straight into the index, so nothing is ever checked out on the test machine.
//
// The scanner's subprocess environment is built for the Linux sandbox, so these run on Linux and macOS.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { Findings } from '../sandbox/scanner/findings.js'
import { gitChecks, validateCloneInput } from '../sandbox/scanner/clone.js'

const skip = process.platform === 'win32' ? 'sandbox subprocess environment is Linux/macOS only' : false

async function repoWithIndex(entries) {
  const dir = await mkdtemp(path.join(tmpdir(), 'bouncer-git-'))
  const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input, encoding: 'utf8' }).trim()
  git(['init', '-q'])
  for (const { mode = '100644', name, content, unprotected, onDisk } of entries) {
    const sha = git(['hash-object', '-w', '--stdin'], content)
    // git refuses NTFS/HFS-dangerous names by default; an attacker crafts such trees by hand.
    const prot = unprotected ? ['-c', 'core.protectNTFS=false', '-c', 'core.protectHFS=false'] : []
    execFileSync('git', [...prot, '-C', dir, 'update-index', '--add', '--cacheinfo', `${mode},${sha},${name}`])
    if (onDisk) await writeFile(path.join(dir, name), content) // like a real checkout
  }
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) }
}

async function check(entries) {
  const r = await repoWithIndex(entries)
  try {
    const f = new Findings()
    await gitChecks(r.dir, f)
    return f.toJSON()
  } finally { await r.cleanup() }
}
const ids = list => list.map(f => `${f.id}:${f.severity}`)

test('a symlink pointing outside the repo is a FAIL; one inside it is just noted', { skip }, async () => {
  const r = await check([
    { mode: '120000', name: 'keys', content: '../../.ssh/id_ed25519' },
    { mode: '120000', name: 'abs', content: '/etc/passwd' },
    { mode: '120000', name: 'docs/latest', content: 'v2' },
  ])
  assert.equal(r.filter(f => f.id === 'GIT-SYMLINK-ESCAPE').length, 2, ids(r))
  assert.ok(r.some(f => f.id === 'GIT-SYMLINKS' && f.severity === 'info'), ids(r))
})

test('paths that differ only by case are a warning', { skip }, async () => {
  const r = await check([{ name: 'README.md', content: 'a' }, { name: 'readme.md', content: 'b' }])
  assert.ok(r.some(f => f.id === 'GIT-CASE-COLLISION'), ids(r))
})

test('a path component impersonating .git (Windows short name) is a FAIL', { skip }, async () => {
  // A literal ".git"/".GIT" component can't even enter an index: git rejects it, and a crafted tree
  // fails object verification at fetch (GIT-FSCK) or checkout (GIT-UNSAFE-PATH). GIT~1 can.
  const r = await check([{ name: 'x/git~1/hooks', content: '', unprotected: true }])
  assert.equal(r.filter(f => f.id === 'GIT-DOTGIT-PATH').length, 1, ids(r))
})

test('submodules are listed; traversal paths and non-https URLs are flagged', { skip }, async () => {
  const r = await check([{ name: '.gitmodules', onDisk: true, content: '[submodule "a"]\n\tpath = ../outside\n\turl = file:///tmp/x\n[submodule "b"]\n\tpath = lib/b\n\turl = https://github.com/x/b.git\n' }])
  assert.ok(r.some(f => f.id === 'GIT-SUBMODULE-PATH' && f.severity === 'high'), ids(r))
  assert.ok(r.some(f => f.id === 'GIT-SUBMODULE-URL'), ids(r))
  assert.ok(r.some(f => f.id === 'GIT-SUBMODULES' && /2 submodule/.test(f.title)), ids(r))
})

test('an ordinary repo has no git-level findings', { skip }, async () => {
  const r = await check([{ name: 'src/index.js', content: 'export {}\n' }, { name: 'README.md', content: '# x\n' }])
  assert.deepEqual(ids(r), [])
})

test('the scanner re-validates its clone input instead of trusting the host', () => {
  assert.doesNotThrow(() => validateCloneInput('https://github.com/a/b.git', null))
  assert.doesNotThrow(() => validateCloneInput('https://github.com/a/b.git', 'v1.2.3'))
  for (const [url, ref] of [['--upload-pack=x', null], ['http://github.com/a/b', null], ['https://t@github.com/a/b', null],
    ['https://github.com/../b', null], ['file:///etc', null], ['https://github.com/a/b.git', '--upload-pack=x'], ['https://github.com/a/b.git', 'a..b']]) {
    assert.throws(() => validateCloneInput(url, ref), /refusing to clone/, `${url} ${ref}`)
  }
})
