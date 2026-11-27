// Hardened clone, done inside the sandbox.
//
// Malicious repositories have attacked git itself during clone (for example CVE-2024-32002:
// symlinks + case-insensitive paths + submodules -> code execution). So even the clone
// happens in the throwaway sandbox, with every risky git feature switched off:
//
//   protocol.allow=never + protocol.https.allow=always   only https, no ext::/file:// transports
//   core.hooksPath=/dev/null, init.templateDir=           no hooks of any kind
//   core.symlinks=false                                    symlinks become plain text files
//   transfer/fetch.fsckObjects=true                        verify every object's hash and format
//   credential.helper=  (+ GIT_TERMINAL_PROMPT=0)          no credentials are available or asked for
//   no submodules                                          listed and reported, never fetched

import { mkdir, lstat, rm, cp, readdir } from 'node:fs/promises'
import path from 'node:path'
import { run, cleanEnv } from './proc.js'

export const GIT_HARDENING = [
  '-c', 'protocol.allow=never',
  '-c', 'protocol.https.allow=always',
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'init.templateDir=',
  '-c', 'core.symlinks=false',
  '-c', 'core.fsmonitor=false',
  '-c', 'core.protectNTFS=true',
  '-c', 'core.protectHFS=true',
  '-c', 'transfer.fsckObjects=true',
  '-c', 'fetch.fsckObjects=true',
  '-c', 'credential.helper=',
  '-c', 'submodule.recurse=false',
  '-c', 'advice.detachedHead=false',
]

// The host validates these too; the scanner re-checks because it must not trust its caller.
const SHA_RE = /^[0-9a-f]{40}$/
const REF_RE = /^(?!-)(?!.*\.\.)(?!.*\/\/)(?!.*@\{)[A-Za-z0-9._/-]{1,200}(?<!\.lock)(?<![/.])$/
const SEGMENT_RE = /^[A-Za-z0-9._~-]{1,100}$/
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

export function validateCloneInput(url, ref) {
  let u
  try { u = new URL(url) } catch { throw new Error('refusing to clone: not a URL') }
  const segments = u.pathname.replace(/\/$/, '').split('/').slice(1)
  const ok = u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash &&
    HOST_RE.test(u.hostname) && url === u.href.replace(/\/$/, url.endsWith('/') ? '/' : '') &&
    segments.length >= 2 && segments.every(s => SEGMENT_RE.test(s) && s !== '.' && s !== '..' && !s.startsWith('-'))
  if (!ok) throw new Error('refusing to clone: URL is not a plain https repository URL')
  if (ref !== undefined && ref !== null && !(SHA_RE.test(ref) || REF_RE.test(ref))) {
    throw new Error('refusing to clone: ref is not a valid branch, tag or full commit SHA')
  }
}

const git = (args, cwd, timeoutMs = 10 * 60 * 1000) => run('git', [...GIT_HARDENING, ...args], { cwd, env: cleanEnv(), timeoutMs })

/**
 * Fetch exactly one commit (shallow) into `dir` and check it out, without hooks or symlinks.
 * Returns { commit, tree, defaultBranch, ref } or throws an Error whose `.finding` explains why.
 */
export async function hardenedClone(url, ref, dir) {
  validateCloneInput(url, ref)
  await mkdir(dir, { recursive: true })

  const steps = []
  const must = async (label, args, cwd = dir) => {
    const r = await git(args, cwd)
    steps.push({ label, code: r.code })
    if (r.code !== 0) {
      const err = new Error(`${label} failed`)
      err.stderr = r.stderr.slice(-2000)
      err.timedOut = r.timedOut
      throw err
    }
    return r.stdout
  }

  await must('git init', ['init', '-q', dir], path.dirname(dir))
  // A config value, not an argument, so a URL can never be parsed as an option.
  await must('set remote', ['config', 'remote.origin.url', url])

  let defaultBranch = null
  const symref = await git(['ls-remote', '--symref', 'origin', 'HEAD'], dir, 2 * 60 * 1000)
  if (symref.code === 0) {
    const m = symref.stdout.match(/^ref: refs\/heads\/(\S+)\tHEAD$/m)
    if (m) defaultBranch = m[1]
  } else {
    const err = new Error('repository is not reachable over https (it may not exist, may be private, or the host may be down)')
    err.stderr = symref.stderr.slice(-2000)
    err.unreachable = true
    throw err
  }

  const want = ref || 'HEAD'
  try {
    await must('fetch', ['fetch', '--depth=1', '--no-tags', '--no-recurse-submodules', 'origin', '--', want])
  } catch (e) {
    if (/fsck|badObject|bad object|missingSpaceBeforeDate|zeroPaddedFilemode|hash mismatch/i.test(e.stderr || '')) {
      e.fsck = true
    }
    throw e
  }
  try {
    await must('checkout', ['checkout', '-q', '--detach', 'FETCH_HEAD'])
  } catch (e) {
    // core.protectNTFS/HFS refuse paths like ".git" lookalikes; that's a finding, not a crash.
    if (/invalid path|refusing to|is beyond a symbolic link/i.test(e.stderr || '')) e.unsafePath = true
    throw e
  }
  const commit = (await must('rev-parse', ['rev-parse', 'HEAD'])).trim()
  const tree = (await must('rev-parse tree', ['rev-parse', 'HEAD^{tree}'])).trim()
  return { commit, tree, defaultBranch, ref: ref || null, steps }
}

/**
 * Git-level checks on the checked-out tree (symlinks, submodules, case collisions, .git lookalikes).
 * Uses the index, because with core.symlinks=false the working tree shows links as plain files.
 */
/** Read many blobs in one `git cat-file --batch` call (no per-link process, no cap on link count). */
async function readBlobs(dir, shas) {
  if (!shas.length) return new Map()
  const r = await run('git', [...GIT_HARDENING, 'cat-file', '--batch'], { cwd: dir, env: cleanEnv(), input: `${shas.join('\n')}\n`, timeoutMs: 120000 })
  const out = new Map()
  const buf = Buffer.from(r.stdout, 'utf8')
  let at = 0
  while (at < buf.length) {
    const nl = buf.indexOf(10, at)
    if (nl === -1) break
    const [sha, type, size] = buf.subarray(at, nl).toString('utf8').split(' ')
    at = nl + 1
    if (type !== 'blob') continue
    const n = Number(size)
    out.set(sha, buf.subarray(at, at + n).toString('utf8'))
    at += n + 1
  }
  return out
}

const MAX_MATERIALIZE_FILES = 5000

/**
 * The sandbox checks out symlinks as plain text files (core.symlinks=false), so nothing can follow
 * them out of the repo. But a normal clone on your machine WOULD follow a link that stays inside the
 * repo: `package.json -> tools/manifest.json` makes npm read tools/manifest.json. So each in-repo link
 * is replaced with a copy of what it points to, and the scanner checks what your tools would really see.
 */
async function materializeLinks(dir, links, findings) {
  const targets = new Map(links.map(l => [l.file, l.target]))
  // Resolve a repo-relative path through any links on the way (a/b where a is a link), max 40 hops.
  const resolve = p => {
    let cur = path.posix.normalize(p)
    for (let hop = 0; hop < 40; hop++) {
      const parts = cur.split('/')
      let changed = false
      for (let i = 1; i <= parts.length; i++) {
        const prefix = parts.slice(0, i).join('/')
        if (targets.has(prefix)) {
          const t = targets.get(prefix)
          if (t.startsWith('/') || /^[A-Za-z]:[\\/]/.test(t) || t.startsWith('~')) return null
          cur = path.posix.normalize(path.posix.join(path.posix.dirname(prefix), t, ...parts.slice(i)))
          if (cur.startsWith('..')) return null
          changed = true
          break
        }
      }
      if (!changed) return cur
    }
    return null // a loop
  }
  let done = 0
  let copiedFiles = 0
  for (const link of links) {
    const real = resolve(link.file)
    if (!real || real === link.file) continue
    const src = path.join(dir, real)
    const st = await lstat(src).catch(() => null)
    if (!st) continue
    const dest = path.join(dir, link.file)
    try {
      if (st.isFile()) {
        await rm(dest, { force: true })
        await cp(src, dest)
        copiedFiles++
      } else if (st.isDirectory()) {
        const count = await countFiles(src, MAX_MATERIALIZE_FILES - copiedFiles)
        if (count < 0) continue
        await rm(dest, { force: true, recursive: true })
        await cp(src, dest, { recursive: true })
        copiedFiles += count
      } else continue
      done++
    } catch { /* leave the placeholder; the link itself is still reported */ }
    if (copiedFiles >= MAX_MATERIALIZE_FILES) break
  }
  if (done) {
    findings.add({ id: 'GIT-SYMLINKS-RESOLVED', severity: 'info', title: `${done} in-repo symlink(s) were resolved for scanning`,
      detail: 'Tools on your machine would follow these links, so their targets\' contents were checked at the link locations too.' })
  }
}

async function countFiles(dir, limit) {
  let n = 0
  const stack = [dir]
  while (stack.length) {
    for (const e of await readdir(stack.pop(), { withFileTypes: true })) {
      if (e.isDirectory()) stack.push(path.join(e.parentPath ?? e.path, e.name))
      else n++
      if (n > limit) return -1
    }
  }
  return n
}

/**
 * Git-level checks on the checked-out tree (symlinks, submodules, case collisions, .git lookalikes).
 * Uses the index, because with core.symlinks=false the working tree shows links as plain files.
 */
export async function gitChecks(dir, findings) {
  const ls = await git(['ls-files', '-s', '-z'], dir)
  // Every check below works from this listing, so a failed or cut-off listing is a coverage gap, not
  // a clean result.
  if (ls.code !== 0 || ls.truncated) {
    findings.add({
      id: 'GIT-LISTING-INCOMPLETE', severity: 'medium',
      evidence: ls.code !== 0 ? `git ls-files exited ${ls.code}: ${(ls.stderr || '').trim().split('\n').pop()?.slice(0, 160) ?? ''}` : 'the listing was larger than the scanner reads',
      title: 'The list of files in the commit could not be read completely',
      detail: 'The git-level checks (symlinks, case collisions, .git look-alikes, submodules) work from git\'s own list of files. That list was incomplete, so those checks are too. Treat the result as incomplete.',
    })
    if (ls.code !== 0) return
  }
  // A cut-off listing ends mid-entry; only entries followed by their NUL terminator are complete.
  const listing = ls.truncated ? ls.stdout.slice(0, ls.stdout.lastIndexOf('\0') + 1) : ls.stdout
  const entries = listing.split('\0').filter(Boolean).map(line => {
    const tab = line.indexOf('\t')
    const [mode, sha] = line.slice(0, tab).split(' ')
    return { mode, sha, file: line.slice(tab + 1) }
  })

  // Symlinks: every one is checked (one batched git call), and in-repo ones are resolved for scanning.
  const linkEntries = entries.filter(e => e.mode === '120000')
  const blobs = await readBlobs(dir, [...new Set(linkEntries.map(l => l.sha))])
  const links = linkEntries.map(l => ({ file: l.file, target: (blobs.get(l.sha) ?? '').slice(0, 1000) }))
  for (const link of links) {
    const { target } = link
    const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(link.file), target))
    if (target.startsWith('/') || /^[A-Za-z]:[\\/]/.test(target) || target.startsWith('~') || resolved.startsWith('..')) {
      findings.add({
        id: 'GIT-SYMLINK-ESCAPE', severity: 'high', file: link.file, evidence: `-> ${target}`,
        title: 'Symlink points outside the repository',
        detail: 'A committed symlink that points outside the repo (for example at ~/.ssh or an absolute path) can make a tool or the app read or overwrite files on your machine. It is also the building block of git clone exploits like CVE-2024-32002.',
      })
    }
  }
  if (links.length) {
    findings.add({
      id: 'GIT-SYMLINKS', severity: 'info', title: `${links.length} symlink(s) in the repository`,
      detail: 'Symlinks were checked out as plain files inside the sandbox. Ones pointing outside the repo are flagged; ones inside it are resolved so their targets are scanned where your tools would read them.',
    })
    await materializeLinks(dir, links, findings)
  }

  // Path components git itself treats specially.
  for (const e of entries) {
    const parts = e.file.split('/')
    if (parts.some(p => /^\.git$/i.test(p.replace(/[ .]+$/, '')) || /^git~\d$/i.test(p))) {
      findings.add({
        id: 'GIT-DOTGIT-PATH', severity: 'high', file: e.file,
        title: 'Path impersonates the .git directory',
        detail: 'A path component that looks like ".git" (case or trailing-dot variants, or the Windows short name GIT~1) is a classic way to plant git configuration or hooks on case-insensitive filesystems.',
      })
    }
  }

  // Case collisions only matter on case-insensitive filesystems (macOS, Windows), which is where many devs work.
  const seen = new Map()
  for (const e of entries) {
    const k = e.file.toLowerCase()
    if (seen.has(k) && seen.get(k) !== e.file) {
      findings.add({
        id: 'GIT-CASE-COLLISION', severity: 'medium', file: e.file, evidence: `also: ${seen.get(k)}`,
        title: 'Two paths differ only by letter case',
        detail: 'On macOS and Windows these overwrite each other at checkout. Combined with symlinks this was the trigger for CVE-2024-32002.',
      })
    } else seen.set(k, e.file)
  }

  // Submodules are never fetched; list them and flag odd ones.
  const gm = entries.find(e => e.file === '.gitmodules')
  if (gm) {
    const conf = await git(['config', '--file', '.gitmodules', '--get-regexp', '^submodule\\..*\\.(url|path)$'], dir, 30000)
    const lines = conf.code === 0 ? conf.stdout.split('\n').filter(Boolean) : []
    let count = 0
    for (const line of lines) {
      const sp = line.indexOf(' ')
      const key = line.slice(0, sp)
      const value = line.slice(sp + 1)
      if (key.endsWith('.url')) {
        count++
        if (!/^https:\/\//.test(value)) {
          findings.add({
            id: 'GIT-SUBMODULE-URL', severity: 'medium', file: '.gitmodules', evidence: value,
            title: 'Submodule uses a non-https URL',
            detail: 'Submodules were not fetched. Before running `git submodule update`, check where this one points; local paths and unusual transports have been used in git exploits.',
          })
        }
      } else if (/(^|\/)\.\.(\/|$)|(^|\/)\.git(\/|$)/i.test(value) || value.startsWith('/') || value.startsWith('-')) {
        findings.add({
          id: 'GIT-SUBMODULE-PATH', severity: 'high', file: '.gitmodules', evidence: value,
          title: 'Submodule path escapes the repository or targets .git',
          detail: 'A submodule path containing "..", ".git" or a leading "-" is a known git exploit pattern.',
        })
      }
    }
    findings.add({
      id: 'GIT-SUBMODULES', severity: 'low', file: '.gitmodules', title: `${count} submodule(s) not fetched`,
      detail: 'Submodules are separate repositories and were not scanned. Scan each one the same way before running `git submodule update`.',
    })
  }
}
