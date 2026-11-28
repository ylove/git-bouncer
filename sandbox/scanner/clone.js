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
import { foldPath } from './paths.js'

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
 * Read many blobs in one `git cat-file --batch` call (no per-link process, no cap on link count).
 * Returns the blobs it could read; any sha missing from the result could not be read.
 */
async function readBlobs(dir, shas) {
  if (!shas.length) return new Map()
  // Raw bytes, not text: decoding chunk by chunk could split a multi-byte character, and then the
  // byte sizes in the headers would no longer line up with the data.
  const r = await run('git', [...GIT_HARDENING, 'cat-file', '--batch'], { cwd: dir, env: cleanEnv(), input: `${shas.join('\n')}\n`, timeoutMs: 120000, raw: true })
  const out = new Map()
  const buf = r.stdout
  let at = 0
  // Objects come back in the order they were asked for; stop at the first header that doesn't match.
  for (const want of shas) {
    const nl = buf.indexOf(10, at)
    if (nl === -1) break
    const [sha, type, size] = buf.subarray(at, nl).toString('utf8').split(' ')
    if (sha !== want) break
    at = nl + 1
    if (type !== 'blob') continue // "missing"
    const n = Number(size)
    if (!Number.isSafeInteger(n) || at + n > buf.length) break
    out.set(sha, buf.subarray(at, at + n).toString('utf8'))
    at += n + 1
  }
  return out
}

const MAX_MATERIALIZE_FILES = 5000
const MAX_MATERIALIZE_LINKS = 2000
const MAX_LINK_HOPS = 40

const isAbsoluteTarget = t => t.startsWith('/') || t.startsWith('\\') || /^[A-Za-z]:/.test(t) || t.startsWith('~')

// Places a tool reads automatically: a folder (anywhere in the link's path) or a file name. A link here
// swaps what the editor, agent or package manager loads, and how that link resolves depends on your OS
// and tools, which the scanner can only approximate. Folded names; any component starting ".git" counts.
const SENSITIVE_DIRS = new Set(['node_modules', '.vscode', '.devcontainer', '.claude', '.cursor', '.husky', '.gemini', '.roo', '.windsurf'])
const SENSITIVE_FILES = new Set(['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', '.npmrc',
  'bunfig.toml', 'binding.gyp', 'tasks.json', 'settings.json', 'settings.local.json', 'mcp.json', '.mcp.json', 'hooks.json',
  'devcontainer.json', '.devcontainer.json', 'agents.md', 'claude.md', 'claude.local.md', 'gemini.md', '.cursorrules', '.windsurfrules'])
const SENSITIVE_PREFIXES = ['.git', '.yarnrc', '.pnpmfile']
// Agent instruction files. `CLAUDE.md -> AGENTS.md` is a common, harmless way to share one file between
// agents, and the copy put in its place is scanned with the same rules, so instruction-to-instruction
// links that resolve unambiguously inside the repo are not treated as sensitive.
const INSTRUCTION_FILES = new Set(['agents.md', 'claude.md', 'claude.local.md', 'gemini.md', 'copilot-instructions.md', '.cursorrules', '.windsurfrules'])

function sensitiveComponent(file) {
  const parts = foldPath(file).split('/')
  const base = parts.at(-1)
  const hit = p => SENSITIVE_DIRS.has(p) || SENSITIVE_PREFIXES.some(x => p.startsWith(x)) || p.endsWith('.code-workspace')
  return parts.slice(0, -1).find(hit) ?? (hit(base) || SENSITIVE_FILES.has(base) ? base : null)
}

/**
 * Resolves repo paths through the repo's own symlinks, the way different systems would.
 * Lookups try the exact spelling first, then the folded one (macOS and Windows would follow a link or
 * enter a folder spelled differently), so the scanner sees the worst case.
 */
export function linkResolver(entries, links) {
  const linkTarget = new Map(links.map(l => [l.file, l.target]))
  const exact = new Set()
  const folders = new Set()
  const folded = new Map() // folded path -> real spelling, for files, links and folders
  const remember = p => { exact.add(p); const k = foldPath(p); if (!folded.has(k)) folded.set(k, p) }
  for (const e of entries) {
    remember(e.file)
    for (let at = e.file.indexOf('/'); at !== -1; at = e.file.indexOf('/', at + 1)) { remember(e.file.slice(0, at)); folders.add(e.file.slice(0, at)) }
  }
  /** The real spelling of `p` in the index (or `p` itself if it doesn't exist). */
  const spell = p => (exact.has(p) ? p : folded.get(foldPath(p)) ?? p)
  const targetOf = p => linkTarget.get(spell(p))
  const split = (t, backslash) => (backslash ? t.replace(/\\/g, '/') : t).split('/')

  /**
   * Physical resolution, as macOS and Linux do it: one component at a time, following a link the
   * moment it appears. `s/../x` where `s -> a/b` is a/x: ".." leaves the link's TARGET, not the place
   * the link sits. A component that doesn't exist, or a file used as a folder, stops resolution there,
   * as it does for the OS. Returns {path} (in the repo, no links left in it), {missing}, {escape} or {loop}.
   */
  const physical = (start, backslash = false) => {
    const stack = []
    const pending = split(start, false)
    let hops = 0
    while (pending.length) {
      const c = pending.shift()
      if (c === '' || c === '.') continue
      if (c === '..') { if (!stack.length) return { escape: true }; stack.pop(); continue }
      const cand = spell([...stack, c].join('/'))
      const t = targetOf(cand)
      if (t === undefined) {
        if (!exact.has(cand)) return { missing: true }
        if (!folders.has(cand) && pending.some(x => x !== '' && x !== '.')) return { missing: true } // ENOTDIR
        stack.splice(0, stack.length, ...cand.split('/'))
        continue
      }
      if (t === null) return { unreadable: true }
      if (++hops > MAX_LINK_HOPS) return { loop: true }
      if (isAbsoluteTarget(t)) return { escape: true }
      pending.unshift(...split(t, backslash)) // relative to the folder the link is in, which is `stack`
    }
    return { path: stack.join('/') }
  }

  /**
   * Lexical resolution, as tools that clean up ".." before touching the disk do (Windows path handling,
   * path.resolve-style code): `s/../x` is just x.
   */
  const lexical = (start, backslash = false) => {
    let cur = path.posix.normalize(start)
    for (let hop = 0; hop <= MAX_LINK_HOPS; hop++) {
      if (cur === '..' || cur.startsWith('../')) return { escape: true }
      const parts = cur.split('/')
      let changed = false
      for (let i = 1; i <= parts.length; i++) {
        const prefix = parts.slice(0, i).join('/')
        const t = targetOf(prefix)
        if (t === undefined) continue
        if (t === null) return { unreadable: true }
        if (isAbsoluteTarget(t)) return { escape: true }
        cur = path.posix.normalize(path.posix.join(path.posix.dirname(spell(prefix)), ...split(t, backslash), ...parts.slice(i)))
        changed = true
        break
      }
      if (!changed) return { path: cur === '.' ? '' : spell(cur) }
    }
    return { loop: true }
  }

  /** Every reading of a link: physical (macOS/Linux), lexical, and Windows' (backslashes are separators). */
  const views = file => {
    const out = [physical(file), lexical(file)]
    if (/\\/.test(linkTarget.get(file) ?? '')) out.push(lexical(file, true))
    return out
  }
  return { views }
}

/**
 * The sandbox checks out symlinks as plain text files (core.symlinks=false), so nothing can follow
 * them out of the repo. But a normal clone on your machine WOULD follow a link that stays inside the
 * repo: `package.json -> tools/manifest.json` makes npm read tools/manifest.json. So each in-repo link
 * is replaced with a copy of what it points to, and the scanner checks what your tools would really see.
 */
async function symlinkChecks(dir, entries, links, findings) {
  const resolver = linkResolver(entries, links)
  const unresolved = (link, why) => findings.add({
    id: 'GIT-SYMLINK-UNRESOLVED', severity: 'medium', file: link.file, evidence: `-> ${link.target ?? '(unreadable)'}`.slice(0, 200),
    title: `A symlink could not be resolved for scanning: ${why}`,
    detail: 'Tools on your machine would follow this link, but the scanner could not put a faithful copy of its target in its place, so what your tools would read there was not (fully) checked. Treat the result as incomplete.',
  })

  const plans = []
  for (const [i, link] of links.entries()) {
    const sensitive = sensitiveComponent(link.file)
    const views = link.target === null ? [{ unreadable: true }] : resolver.views(link.file)
    const escape = views.some(v => v.escape)
    if (escape) {
      findings.add({
        id: 'GIT-SYMLINK-ESCAPE', severity: 'high', file: link.file, evidence: `-> ${link.target}`,
        title: 'Symlink points outside the repository',
        detail: 'A committed symlink that points outside the repo (for example at ~/.ssh, an absolute path, or a chain of links whose ".." climbs out) can make a tool or the app read or overwrite files on your machine. Paths are followed one step at a time, the way your OS does. It is also the building block of git clone exploits like CVE-2024-32002.',
      })
    }
    const [phys] = views
    const agreed = views.every(v => v.path !== undefined && v.path === phys.path)
    let realKind = null
    if (!escape && phys.path !== undefined) {
      const st = await lstat(path.join(dir, phys.path)).catch(() => null)
      realKind = st?.isFile() ? 'file' : st?.isDirectory() ? 'dir' : null
    }
    const sharedInstructions = agreed && realKind === 'file' && INSTRUCTION_FILES.has(path.posix.basename(foldPath(link.file))) &&
      INSTRUCTION_FILES.has(path.posix.basename(foldPath(phys.path)))
    if (sensitive && !sharedInstructions) {
      findings.add({
        id: 'GIT-SYMLINK-SENSITIVE', severity: 'high', file: link.file, evidence: `-> ${link.target ?? '(unreadable)'}`.slice(0, 200),
        title: `Symlink at a path tools read automatically (${sensitive})`,
        detail: 'Editors, AI agents and package managers load files here on their own. A symlink in this place decides what they load, and where it lands depends on how your OS and tools resolve links, which the scanner can only approximate. Legitimate repos almost never need one here.',
      })
    }
    if (escape) continue
    if (i >= MAX_MATERIALIZE_LINKS) { unresolved(link, `more than ${MAX_MATERIALIZE_LINKS} symlinks`); continue }
    if (views.some(v => v.unreadable)) { unresolved(link, 'its target could not be read from git'); continue }
    if (views.some(v => v.loop)) { unresolved(link, 'it is part of a loop of links'); continue }
    if (phys.missing) {
      const other = views.find(v => v.path !== undefined)
      unresolved(link, other ? `it points at nothing on macOS/Linux but at "${other.path || '.'}" for tools that resolve ".." first (Windows, Node's realpath)` : 'its target does not exist in the repo')
      continue
    }
    if (!agreed) {
      const other = views.find(v => v.path !== phys.path)
      unresolved(link, `it means "${phys.path || '.'}" on macOS/Linux but ${other.path === undefined ? 'nothing' : `"${other.path || '.'}"`} to tools that resolve ".." first (Windows, Node's realpath)`)
    }
    if (!realKind) { unresolved(link, phys.path ? 'its target does not exist in the repo' : 'it points at the repository itself'); continue }
    plans.push({ link, real: phys.path, kind: realKind })
  }

  // A copy of a folder must already contain whatever the links inside that folder point at, so links
  // inside a target folder are materialized first. A folder that contains its own link is a loop.
  const inside = (p, folder) => folder === '' || p.startsWith(`${folder}/`)
  const order = []
  const state = new Map()
  const cyclic = new Set()
  const stack = []
  const visit = plan => {
    if (state.get(plan) === 'done') return
    if (state.get(plan) === 'visiting') { for (const p of stack.slice(stack.indexOf(plan))) cyclic.add(p); return }
    state.set(plan, 'visiting')
    stack.push(plan)
    if (plan.kind === 'dir') for (const p of plans) if (inside(p.link.file, plan.real)) visit(p)
    stack.pop()
    state.set(plan, 'done')
    order.push(plan)
  }
  for (const plan of plans) visit(plan)

  let done = 0
  let copiedFiles = 0
  for (const plan of order) {
    const { link } = plan
    if (cyclic.has(plan)) { unresolved(link, 'its target folder contains the link itself (an endless folder)'); continue }
    const src = path.join(dir, plan.real)
    const dest = path.join(dir, link.file)
    try {
      if (plan.kind === 'file') {
        if (copiedFiles + 1 > MAX_MATERIALIZE_FILES) { unresolved(link, `more than ${MAX_MATERIALIZE_FILES} files would have to be copied`); continue }
        await rm(dest, { force: true })
        await cp(src, dest)
        copiedFiles++
      } else {
        const count = await countFiles(src, MAX_MATERIALIZE_FILES - copiedFiles)
        if (count < 0) { unresolved(link, `its target folder holds more than the ${MAX_MATERIALIZE_FILES} files the scanner copies`); continue }
        await rm(dest, { force: true, recursive: true })
        await cp(src, dest, { recursive: true })
        copiedFiles += count
      }
      done++
    } catch (e) {
      unresolved(link, `copying its target failed (${String(e?.code || e?.message || e).slice(0, 60)})`)
    }
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
  // A target longer than any OS accepts (PATH_MAX) is treated as unreadable rather than cut short.
  const linkEntries = entries.filter(e => e.mode === '120000')
  const blobs = await readBlobs(dir, [...new Set(linkEntries.map(l => l.sha))])
  const links = linkEntries.map(l => ({ file: l.file, target: blobs.has(l.sha) && blobs.get(l.sha).length <= 4096 ? blobs.get(l.sha) : null }))
  if (links.length) {
    findings.add({
      id: 'GIT-SYMLINKS', severity: 'info', title: `${links.length} symlink(s) in the repository`,
      detail: 'Symlinks were checked out as plain files inside the sandbox. Ones pointing outside the repo are flagged; ones inside it are resolved, step by step the way your OS does, so their targets are scanned where your tools would read them.',
    })
    await symlinkChecks(dir, entries, links, findings)
  }

  // Path components git itself treats specially (folded, so invisible or case variants count too).
  for (const e of entries) {
    const parts = e.file.split('/')
    if (parts.some(p => foldPath(p).replace(/[ .]+$/, '') === '.git' || /^git~\d$/i.test(p))) {
      findings.add({
        id: 'GIT-DOTGIT-PATH', severity: 'high', file: e.file,
        title: 'Path impersonates the .git directory',
        detail: 'A path component that looks like ".git" (case or trailing-dot variants, or the Windows short name GIT~1) is a classic way to plant git configuration or hooks on case-insensitive filesystems.',
      })
    }
  }

  // Collisions: two entries that macOS or Windows treat as the same path (letter case, Unicode
  // normalization, U+017F for "s", invisible code points). They overwrite each other at checkout, so
  // which one ends up on disk depends on checkout order, not on what was scanned. A file that folds onto
  // another entry's folder is the same trick one level up (CVE-2024-32002: a symlink "a" next to "A/").
  const files = new Map() // folded path -> first spelling seen
  const dirs = new Map() // folded folder path -> first spelling seen
  for (const e of entries) {
    for (let at = e.file.indexOf('/'); at !== -1; at = e.file.indexOf('/', at + 1)) {
      const d = e.file.slice(0, at)
      const k = foldPath(d)
      if (!dirs.has(k)) dirs.set(k, d)
    }
  }
  for (const e of entries) {
    const k = foldPath(e.file)
    const other = files.has(k) && files.get(k) !== e.file ? files.get(k) : dirs.has(k) ? dirs.get(k) : null
    if (other === null) { files.set(k, e.file); continue }
    findings.add({
      id: 'GIT-CASE-COLLISION', severity: 'high', file: e.file, evidence: `also: ${other}`,
      title: 'Two paths are the same file on macOS and Windows',
      detail: 'These names differ only by letter case or by Unicode look-alikes that macOS and Windows treat as the same letter (for example U+017F, a long s, for "s"). On those systems they overwrite each other at checkout, so the file you get is not necessarily the one that was scanned. Combined with symlinks this was the trigger for CVE-2024-32002.',
    })
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
