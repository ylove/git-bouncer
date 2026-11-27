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

import { mkdir } from 'node:fs/promises'
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
export async function gitChecks(dir, findings) {
  const ls = await git(['ls-files', '-s', '-z'], dir)
  if (ls.code !== 0) return
  const entries = ls.stdout.split('\0').filter(Boolean).map(line => {
    const tab = line.indexOf('\t')
    const [mode, , ] = line.slice(0, tab).split(' ')
    return { mode, file: line.slice(tab + 1) }
  })

  // Symlinks: report any that point outside the repository (e.g. at ~/.ssh) or at absolute paths.
  const links = entries.filter(e => e.mode === '120000')
  for (const link of links.slice(0, 200)) {
    const show = await git(['cat-file', '-p', `:${link.file}`], dir, 30000)
    const target = show.code === 0 ? show.stdout.slice(0, 500) : ''
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
      detail: 'Symlinks were checked out as plain files inside the sandbox. Only ones pointing outside the repo are flagged.',
    })
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
