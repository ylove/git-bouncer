// Host-side subprocess helper.
//
// Same rules as the scanner's helper: argument arrays only (never a shell string), a timeout,
// and a cap on captured output. Callers choose whether output is captured or shown live.

import { spawn } from 'node:child_process'
import { realpathSync } from 'node:fs'
import { stat, access, constants } from 'node:fs/promises'
import { homedir } from 'node:os'
import path from 'node:path'

/**
 * @param {string} cmd
 * @param {string[]} args
 * @param {{cwd?: string, env?: object, timeoutMs?: number, input?: string|Buffer, maxStdout?: number,
 *          onStderr?: (chunk: string) => void, inherit?: boolean}} [opts]
 *   inherit: connect the child to this terminal (used for installs the user asked for)
 * @returns {Promise<{code: number, signal: string|null, stdout: string, stderr: string, timedOut: boolean, truncated: boolean, error?: Error}>}
 *   signal: set when the child was stopped by a signal (Ctrl-C, kill); code is then -1
 */
export function run(cmd, args, { cwd, env = process.env, timeoutMs = 120_000, input, maxStdout = 64 * 1024 * 1024, onStderr, inherit = false } = {}) {
  return new Promise(resolve => {
    let stdout = ''
    let stderr = ''
    let truncated = false
    let timedOut = false
    let child
    try {
      child = spawn(cmd, args, { cwd, env, shell: false, windowsHide: true, stdio: inherit ? 'inherit' : ['pipe', 'pipe', 'pipe'] })
    } catch (error) {
      resolve({ code: -1, signal: null, stdout: '', stderr: String(error), timedOut: false, truncated: false, error })
      return
    }
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL') }, timeoutMs)
    if (!inherit) {
      child.stdout.on('data', b => {
        if (stdout.length + b.length > maxStdout) { truncated = true; return }
        stdout += b.toString('utf8')
      })
      child.stderr.on('data', b => {
        const s = b.toString('utf8')
        if (stderr.length < 256 * 1024) stderr += s
        if (onStderr) onStderr(s)
      })
      if (input !== undefined) child.stdin.end(input)
      else child.stdin.end()
    }
    child.on('error', error => { clearTimeout(timer); resolve({ code: -1, signal: null, stdout, stderr: stderr + String(error), timedOut, truncated, error }) })
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code: code ?? -1, signal: signal ?? null, stdout, stderr, timedOut, truncated }) })
  })
}

/**
 * The PATH folders a program may be started from. A folder is skipped when the repository you're
 * about to check could have put it there:
 *  - relative entries ("", ".", "bin"), which mean "the current folder";
 *  - absolute entries inside the current folder. npx, `npm run`, direnv and activated virtualenvs
 *    add these (/path/to/take-home/node_modules/.bin), and that folder may be the untrusted repo.
 *    Exception: when the current folder is your home folder or above it (/, /home), every tool you
 *    installed lives "inside" it, and those folders aren't a repo someone sent you;
 *  - any entry with a node_modules segment: those hold programs that packages installed;
 *  - on Windows, anything but a drive path (C:\Tools) or a network path (\\server\share).
 *    "\Tools" looks absolute, but it means "\Tools on whatever drive the current folder is on",
 *    which may be a USB stick or a mounted disk image.
 * @param {Record<string, string|undefined>} [env]
 * @param {{cwd?: string, home?: string, platform?: string}} [opts]
 * @returns {string[]}
 */
export function trustedPathDirs(env = process.env, { cwd = process.cwd(), home = homedir(), platform = process.platform } = {}) {
  const win = platform === 'win32'
  const p = win ? path.win32 : path.posix
  const fold = s => (win || platform === 'darwin' ? s.toLowerCase() : s) // case-insensitive filesystems
  const real = d => { try { return realpathSync.native(d) } catch { return p.resolve(d) } }
  const inside = (child, parent) => {
    const rel = p.relative(fold(parent), fold(child))
    return rel === '' || (rel !== '..' && !rel.startsWith(`..${p.sep}`) && !p.isAbsolute(rel))
  }
  const here = real(cwd)
  const guardCwd = !inside(real(home), here)
  const value = (win ? env.PATH ?? env.Path ?? env.path : env.PATH) ?? ''
  return value.split(win ? ';' : ':')
    .map(d => (win ? d.replace(/^"(.*)"$/, '$1') : d))
    .filter(d => {
      if (win ? !/^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)/.test(d) : !d.startsWith('/')) return false
      if (d.split(/[\\/]+/).some(segment => fold(segment) === 'node_modules')) return false
      if (guardCwd && inside(real(d), here)) return false
      return true
    })
}

/**
 * Find a program on PATH, in trusted folders only (see trustedPathDirs). A freshly cloned repo
 * must never be able to supply its own `git`, `npm` or `brew`.
 * @param {string} cmd
 * @param {Record<string, string|undefined>} [env]
 * @param {{cwd?: string, home?: string, exts?: string[]}} [opts]
 *   exts: Windows file extensions to try (default: PATHEXT). Pass ['.EXE', '.COM'] for a program
 *   that must start without a shell.
 * @returns {Promise<string|null>} absolute path
 */
export async function which(cmd, env = process.env, { cwd, home, exts } = {}) {
  const dirs = trustedPathDirs(env, { cwd, home })
  const tryExts = process.platform === 'win32' ? (exts ?? (env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean)) : ['']
  for (const d of dirs) {
    for (const e of tryExts) {
      const p = path.join(d, cmd + e)
      try {
        const st = await stat(p)
        if (!st.isFile()) continue
        if (process.platform !== 'win32') await access(p, constants.X_OK)
        return p
      } catch { /* keep looking */ }
    }
  }
  return null
}

/** Is `cmd` runnable? (Runs `<cmd> --version`; nothing else.) */
export async function has(cmd) {
  const r = await run(cmd, ['--version'], { timeoutMs: 10_000 })
  return r.code === 0
}
