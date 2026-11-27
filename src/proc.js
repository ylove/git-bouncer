// Host-side subprocess helper.
//
// Same rules as the scanner's helper: argument arrays only (never a shell string), a timeout,
// and a cap on captured output. Callers choose whether output is captured or shown live.

import { spawn } from 'node:child_process'
import { stat, access, constants } from 'node:fs/promises'
import path from 'node:path'

/**
 * @param {string} cmd
 * @param {string[]} args
 * @param {{cwd?: string, env?: object, timeoutMs?: number, input?: string|Buffer, maxStdout?: number,
 *          onStderr?: (chunk: string) => void, inherit?: boolean}} [opts]
 *   inherit: connect the child to this terminal (used for installs the user asked for)
 * @returns {Promise<{code: number, stdout: string, stderr: string, timedOut: boolean, truncated: boolean, error?: Error}>}
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
      resolve({ code: -1, stdout: '', stderr: String(error), timedOut: false, truncated: false, error })
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
    child.on('error', error => { clearTimeout(timer); resolve({ code: -1, stdout, stderr: stderr + String(error), timedOut, truncated, error }) })
    child.on('close', code => { clearTimeout(timer); resolve({ code: code ?? -1, stdout, stderr, timedOut, truncated }) })
  })
}

/**
 * Find a program on PATH, using absolute PATH entries only. Relative entries like "." or
 * "./node_modules/.bin" would let a freshly cloned repo supply its own `git` or `npm`.
 * @returns {Promise<string|null>} absolute path
 */
export async function which(cmd, env = process.env) {
  const dirs = (env.PATH || env.Path || '').split(path.delimiter).filter(d => d && path.isAbsolute(d))
  const exts = process.platform === 'win32' ? (env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean) : ['']
  for (const d of dirs) {
    for (const e of exts) {
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
