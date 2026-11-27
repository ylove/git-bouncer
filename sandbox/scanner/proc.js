// Subprocess helper for the in-sandbox scanner.
//
// Every command is spawned with an argument array (never a shell string), a minimal
// environment, a timeout, and a cap on how much output we keep. Nothing from the scanned
// repository is ever passed as the command itself — only as data arguments after "--".

import { spawn } from 'node:child_process'
import path from 'node:path'

const MAX_OUTPUT = 32 * 1024 * 1024 // 32 MiB: npm/osv JSON for big trees can be large

/** A deliberately small environment: no tokens, no proxies we didn't choose, no user config. */
export function cleanEnv(extra = {}) {
  return {
    // The folder of the node running the scanner comes first, so npm is found wherever Node was
    // installed (in the sandbox image that's /usr/local/bin; in a Codespace it's under nvm).
    PATH: `${path.dirname(process.execPath)}:/usr/local/bin:/usr/bin:/bin`,
    HOME: '/tmp',
    LANG: 'C.UTF-8',
    TMPDIR: '/tmp',
    npm_config_cache: '/tmp/npm-cache',
    npm_config_update_notifier: 'false',
    npm_config_fund: 'false',
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_ALLOW_PROTOCOL: 'https',
    // Give up on a stalled transfer instead of hanging the scan (bytes/second over seconds).
    GIT_HTTP_LOW_SPEED_LIMIT: '1000',
    GIT_HTTP_LOW_SPEED_TIME: '60',
    // The same git hardening as clone.js, but through the environment, so it also applies to the
    // git commands npm runs on its own when a dependency comes from a git repository.
    ...gitConfigEnv(GIT_ENV_HARDENING),
    ...extra,
  }
}

const GIT_ENV_HARDENING = [
  ['protocol.allow', 'never'], ['protocol.https.allow', 'always'], ['protocol.file.allow', 'never'],
  ['core.hooksPath', '/dev/null'], ['init.templateDir', ''], ['core.symlinks', 'false'], ['core.fsmonitor', 'false'],
  ['core.protectNTFS', 'true'], ['core.protectHFS', 'true'], ['transfer.fsckObjects', 'true'], ['fetch.fsckObjects', 'true'],
  ['credential.helper', ''], ['submodule.recurse', 'false'], ['filter.lfs.smudge', ''], ['filter.lfs.process', ''], ['filter.lfs.required', 'false'],
]

function gitConfigEnv(pairs) {
  const env = { GIT_CONFIG_COUNT: String(pairs.length) }
  pairs.forEach(([k, v], i) => { env[`GIT_CONFIG_KEY_${i}`] = k; env[`GIT_CONFIG_VALUE_${i}`] = v })
  return env
}

/**
 * Run a command and collect its output.
 * Resolves (never rejects) with { code, stdout, stderr, timedOut, error }.
 */
export function run(cmd, args, { cwd, env = cleanEnv(), timeoutMs = 10 * 60 * 1000, input } = {}) {
  return new Promise(resolve => {
    let stdout = ''
    let stderr = ''
    let truncated = false
    let timedOut = false
    let child
    try {
      // detached: the child leads its own process group, so a timeout can kill everything it started
      // (npm -> git -> ssh ...), not just the top process.
      child = spawn(cmd, args, { cwd, env, stdio: ['pipe', 'pipe', 'pipe'], shell: false, detached: true })
    } catch (error) {
      resolve({ code: -1, stdout: '', stderr: String(error), timedOut: false, error })
      return
    }
    const timer = setTimeout(() => {
      timedOut = true
      try { process.kill(-child.pid, 'SIGKILL') } catch { child.kill('SIGKILL') }
    }, timeoutMs)
    const take = (buf, which) => {
      const s = buf.toString('utf8')
      if (which === 'out') {
        if (stdout.length + s.length > MAX_OUTPUT) { truncated = true; return }
        stdout += s
      } else if (stderr.length < 1024 * 1024) {
        stderr += s
      }
    }
    child.stdout.on('data', b => take(b, 'out'))
    child.stderr.on('data', b => take(b, 'err'))
    child.on('error', error => {
      clearTimeout(timer)
      resolve({ code: -1, stdout, stderr: stderr + String(error), timedOut, error })
    })
    child.on('close', code => {
      clearTimeout(timer)
      resolve({ code: code ?? -1, stdout, stderr, timedOut, truncated })
    })
    // On timeout, the group is killed; 'close' can still wait on a grandchild holding a pipe, so
    // resolve on 'exit' + timeout as well.
    child.on('exit', () => { if (timedOut) { clearTimeout(timer); resolve({ code: -1, stdout, stderr, timedOut, truncated }) } })
    if (input !== undefined) child.stdin.end(input)
    else child.stdin.end()
  })
}
