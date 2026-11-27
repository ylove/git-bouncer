// Shared pieces of the cloud runtimes (GCP Cloud Build and AWS CodeBuild).
//
// NOT LIVE-TESTED BY THE MAINTAINER: running these costs money. Everything here is covered by unit
// tests with a fake `exec`, and `plan()` lets anyone see exactly what would run. See docs/cloud.md.
//
// The rules this file enforces for both providers:
//  1. Commands are argument arrays handed to spawn() without a shell. Never a command string.
//  2. The repository URL, ref and nonce are re-validated here even though the CLI already did,
//     because this module must not trust its caller. Valid values contain no quotes, spaces, "$",
//     newlines or anything else a YAML file or a shell could give meaning to.
//  3. Generated files are produced from plain objects by one small serializer (toYaml), which
//     quotes every string. No hand-written YAML with values pasted into it.
//  4. Nothing we run in the cloud gets credentials, mounts or environment variables from the host.

import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import path from 'node:path'
import { validateRef } from '../url.js'
import { clean } from '../ui/sanitize.js'

/** The local tag the sandbox image gets inside the build machine. Never pushed anywhere. */
export const SANDBOX_IMAGE = 'git-bouncer-sandbox:scan'

/** Where sandbox/Dockerfile puts the scanner. */
export const SCANNER_ENTRY = '/opt/bouncer/scanner/main.js'

/**
 * The container hardening flags. They must stay identical to the local Docker/Podman runtime
 * (issue #3), so a cloud scan is exactly as locked down as a local one:
 *   --cap-drop=ALL                    no Linux capabilities at all
 *   --security-opt=no-new-privileges  setuid binaries can't raise privileges
 *   --read-only                       the image's filesystem can't be changed
 *   --user=10001:10001                an unprivileged user, never root
 *   --tmpfs ... noexec,nosuid,nodev   the only writable places, size-capped, nothing there can run
 *   --pids-limit / --memory           no fork bombs, no eating the build machine's memory
 */
export const SANDBOX_RUN_FLAGS = Object.freeze([
  '--cap-drop=ALL',
  '--security-opt=no-new-privileges',
  '--read-only',
  '--user=10001:10001',
  '--tmpfs=/work:rw,noexec,nosuid,nodev,size=2g',
  '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=768m',
  '--pids-limit=512',
  '--memory=3g',
])

/**
 * `docker run` arguments for the cloud runtimes: remove the container afterwards, and say out loud
 * that it joins Docker's default bridge network. On Cloud Build that matters: the build's
 * credentials are served on a network named "cloudbuild", and the sandbox is never attached to it.
 */
export const CLOUD_RUN_FLAGS = Object.freeze(['--rm', ...SANDBOX_RUN_FLAGS, '--network=bridge'])

/** Placeholder shown by plan() when no real temporary folder exists yet (a dry run). */
export const TEMP_DIR_PLACEHOLDER = '<temp-dir>'

const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/
const SEGMENT = /^[A-Za-z0-9._~-]{1,100}$/
const NONCE = /^[0-9a-f]{32,64}$/

/**
 * Re-check the three values that end up in the cloud build. Accepts only the canonical form that
 * parseRepoUrl() produces (https://host/owner/repo.git), a ref that validateRef() accepts, and a
 * 32-64 character lowercase hex nonce. Throws on anything else.
 */
export function assertScanInputs({ url, ref, nonce }) {
  const m = typeof url === 'string' && url.length <= 600 ? /^https:\/\/([^/]+)\/(.+)\.git$/.exec(url) : null
  const segments = m ? m[2].split('/') : []
  const urlOk = m && HOSTNAME.test(m[1]) && segments.length >= 2 &&
    segments.every(s => SEGMENT.test(s) && s !== '.' && s !== '..' && !s.startsWith('-'))
  if (!urlOk) throw new Error('refusing to start a cloud build: the repository URL is not a canonical https URL')
  if (ref !== undefined && ref !== null) {
    try { validateRef(ref) } catch { throw new Error('refusing to start a cloud build: the ref is not a valid branch, tag or commit SHA') }
  }
  if (typeof nonce !== 'string' || !NONCE.test(nonce)) throw new Error('refusing to start a cloud build: the nonce must be 32-64 lowercase hex characters')
}

/** The scanner command inside the sandbox container. `--flag=value` binds each value to its flag. */
export function scannerCommand({ url, ref, nonce }) {
  return ['node', SCANNER_ENTRY, `--url=${url}`, ...(ref ? [`--ref=${ref}`] : []), `--nonce=${nonce}`]
}

export const reportEndMarker = nonce => `-----END BOUNCER REPORT ${nonce}-----`

/** True when the text contains both report markers for this nonce, each as a whole line. */
export function hasCompleteReport(text, nonce) {
  const lines = String(text).split(/\r?\n/)
  const begin = lines.indexOf(`-----BEGIN BOUNCER REPORT ${nonce}-----`)
  return begin !== -1 && lines.indexOf(reportEndMarker(nonce), begin + 1) !== -1
}

/**
 * A short, unguessable id for names we create in the cloud (an S3 prefix, a temp folder). It is
 * derived from the nonce so plan() can stay a pure function, and it is one-way, so the nonce itself
 * never shows up in a bucket listing.
 */
export function runIdFor(nonce) {
  return createHash('sha256').update(`git-bouncer cloud run ${nonce}`).digest('hex').slice(0, 24)
}

// ---------------------------------------------------------------------------------------------
// YAML: a deliberately tiny serializer.
//
// It writes block-style YAML in which every string is a double-quoted scalar produced by
// JSON.stringify. JSON's string escapes are valid YAML double-quoted escapes, so a value can never
// end its quotes early, start a new key or list item, or be read as a number/boolean/null ("no",
// "on" and "1e3" stay strings). Keys come from our own code and must be plain identifiers, and any
// string with characters outside printable ASCII is refused rather than escaped. Refusing is
// simpler to get right than escaping, and nothing we generate needs anything else.
// ---------------------------------------------------------------------------------------------

const YAML_KEY = /^[A-Za-z_][A-Za-z0-9_-]*$/
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/
const isPlainObject = v => v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype

function yamlScalar(v) {
  if (typeof v === 'string') {
    if (!PRINTABLE_ASCII.test(v)) throw new Error('toYaml: strings must be printable ASCII')
    return JSON.stringify(v)
  }
  if (typeof v === 'number' && Number.isFinite(v)) return String(v)
  if (typeof v === 'boolean') return String(v)
  throw new TypeError(`toYaml: unsupported value of type ${v === null ? 'null' : typeof v}`)
}

function yamlMap(obj, indent, out) {
  const pad = ' '.repeat(indent)
  for (const [key, value] of Object.entries(obj)) {
    if (!YAML_KEY.test(key)) throw new Error(`toYaml: unsupported key ${JSON.stringify(key)}`)
    if (value === undefined) continue
    if (Array.isArray(value)) {
      if (value.length === 0) out.push(`${pad}${key}: []`)
      else { out.push(`${pad}${key}:`); yamlSeq(value, indent + 2, out) }
    } else if (isPlainObject(value)) {
      if (Object.keys(value).length === 0) out.push(`${pad}${key}: {}`)
      else { out.push(`${pad}${key}:`); yamlMap(value, indent + 2, out) }
    } else {
      out.push(`${pad}${key}: ${yamlScalar(value)}`)
    }
  }
}

function yamlSeq(items, indent, out) {
  const pad = ' '.repeat(indent)
  for (const item of items) {
    if (isPlainObject(item) && Object.keys(item).length > 0) {
      const sub = []
      yamlMap(item, indent + 2, sub)
      sub[0] = `${pad}- ${sub[0].slice(indent + 2)}`
      out.push(...sub)
    } else if (Array.isArray(item) || isPlainObject(item)) {
      throw new Error('toYaml: nested lists and empty maps inside lists are not supported')
    } else {
      out.push(`${pad}- ${yamlScalar(item)}`)
    }
  }
}

/**
 * @param {object} doc  a plain object of strings, finite numbers, booleans, arrays and objects
 * @param {{comments?: string[]}} [opts]  header comment lines (printable ASCII)
 */
export function toYaml(doc, { comments = [] } = {}) {
  if (!isPlainObject(doc)) throw new TypeError('toYaml: the document must be a plain object')
  const out = comments.map(c => {
    if (!PRINTABLE_ASCII.test(c)) throw new Error('toYaml: comments must be printable ASCII')
    return c ? `# ${c}` : '#'
  })
  yamlMap(doc, 0, out)
  return `${out.join('\n')}\n`
}

// ---------------------------------------------------------------------------------------------
// Configuration: environment variables first, then ~/.config/git-bouncer/cloud.json.
// ---------------------------------------------------------------------------------------------

const CONFIG_KEYS = { gcp: ['project', 'region', 'serviceAccount'], aws: ['project', 'region', 'bucket'] }
const MAX_CONFIG_BYTES = 64 * 1024

/** Where the cloud config file lives: $XDG_CONFIG_HOME/git-bouncer/cloud.json, else ~/.config/... */
export function cloudConfigPath(env = process.env) {
  const base = env.XDG_CONFIG_HOME && path.isAbsolute(env.XDG_CONFIG_HOME)
    ? env.XDG_CONFIG_HOME
    : path.join(env.HOME || env.USERPROFILE || homedir(), '.config')
  return path.join(base, 'git-bouncer', 'cloud.json')
}

/**
 * Read and check the config file. A missing file is fine (returns empty sections). Unknown keys
 * are an error, so a typo like "regoin" is reported instead of silently ignored.
 * @returns {Promise<{path: string, gcp: object, aws: object}>}
 */
export async function loadCloudConfig(env = process.env) {
  const file = cloudConfigPath(env)
  let text
  try {
    text = await readFile(file, 'utf8')
  } catch (e) {
    if (e && e.code === 'ENOENT') return { path: file, gcp: {}, aws: {} }
    throw new Error(`could not read ${file}: ${e && e.code ? e.code : 'unknown error'}`)
  }
  if (Buffer.byteLength(text) > MAX_CONFIG_BYTES) throw new Error(`${file} is larger than 64 KB`)
  let data
  try { data = JSON.parse(text) } catch { throw new Error(`${file} is not valid JSON`) }
  if (!isPlainObject(data)) throw new Error(`${file} must contain a JSON object`)
  const result = { path: file, gcp: {}, aws: {} }
  for (const [section, value] of Object.entries(data)) {
    if (!CONFIG_KEYS[section]) throw new Error(`${file}: unknown section "${clean(section, { max: 40 })}" (expected "gcp" or "aws")`)
    if (!isPlainObject(value)) throw new Error(`${file}: "${section}" must be an object`)
    for (const [key, v] of Object.entries(value)) {
      if (!CONFIG_KEYS[section].includes(key)) throw new Error(`${file}: unknown setting "${section}.${clean(key, { max: 40 })}" (expected one of: ${CONFIG_KEYS[section].join(', ')})`)
      if (typeof v !== 'string' || v.length === 0) throw new Error(`${file}: "${section}.${key}" must be a non-empty string`)
      result[section][key] = v
    }
  }
  return result
}

// ---------------------------------------------------------------------------------------------
// Files: copy git-bouncer's own sandbox folder, write generated files.
// ---------------------------------------------------------------------------------------------

const MAX_SANDBOX_FILES = 1000
const MAX_SANDBOX_BYTES = 25 * 1024 * 1024

/**
 * Copy the sandbox folder (Dockerfile + scanner) into `dest`, which must not exist yet. Only plain
 * files and folders are copied: a symlink or anything else makes it stop, because the upload must
 * contain exactly git-bouncer's own files and nothing a link could pull in from elsewhere.
 * @returns {Promise<{files: number, bytes: number}>}
 */
export async function copySandbox(src, dest) {
  let files = 0
  let bytes = 0
  const walk = async (from, to) => {
    await mkdir(to, { mode: 0o700 })
    const entries = await readdir(from, { withFileTypes: true })
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    for (const entry of entries) {
      const s = path.join(from, entry.name)
      const d = path.join(to, entry.name)
      if (entry.isDirectory()) {
        await walk(s, d)
      } else if (entry.isFile()) {
        const content = await readFile(s)
        files += 1
        bytes += content.length
        if (files > MAX_SANDBOX_FILES || bytes > MAX_SANDBOX_BYTES) throw new Error('the sandbox folder is unexpectedly large; refusing to upload it')
        await writeFile(d, content, { flag: 'wx', mode: 0o600 })
      } else {
        throw new Error(`the sandbox folder contains something that is not a plain file or folder (${clean(path.relative(src, s), { max: 200 })}); refusing to upload it`)
      }
    }
  }
  await walk(src, dest)
  if (files === 0) throw new Error('the sandbox folder is empty')
  return { files, bytes }
}

/** Write plan.files into workDir. Names are our own constants; 'wx' refuses to overwrite anything. */
export async function writePlanFiles(workDir, files) {
  for (const [name, content] of Object.entries(files)) {
    if (!/^[a-z][a-z0-9.-]*$/.test(name)) throw new Error(`unexpected generated file name ${JSON.stringify(name)}`)
    await writeFile(path.join(workDir, name), content, { flag: 'wx', mode: 0o600 })
  }
}

// ---------------------------------------------------------------------------------------------
// Running commands.
// ---------------------------------------------------------------------------------------------

const MAX_STDOUT = 64 * 1024 * 1024
const MAX_STDERR = 1024 * 1024

/**
 * Run one program with an argument array: spawn() with shell: false, so nothing in `args` is ever
 * interpreted by a shell. Never rejects; resolves with
 * { code, stdout, stderr, timedOut, aborted, truncated, error }.
 *
 * @param {string} cmd
 * @param {string[]} args
 * @param {{input?: string, timeoutMs?: number, onStdout?: (chunk: string) => void,
 *          env?: Record<string, string>, signal?: AbortSignal}} [opts]
 */
export function defaultExec(cmd, args, { input, timeoutMs = 60_000, onStdout, env = process.env, signal } = {}) {
  if (typeof cmd !== 'string' || !Array.isArray(args) || args.some(a => typeof a !== 'string')) {
    return Promise.reject(new TypeError('exec needs a command name and an array of string arguments'))
  }
  return new Promise(resolve => {
    let stdout = ''
    let stderr = ''
    let truncated = false
    let timedOut = false
    let aborted = false
    let settled = false
    let child
    const finish = result => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      clearTimeout(killTimer)
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve({ stdout, stderr, timedOut, aborted, truncated, ...result })
    }
    try {
      child = spawn(cmd, args, { shell: false, windowsHide: true, env, stdio: ['pipe', 'pipe', 'pipe'] })
    } catch (error) {
      resolve({ code: -1, stdout: '', stderr: String(error && error.message), timedOut: false, aborted: false, truncated: false, error })
      return
    }
    let killTimer
    const stop = () => {
      child.kill('SIGTERM')
      killTimer = setTimeout(() => child.kill('SIGKILL'), 5000)
    }
    const timer = setTimeout(() => { timedOut = true; stop() }, timeoutMs)
    const onAbort = () => { aborted = true; stop() }
    if (signal) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', s => {
      if (stdout.length + s.length > MAX_STDOUT) { truncated = true; return }
      stdout += s
      if (onStdout) onStdout(s)
    })
    child.stderr.on('data', s => { if (stderr.length < MAX_STDERR) stderr += s })
    child.on('error', error => finish({ code: -1, stderr: stderr + String(error && error.message), error }))
    child.on('close', code => finish({ code: code ?? -1 }))
    child.stdin.on('error', () => {}) // the program may exit before reading its input
    child.stdin.end(input)
  })
}

/** Turn streamed chunks into sanitized single lines for onLog (untrusted text: the build log). */
export function lineSink(onLog) {
  let buf = ''
  const emit = line => { if (onLog && line.trim()) onLog(clean(line, { max: 500 })) }
  return {
    write(chunk) {
      buf += chunk
      if (buf.length > 1024 * 1024) buf = buf.slice(-1024 * 1024)
      const lines = buf.split(/\r?\n/)
      buf = lines.pop()
      lines.forEach(emit)
    },
    end() { emit(buf); buf = '' },
  }
}

/** The last few lines of a CLI's error output, sanitized, for error messages. */
export function errorTail(result, max = 600) {
  const text = `${result && result.stderr ? result.stderr : ''}\n${result && result.stdout ? result.stdout : ''}`.trim()
  return clean(text.split(/\r?\n/).filter(Boolean).slice(-4).join(' | '), { max })
}

/** Replace placeholders like <build-id> in a planned step with values we have already validated. */
export function fillStep(step, vars) {
  const args = step.args.map(a => a.replace(/<[a-z-]+>/g, m => {
    if (!(m in vars)) throw new Error(`internal: no value for ${m}`)
    return vars[m]
  }))
  return { cmd: step.cmd, args }
}

export const sleep = (ms, signal) => new Promise(resolve => {
  if (signal && signal.aborted) return resolve()
  const t = setTimeout(done, ms)
  function done() { clearTimeout(t); if (signal) signal.removeEventListener('abort', done); resolve() }
  if (signal) signal.addEventListener('abort', done, { once: true })
})

export function abortError() {
  const e = new Error('the cloud scan was interrupted')
  e.name = 'AbortError'
  return e
}
