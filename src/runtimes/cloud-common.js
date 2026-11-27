// Shared pieces of the cloud runtimes (GCP Cloud Build and AWS CodeBuild).
//
// NOT LIVE-TESTED BY THE MAINTAINER: running these costs money. Everything here is covered by unit
// tests with a fake `exec`, and `plan()` lets anyone see exactly what would run. See docs/cloud.md.
//
// The rules this file enforces for both providers:
//  1. Commands are argument arrays handed to spawn() without a shell, through the same helper the
//     rest of git-bouncer uses (src/proc.js). Programs are found on absolute PATH entries only.
//  2. The repository URL, ref and nonce are re-validated here even though the CLI already did,
//     because this module must not trust its caller. Valid values contain no quotes, spaces, "$",
//     newlines or anything else a YAML file or a shell could give meaning to.
//  3. Generated files are produced from plain objects by one small serializer (toYaml), which
//     quotes every string. No hand-written YAML with values pasted into it.
//  4. The sandbox container gets exactly the local runtime's hardening (sandboxFlags() from
//     container.js), no credentials, mounts or environment, and the nonce only on stdin.

import { createHash } from 'node:crypto'
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import path from 'node:path'
import { validateRef } from '../url.js'
import { extractReport } from '../report.js'
import { run, which } from '../proc.js'
import { clean } from '../ui/sanitize.js'
import { sandboxFlags } from './container.js'

/** The local tag the sandbox image gets inside the build machine. Never pushed anywhere. */
export const SANDBOX_IMAGE = 'git-bouncer-sandbox:scan'

/** Where sandbox/Dockerfile puts the scanner. */
export const SCANNER_ENTRY = '/opt/bouncer/scanner/main.js'

/** Placeholder shown by plan() when no real temporary folder exists yet (a dry run). */
export const TEMP_DIR_PLACEHOLDER = '<temp-dir>'

/**
 * `docker run` arguments for a cloud sandbox: the local runtime's hardening flags, removed when it
 * exits, and (for the scan) stdin kept open so the nonce can be written to it.
 */
export function sandboxRunArgs({ interactive = false } = {}) {
  return ['run', '--rm', ...(interactive ? ['--interactive'] : []), ...sandboxFlags(), SANDBOX_IMAGE]
}

/**
 * The scanner command. The nonce is NOT an argument: arguments are readable by every process in the
 * container (/proc/<pid>/cmdline), and the nonce is what keeps anything inside the sandbox from
 * printing a forged report. The scanner reads it from the first line of stdin instead.
 */
export function scannerCommand({ url, ref }) {
  return ['node', SCANNER_ENTRY, `--url=${url}`, ...(ref ? [`--ref=${ref}`] : []), '--nonce-stdin']
}

/**
 * The metadata canary: a few lines of git-bouncer's own JavaScript, run in a sandbox container with
 * the same flags as the scan, before the scan. It asks the cloud credential endpoints for
 * credentials and makes the build fail if it gets any (mode "token": any 2xx; mode "any-answer":
 * any HTTP response at all, for endpoints that are supposed to be blocked). Each probe gives up
 * after 3 seconds. It prints only host names and HTTP status codes, never a response body.
 *
 * Kept on one line, with no "$" (Cloud Build would expand it), no single quote (AWS passes it
 * inside single quotes) and no "!" (some shells treat it specially).
 */
export const CANARY_JS = [
  'const mode = process.argv[1] || "token";',
  'const probes = [',
  '["http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", true],',
  '["http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", true],',
  '["http://169.254.169.254/latest/meta-data/iam/security-credentials/", false],',
  '["http://169.254.170.2/v2/credentials/", false]];',
  'Promise.all(probes.map(([u, google]) => fetch(u, { headers: google ? { "Metadata-Flavor": "Google" } : {}, redirect: "manual", signal: AbortSignal.timeout(3000) })',
  '.then(r => { if (r.body) r.body.cancel().catch(() => {}); return [u, r.status] }, () => [u, 0])))',
  '.then(results => { let bad = false;',
  'for (const [u, s] of results) { console.log("metadata canary: " + new URL(u).host + (s ? " answered HTTP " + s : " is not reachable"));',
  'if (s && (mode === "any-answer" || (s >= 200 && s < 300))) bad = true }',
  'if (bad) { console.log("metadata canary: FAILED, the sandbox can reach a cloud credential endpoint, refusing to scan"); process.exit(1) }',
  'console.log("metadata canary: passed") })',
].join(' ')

export const CANARY_FAILED = 'metadata canary: FAILED'

export function canaryCommand(mode) {
  if (/[$'!\n\r]/.test(CANARY_JS)) throw new Error('internal: the canary script must contain no $, \', ! or newline')
  return ['node', '-e', CANARY_JS, mode]
}

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

/** scan() needs the absolute path of git-bouncer's own sandbox/ folder (Dockerfile + scanner). */
export function assertSandboxDir(sandboxDir) {
  if (typeof sandboxDir !== 'string' || !path.isAbsolute(sandboxDir)) {
    throw new Error('refusing to start a cloud build: sandboxDir must be the absolute path of git-bouncer\'s sandbox folder')
  }
}

/**
 * Has the log got a report the CLI will accept? Same rules as the CLI itself (extractReport in
 * src/report.js), so a retry loop never stops on a log the CLI would then reject.
 */
export function reportReady(text, nonce) {
  return extractReport(text, nonce).report !== null
}

/**
 * A short, unguessable id for the names we create in the cloud: a build tag, a storage prefix. It is
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

const CONFIG_KEYS = { gcp: ['project', 'region', 'serviceAccount', 'bucket'], aws: ['project', 'region', 'bucket'] }
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
// Plain names only, so a path can be used as an object key without any escaping.
export const SANDBOX_PATH = /^(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/

/**
 * Copy the sandbox folder (Dockerfile + scanner) into `dest`, which must not exist yet. Only plain
 * files and folders are copied: a symlink or anything else makes it stop, because the upload must
 * contain exactly git-bouncer's own files and nothing a link could pull in from elsewhere.
 * @returns {Promise<{files: number, bytes: number, paths: string[]}>}  paths: relative, with "/"
 */
export async function copySandbox(src, dest) {
  let files = 0
  let bytes = 0
  const paths = []
  const walk = async (from, to, rel) => {
    await mkdir(to, { mode: 0o700 })
    const entries = await readdir(from, { withFileTypes: true })
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    for (const entry of entries) {
      const s = path.join(from, entry.name)
      const d = path.join(to, entry.name)
      const r = rel ? `${rel}/${entry.name}` : entry.name
      if (entry.isDirectory()) {
        await walk(s, d, r)
      } else if (entry.isFile()) {
        if (!SANDBOX_PATH.test(r)) throw new Error(`the sandbox folder contains an unexpected file name (${clean(r, { max: 200 })}); refusing to upload it`)
        const content = await readFile(s)
        paths.push(r)
        files += 1
        bytes += content.length
        if (files > MAX_SANDBOX_FILES || bytes > MAX_SANDBOX_BYTES) throw new Error('the sandbox folder is unexpectedly large; refusing to upload it')
        await writeFile(d, content, { flag: 'wx', mode: 0o600 })
      } else {
        throw new Error(`the sandbox folder contains something that is not a plain file or folder (${clean(path.relative(src, s), { max: 200 })}); refusing to upload it`)
      }
    }
  }
  await walk(src, dest, '')
  if (files === 0) throw new Error('the sandbox folder is empty')
  return { files, bytes, paths }
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

/**
 * The default `exec` for the cloud runtimes: find the program on an absolute PATH entry (never "."
 * or ./node_modules/.bin, so a cloned repo can't supply its own `aws`), then run it with
 * src/proc.js, which uses spawn() with shell: false. On Windows, .cmd and .bat files are refused:
 * Node can only start them through cmd.exe, whose argument parsing is a shell's.
 * Resolves (never rejects) with { code, stdout, stderr, timedOut, truncated, error }.
 */
export function makeDefaultExec(platform = process.platform) {
  return async (cmd, args, opts = {}) => {
    const bin = await which(cmd, opts.env || process.env)
    if (!bin || (platform === 'win32' && /\.(cmd|bat)$/i.test(bin))) {
      const error = Object.assign(new Error(`${cmd} not found`), { code: 'ENOENT' })
      return { code: -1, stdout: '', stderr: error.message, timedOut: false, truncated: false, error }
    }
    return run(bin, args, opts)
  }
}

/** The last few lines of a CLI's error output, sanitized, for error messages. */
export function errorTail(result, max = 600) {
  const text = `${result && result.stderr ? result.stderr : ''}\n${result && result.stdout ? result.stdout : ''}`.trim()
  return clean(text.split(/\r?\n/).filter(Boolean).slice(-4).join(' | '), { max })
}

/**
 * Replace placeholders like <build-id> in a planned step with values we have already validated.
 * An argument that is exactly a placeholder whose value is an array becomes that many arguments.
 */
export function fillStep(step, vars) {
  const args = step.args.flatMap(a => {
    if (a in vars && Array.isArray(vars[a])) return vars[a]
    return [a.replace(/<[a-z-]+>/g, m => {
      if (!(m in vars) || Array.isArray(vars[m])) throw new Error(`internal: no value for ${m}`)
      return vars[m]
    })]
  })
  return { cmd: step.cmd, args }
}

export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

/** Thrown when destroy() has already run for a session: no new cloud work may start after it. */
export function stoppedError(session) {
  return Object.assign(new Error('the cloud scan was stopped'), { name: 'AbortError', session })
}
