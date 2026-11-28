// Docker / Podman sandbox runtime.
//
// The sandbox is a container with everything worth stealing taken away:
//   --cap-drop=ALL                    no Linux capabilities (no raw sockets, no chown, no mount, ...)
//   --security-opt=no-new-privileges  setuid binaries can't raise privileges
//   --read-only                       the container's own filesystem can't be modified
//   --user 10001:10001                not root
//   --tmpfs /work, /tmp (noexec)      the only writable places; nothing there can be executed directly,
//                                     and they vanish with the container
//   --pids-limit / --memory / --cpus  a repo can't fork-bomb or exhaust the machine
//   no -v/--mount, no Docker socket   your files and the Docker daemon are out of reach
//   no -e                             your environment variables (tokens!) are never passed in
//
// Docker and Podman share these flags, so one implementation serves both.

import { createHash, randomBytes } from 'node:crypto'
import { readdir, readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { run, which } from '../proc.js'

export const SANDBOX_DIR = fileURLToPath(new URL('../../sandbox/', import.meta.url))
export const LABEL = 'dev.git-bouncer.sandbox=1'

const MINIMAL_ENV = () => {
  // The container CLI itself needs PATH and HOME (and DOCKER_HOST/contexts if the user set them).
  // Nothing here is passed into the container: `docker run` doesn't forward the environment.
  const keep = ['PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'TMPDIR', 'TEMP', 'TMP', 'DOCKER_HOST', 'DOCKER_CONTEXT',
    'DOCKER_CONFIG', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY', 'CONTAINER_HOST', 'CONTAINER_CONNECTION', 'XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME']
  return Object.fromEntries(keep.filter(k => process.env[k] !== undefined).map(k => [k, process.env[k]]))
}

/** The exact `run` flags. Exported so tests (and curious readers) can see them in one place. */
export function runArgs({ name, image, workSize = '3g' }) {
  return ['run', '--detach', '--name', name, ...sandboxFlags({ workSize }), image]
}

/**
 * The hardening every sandbox gets, local or in the cloud (src/runtimes/gcp.js and aws.js use this
 * too), so the two can't drift apart. `--init` makes a tiny init process PID 1: it reaps orphaned
 * processes, and keeps the scanner's own command line out of the fixed, well-known /proc/1/cmdline.
 * `--pull=never` means a missing image is an error, never a download of a look-alike name.
 */
export function sandboxFlags({ workSize = '3g' } = {}) {
  return [
    '--init',
    '--label', LABEL,
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--read-only',
    '--user', '10001:10001',
    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=768m',
    // mode=1777 rather than uid=/gid= options, which Podman rejects. There is only one user in the box.
    '--tmpfs', `/work:rw,nosuid,nodev,noexec,size=${workSize},mode=1777`,
    '--pids-limit', '512',
    '--memory', '4g',
    '--cpus', '2',
    '--network', 'bridge',
    '--pull=never',
  ]
}

/** Content hash of the sandbox folder, so a changed Dockerfile or scanner means a new image tag. */
export async function sandboxHash(dir = SANDBOX_DIR) {
  const files = []
  const walk = async rel => {
    for (const e of await readdir(path.join(dir, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name
      if (e.isDirectory()) await walk(r)
      else if (e.isFile()) files.push(r)
    }
  }
  await walk('')
  const h = createHash('sha256')
  for (const f of files.sort()) {
    h.update(`${f}\0`)
    h.update(await readFile(path.join(dir, f)))
    h.update('\0')
  }
  return h.digest('hex').slice(0, 16)
}

/**
 * @param {'docker'|'podman'} engine
 * @param {{exec?: typeof run, onLog?: (s: string) => void}} [opts]
 */
export function createContainerRuntime(engine, { exec = run, onLog = () => {} } = {}) {
  if (engine !== 'docker' && engine !== 'podman') throw new Error(`unknown engine ${engine}`)
  // The engine is found once, on trusted PATH entries only (never the current folder or node_modules).
  let bin
  const cli = async (args, o = {}) => {
    if (bin === undefined) bin = (await which(engine)) ?? null
    if (!bin) return { code: -1, stdout: '', stderr: `${engine} not found`, error: Object.assign(new Error(`${engine} not found`), { code: 'ENOENT' }) }
    return exec(bin, args, { env: MINIMAL_ENV(), ...o })
  }

  return {
    name: engine,

    async available() {
      const r = await cli(['version', '--format', '{{.Server.Version}}'], { timeoutMs: 15_000 })
      if (r.code === 0 && r.stdout.trim()) return { ok: true, version: r.stdout.trim().slice(0, 40) }
      if (r.error && r.error.code === 'ENOENT') return { ok: false, reason: `${engine} is not installed` }
      return { ok: false, reason: engine === 'podman'
        ? 'podman is installed but not running (try: podman machine start)'
        : 'docker is installed but the Docker engine is not running (start Docker Desktop, Colima or the docker service)' }
    },

    /** Build (or reuse) the image and return its content ID; containers are started by ID, not by tag. */
    async ensureImage(version) {
      const tag = `git-bouncer-sandbox:${version}-${await sandboxHash()}`
      const inspect = await cli(['image', 'inspect', '--format', '{{.Id}}', tag], { timeoutMs: 30_000 })
      // Docker prints "sha256:<hex>", Podman prints just "<hex>"; both start a container by ID.
      if (inspect.code === 0 && /^(sha256:)?[0-9a-f]{64}$/.test(inspect.stdout.trim())) return inspect.stdout.trim()
      onLog('Building the sandbox image (first run only, about a minute)...')
      const b = await cli(['build', '--tag', tag, '--label', LABEL, SANDBOX_DIR], { timeoutMs: 20 * 60_000, onStderr: s => onLog(s.trimEnd()) })
      if (b.code !== 0) throw new Error(`could not build the sandbox image: ${(b.stderr || b.stdout).trim().split('\n').slice(-3).join(' ')}`)
      const id = (await cli(['image', 'inspect', '--format', '{{.Id}}', tag], { timeoutMs: 30_000 })).stdout.trim()
      if (!/^(sha256:)?[0-9a-f]{64}$/.test(id)) throw new Error('could not read the sandbox image ID after building it')
      return id
    },

    /** Remove sandboxes left behind by a crashed or killed run (older than two hours, ours only). */
    async sweepStale(now = Date.now()) {
      const ls = await cli(['ps', '--all', '--filter', `label=${LABEL}`, '--format', '{{.Names}}\t{{.CreatedAt}}'], { timeoutMs: 30_000 })
      if (ls.code !== 0) return 0
      let n = 0
      for (const line of ls.stdout.split('\n').filter(Boolean)) {
        const [name, created] = line.split('\t')
        const t = Date.parse((created || '').replace(/ [A-Z]{2,5}$/, '').replace(' +0000', 'Z'))
        if (/^git-bouncer-[0-9a-f]{12}$/.test(name) && Number.isFinite(t) && now - t > 2 * 3600_000) {
          await cli(['rm', '--force', '--volumes', name], { timeoutMs: 60_000 }); n++
        }
      }
      return n
    },

    /** Start the sandbox, run the scanner, return its raw output plus a session for later steps. */
    async scan({ url, ref, nonce, image, onSession = () => {} }) {
      const name = `git-bouncer-${randomBytes(6).toString('hex')}`
      const session = { engine, name }
      onSession(session) // known before the container exists, so an interrupt can always remove it
      const started = await cli(runArgs({ name, image }), { timeoutMs: 60_000 })
      if (started.code !== 0) throw Object.assign(new Error(`could not start the sandbox: ${started.stderr.trim().split('\n').pop()}`), { session })
      // The nonce goes in on stdin: arguments are visible to every process in the container (/proc/*/cmdline).
      const scanArgs = ['exec', '--interactive', name, 'node', '/opt/bouncer/scanner/main.js', '--url', url, '--nonce-stdin']
      if (ref) scanArgs.push('--ref', ref)
      const r = await cli(scanArgs, { timeoutMs: 30 * 60_000, input: `${nonce}\n`, onStderr: s => onLog(s.trimEnd()) })
      return { reportText: r.stdout, exitCode: r.code, timedOut: r.timedOut, session }
    },

    /** Read a file the scanner left in /work/repo (e.g. a lockfile generated in the sandbox). */
    async readFile(session, relPath, maxBytes = 50 * 1024 * 1024) {
      if (!/^[A-Za-z0-9._-]+$/.test(relPath)) throw new Error('readFile only reads plain file names in the repo root')
      const r = await cli(['exec', session.name, 'cat', '--', `/work/repo/${relPath}`], { timeoutMs: 60_000, maxStdout: maxBytes })
      if (r.code !== 0 || r.truncated) return null
      return r.stdout
    },

    async destroy(session) {
      if (!session) return
      await cli(['rm', '--force', '--volumes', session.name], { timeoutMs: 60_000 })
    },

    describe() { return `${engine} (local, locked-down container)` },
  }
}

/** Pick Docker or Podman, whichever is installed and running (Docker first if both are). */
export async function detectContainerRuntime(opts) {
  const reasons = []
  for (const engine of ['docker', 'podman']) {
    const rt = createContainerRuntime(engine, opts)
    const a = await rt.available()
    if (a.ok) return { runtime: rt, reasons }
    reasons.push(a.reason)
  }
  return { runtime: null, reasons }
}
