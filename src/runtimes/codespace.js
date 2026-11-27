// GitHub Codespaces sandbox runtime: a throwaway cloud VM, for people without Docker or Podman.
//
// Where the Codespace is created FROM matters as much as the Codespace itself. Creating it from the
// suspect repo would run that repo's devcontainer.json (postCreateCommand and friends) at creation
// time, with a GitHub token in the environment. So it is created from git-bouncer's own repo, using
// .devcontainer/sandbox/devcontainer.json (a pinned image with no lifecycle commands). The scanner is
// copied in with `gh codespace cp` (literal paths, never --expand), tokens are removed from the
// scanner's environment, and the Codespace is deleted afterwards.
//
// Cost: it uses your account's Codespaces allowance (personal accounts get a free monthly quota).

import { run } from '../proc.js'
import { SANDBOX_DIR } from './container.js'

// Same osv-scanner pins as sandbox/Dockerfile; a unit test keeps them in sync.
export const OSV = Object.freeze({
  version: '2.7.1',
  sha256: { amd64: 'fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8', arm64: '983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81' },
})

export const SANDBOX_REPO = 'ylove/git-bouncer'
export const DEVCONTAINER = '.devcontainer/sandbox/devcontainer.json'

/** Quote one argument for a POSIX shell. Every value passed over ssh goes through this. */
export function shQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`
}

/** Commands run inside the Codespace. All constants, except the quoted, already-validated scan inputs. */
export function setupScript() {
  return [
    'set -eu',
    'rm -rf "$HOME/bouncer" && mkdir -p "$HOME/bouncer/work"',
    'case "$(uname -m)" in',
    `  x86_64) a=amd64; s=${OSV.sha256.amd64} ;;`,
    `  aarch64|arm64) a=arm64; s=${OSV.sha256.arm64} ;;`,
    '  *) echo "unsupported architecture" >&2; exit 1 ;;',
    'esac',
    `curl -fsSL --proto '=https' --tlsv1.2 -o "$HOME/bouncer/osv-scanner" "https://github.com/google/osv-scanner/releases/download/v${OSV.version}/osv-scanner_linux_$a"`,
    'echo "$s  $HOME/bouncer/osv-scanner" | sha256sum -c - >/dev/null',
    'chmod 0755 "$HOME/bouncer/osv-scanner"',
    ': > "$HOME/bouncer/osv-scanner.toml"',
  ].join('\n')
}

/** The nonce isn't in here: it goes in on stdin, so it never appears in a process listing. */
export function scanCommand({ url, ref }) {
  const args = [
    'env', '-u', 'GITHUB_TOKEN', '-u', 'GH_TOKEN', '-u', 'GITHUB_CODESPACE_TOKEN', '-u', 'GIT_ASKPASS', '-u', 'GIT_CONFIG_PARAMETERS',
    'node', '"$HOME/bouncer/scanner/main.js"',
    '--url', shQuote(url), '--nonce-stdin',
    ...(ref ? ['--ref', shQuote(ref)] : []),
    '--dir', '"$HOME/bouncer/work/repo"',
    '--osv', '"$HOME/bouncer/osv-scanner"',
    '--osv-config', '"$HOME/bouncer/osv-scanner.toml"',
  ]
  return args.join(' ')
}

export function createArgs({ branch = 'main', machine = 'basicLinux32gb' } = {}) {
  return ['codespace', 'create', '--repo', SANDBOX_REPO, '--branch', branch, '--devcontainer-path', DEVCONTAINER,
    ...(machine ? ['--machine', machine] : []), '--idle-timeout', '10m', '--retention-period', '1h',
    '--display-name', 'git-bouncer sandbox', '--default-permissions']
}

/**
 * @param {{exec?: typeof run, onLog?: (s: string) => void, branch?: string}} [opts]
 */
export function createCodespaceRuntime({ exec = run, onLog = () => {}, branch = process.env.BOUNCER_CODESPACE_BRANCH || 'main' } = {}) {
  // BOUNCER_CODESPACE_BRANCH lets maintainers test a PR's sandbox config; it can only pick a branch of
  // git-bouncer's own repo, never a different repo.
  if (!/^[A-Za-z0-9._/-]{1,100}$/.test(branch) || branch.startsWith('-')) throw new Error('invalid BOUNCER_CODESPACE_BRANCH')
  const gh = (args, o = {}) => exec('gh', args, { timeoutMs: 10 * 60_000, ...o })
  const ssh = (name, command, o) => gh(['codespace', 'ssh', '--codespace', name, '--', command], o)

  return {
    name: 'codespace',

    async available() {
      const status = await gh(['auth', 'status'], { timeoutMs: 20_000 })
      if (status.error && status.error.code === 'ENOENT') return { ok: false, reason: 'the GitHub CLI (gh) is not installed' }
      if (status.code !== 0) return { ok: false, reason: 'gh is not signed in (run: gh auth login)' }
      const probe = await gh(['api', 'user/codespaces?per_page=1'], { timeoutMs: 20_000 })
      if (probe.code === 0) return { ok: true }
      if (/codespace/.test(probe.stderr) && /scope/.test(probe.stderr)) {
        return { ok: false, reason: 'gh needs the "codespace" permission (run: gh auth refresh -h github.com -s codespace)' }
      }
      return { ok: false, reason: 'GitHub Codespaces is not available for this account' }
    },

    async ensureImage() { return null },

    async scan({ url, ref, nonce, onSession = () => {} }) {
      onLog('Creating a throwaway Codespace from git-bouncer\'s own sandbox config (about a minute)...')
      let created = await gh(createArgs({ branch }))
      if (created.code !== 0 && /machine/i.test(created.stderr)) created = await gh(createArgs({ branch, machine: null }))
      const name = created.stdout.trim().split('\n').pop()
      if (created.code !== 0 || !/^[A-Za-z0-9-]{1,90}$/.test(name || '')) {
        throw new Error(`could not create a Codespace: ${created.stderr.trim().split('\n').pop() || 'unknown error'}`)
      }
      const session = { engine: 'codespace', name }
      onSession(session) // registered at once, so an interrupt deletes the Codespace
      try {
        const setup = await ssh(name, setupScript(), { timeoutMs: 5 * 60_000 })
        if (setup.code !== 0) throw new Error(`could not prepare the Codespace: ${setup.stderr.trim().split('\n').pop()}`)
        const cp = await gh(['codespace', 'cp', '--codespace', name, '--recursive', `${SANDBOX_DIR}scanner`, 'remote:bouncer/scanner'])
        if (cp.code !== 0) throw new Error(`could not copy the scanner into the Codespace: ${cp.stderr.trim().split('\n').pop()}`)
        const r = await ssh(name, scanCommand({ url, ref }), { timeoutMs: 30 * 60_000, input: `${nonce}\n`, onStderr: s => onLog(s.trimEnd()) })
        return { reportText: r.stdout, exitCode: r.code, timedOut: r.timedOut, session }
      } catch (e) {
        e.session = session
        throw e
      }
    },

    async readFile(session, relPath, maxBytes = 50 * 1024 * 1024) {
      if (!/^[A-Za-z0-9._-]+$/.test(relPath)) throw new Error('readFile only reads plain file names in the repo root')
      const r = await ssh(session.name, `cat -- "$HOME/bouncer/work/repo/"${shQuote(relPath)}`, { timeoutMs: 2 * 60_000, maxStdout: maxBytes })
      return r.code === 0 && !r.truncated ? r.stdout : null
    },

    async destroy(session) {
      if (!session) return
      await gh(['codespace', 'delete', '--codespace', session.name, '--force'], { timeoutMs: 2 * 60_000 })
    },

    describe() { return 'a throwaway GitHub Codespace (uses your Codespaces allowance)' },
  }
}
