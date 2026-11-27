// No container runtime? Offer to install one, asking first at every step.
//
// git-bouncer runs its checks inside a throwaway container, so it needs Podman or Docker. When it
// finds neither, "command not found" leaves people stuck. But installing software on someone's
// machine is a big deal, so this module follows four rules:
//
//  1. Explain the choice first, in plain language, and let the person pick one or cancel.
//  2. Show the exact command, then run it only after an explicit yes. One yes per command: saying
//     yes to "install Podman" is not saying yes to "create a virtual machine". Only the boolean
//     `true` counts as yes; anything else (a typo, "y" as a string, an error) counts as no.
//  3. Never escalate. Nothing here runs sudo. On Linux, where installing needs root, the commands
//     are printed so the person can read them and run them themselves.
//  4. Never in non-interactive mode. In CI, with --json, or with no terminal, nothing is offered
//     and nothing runs; the caller gets the manual instructions to print instead.
//
// Everything that touches the outside world (finding programs, asking questions, running
// commands, printing) is passed in, so the tests drive every path without installing anything.

import { spawn } from 'node:child_process'
import { accessSync, constants, lstatSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { clean } from '../ui/sanitize.js'

// Official pages only. Docker's terms change, so we link them instead of quoting numbers.
export const LINKS = Object.freeze({
  podman: 'https://podman.io/docs/installation',
  dockerDesktop: 'https://www.docker.com/products/docker-desktop/',
  dockerTerms: 'https://docs.docker.com/subscription/desktop-license/',
  dockerEngine: 'https://docs.docker.com/engine/install/',
  colima: 'https://github.com/abiosoft/colima',
})

// winget package IDs, checked against the manifests in github.com/microsoft/winget-pkgs: both
// download their installers from the publisher's own release URLs. `--source winget` pins the
// lookup to that repository, and `-e` (exact) stops a similarly named package from matching.
export const WINGET_IDS = Object.freeze({ podman: 'RedHat.Podman', docker: 'Docker.DockerDesktop' })

// From https://podman.io/docs/installation. Printed, never run: they need root.
const LINUX_PODMAN = Object.freeze({
  apt: ['sudo apt-get update', 'sudo apt-get -y install podman'],
  dnf: ['sudo dnf -y install podman'],
  pacman: ['sudo pacman -S podman'],
  zypper: ['sudo zypper install podman'],
  apk: ['sudo apk add podman'],
})

// os-release ID / ID_LIKE values -> package manager. Derivatives (Mint, Pop!_OS, Rocky, Manjaro,
// openSUSE Tumbleweed...) name their parent in ID_LIKE, so the parents are enough here.
const LINUX_FAMILIES = [
  ['apt', ['debian', 'ubuntu']],
  ['dnf', ['fedora', 'rhel', 'centos']],
  ['pacman', ['arch']],
  ['zypper', ['suse', 'opensuse', 'sles']],
  ['apk', ['alpine']],
]
// Used only when os-release is missing or unfamiliar: is the package manager itself on PATH?
const PM_PROGRAMS = [['apt', 'apt-get'], ['dnf', 'dnf'], ['pacman', 'pacman'], ['zypper', 'zypper'], ['apk', 'apk']]

const show = argv => argv.join(' ') // every argv here is a constant from this file
const DOCTOR = 'Then run "bouncer doctor" to check that git-bouncer can use it.'

/**
 * Read the fields we need from /etc/os-release text. Unknown or malformed lines are ignored.
 * @param {string|null} text
 * @returns {{id: string|null, idLike: string[], name: string|null}}
 */
export function parseOsRelease(text) {
  const fields = new Map()
  if (typeof text === 'string') {
    for (const raw of text.slice(0, 64 * 1024).split(/\r?\n/)) {
      const m = /^([A-Z0-9_]+)=(.*)$/.exec(raw.trim())
      if (!m) continue
      let value = m[2].trim()
      if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0]) value = value.slice(1, -1)
      fields.set(m[1], value)
    }
  }
  const words = v => (v ?? '').toLowerCase().split(/\s+/).filter(Boolean)
  return { id: words(fields.get('ID'))[0] ?? null, idLike: words(fields.get('ID_LIKE')), name: fields.get('PRETTY_NAME') || fields.get('NAME') || null }
}

function linuxPackageManager(osRelease, has) {
  const { id, idLike } = parseOsRelease(osRelease)
  for (const candidate of [id, ...idLike]) {
    for (const [pm, ids] of LINUX_FAMILIES) if (candidate && ids.includes(candidate)) return pm
  }
  for (const [pm, program] of PM_PROGRAMS) if (has(program) === true) return pm
  return null
}

/**
 * Work out what can be offered on this machine. Pure: it runs nothing and reads nothing itself.
 *
 * Each option has:
 *   steps   commands git-bouncer may run, each only after its own yes ([] when it won't run anything)
 *   manual  what to do yourself instead (always present)
 *   after   what's left to do once every step has succeeded
 *   notes   shown before the steps
 *
 * @param {{platform?: string, has: (cmd: string) => boolean, osRelease?: string|null}} opts
 *   has: is this program on PATH?  osRelease: the text of /etc/os-release (Linux only)
 */
export function planInstall({ platform = process.platform, has, osRelease = null } = {}) {
  if (typeof has !== 'function') throw new TypeError('planInstall needs has(cmd), which says whether a program is on PATH.')
  const present = { podman: has('podman') === true, docker: has('docker') === true }
  let packageManager = null
  let distro = null
  let podman
  let docker

  if (platform === 'darwin') {
    packageManager = has('brew') === true ? 'brew' : null
    podman = option('podman', 'Podman', {
      notes: packageManager ? [`Podman's own docs recommend their installer (${LINKS.podman}). The Homebrew package used here is maintained by the Homebrew community.`] : [],
      steps: packageManager ? [
        { argv: ['brew', 'install', 'podman'], installs: true, what: 'Installs Podman with Homebrew.' },
        { argv: ['podman', 'machine', 'init'], what: 'Creates the small Linux virtual machine that Podman runs containers in. It downloads a disk image, so it can take a few minutes.' },
        { argv: ['podman', 'machine', 'start'], what: 'Starts that virtual machine.' },
      ] : [],
      manual: [`Download the Podman installer for macOS: ${LINKS.podman}`, 'Then run: podman machine init', 'Then run: podman machine start'],
      after: [DOCTOR],
    })
    docker = option('docker', 'Docker Desktop', {
      steps: packageManager ? [
        { argv: ['brew', 'install', '--cask', 'docker-desktop'], installs: true, what: 'Installs Docker Desktop with Homebrew. Homebrew may ask for your Mac password to finish.' },
      ] : [],
      manual: [`Download Docker Desktop for Mac: ${LINKS.dockerDesktop}`, 'Open Docker Desktop once. It asks you to accept Docker\'s terms, then starts its engine.'],
      after: ['Open Docker Desktop from your Applications folder once. It asks you to accept Docker\'s terms, then starts its engine.', DOCTOR],
    })
  } else if (platform === 'win32') {
    packageManager = has('winget') === true ? 'winget' : null
    podman = option('podman', 'Podman', {
      notes: ['Podman on Windows needs Windows 11 or later. It runs containers in WSL 2 (or Hyper-V).'],
      steps: packageManager ? [
        { argv: ['winget', 'install', '-e', '--id', WINGET_IDS.podman, '--source', 'winget'], installs: true, what: 'Installs Podman with winget. Windows may ask you to allow the installer to make changes.' },
      ] : [],
      manual: [`Download the Podman installer for Windows: ${LINKS.podman}`, 'Then, in a new terminal, run: podman machine init', 'Then run: podman machine start'],
      // A new terminal, because the installer's PATH change doesn't reach terminals that are already open.
      after: ['Open a new terminal, so that podman is on your PATH.', 'Then run: podman machine init', 'Then run: podman machine start', DOCTOR],
    })
    docker = option('docker', 'Docker Desktop', {
      steps: packageManager ? [
        { argv: ['winget', 'install', '-e', '--id', WINGET_IDS.docker, '--source', 'winget'], installs: true, what: 'Installs Docker Desktop with winget. Windows may ask you to allow the installer to make changes.' },
      ] : [],
      manual: [`Download Docker Desktop for Windows: ${LINKS.dockerDesktop}`, 'Start Docker Desktop once. It asks you to accept Docker\'s terms, then starts its engine.'],
      after: ['Start Docker Desktop from the Start menu. It asks you to accept Docker\'s terms, and may ask you to sign out or restart.', DOCTOR],
    })
  } else if (platform === 'linux') {
    packageManager = linuxPackageManager(osRelease, has)
    const name = parseOsRelease(osRelease).name
    distro = name ? clean(name, { max: 80 }) : null // os-release is local, but it's still text we didn't write
    podman = option('podman', 'Podman', {
      notes: ['Installing needs administrator rights (sudo), so git-bouncer prints the commands instead of running them. Read them, then run them yourself.'],
      steps: [],
      manual: [
        ...(packageManager ? LINUX_PODMAN[packageManager].map(c => `Run: ${c}`) : []),
        packageManager ? `Other distributions and details: ${LINKS.podman}` : `Find the command for your distribution: ${LINKS.podman}`,
        DOCTOR,
      ],
      after: [DOCTOR],
    })
    docker = option('docker', 'Docker Engine', {
      steps: [],
      manual: [
        `Install Docker Engine with Docker's instructions for your distribution: ${LINKS.dockerEngine}`,
        'Those instructions also offer to add you to the "docker" group. Know that being in that group is equivalent to root access on this machine.',
        DOCTOR,
      ],
      after: [DOCTOR],
    })
  } else {
    podman = option('podman', 'Podman', { steps: [], manual: [`Install Podman: ${LINKS.podman}`, DOCTOR], after: [DOCTOR] })
    docker = option('docker', 'Docker', { steps: [], manual: [`Install Docker: ${LINKS.dockerEngine}`, DOCTOR], after: [DOCTOR] })
  }

  // Already there (just not usable right now)? Then installing it again is the wrong advice.
  const vm = platform === 'darwin' || platform === 'win32'
  if (present.podman) {
    podman = option('podman', podman.name, {
      installed: true, steps: [],
      manual: vm
        ? ['Podman is already installed. If git-bouncer can\'t use it, its virtual machine is probably not running.', 'Run: podman machine start', 'If you have never created one, run this first: podman machine init', DOCTOR]
        : ['Podman is already installed.', 'Run "bouncer doctor" to see why git-bouncer can\'t use it.'],
    })
  }
  if (present.docker) {
    docker = option('docker', docker.name, {
      installed: true, steps: [],
      manual: ['Docker is already installed. Make sure Docker Desktop (or the Docker engine) is running.', DOCTOR],
    })
  }
  return { platform, packageManager, distro, options: { podman, docker } }
}

function option(key, name, { installed = false, notes = [], steps = [], manual = [], after = [] }) {
  return { key, name, installed, notes, steps, manual, after }
}

/** The one screen that explains the choice. */
export function explainChoices(plan) {
  const vm = plan.platform === 'darwin' || plan.platform === 'win32'
  const lines = [
    'git-bouncer checks repositories inside a throwaway container, so it needs Podman or Docker,',
    'and it couldn\'t find either one. It can help you install one now.',
    'Nothing is installed unless you say yes, and you can cancel at any step.',
    '',
    '  Podman (recommended)',
    '    Free and open source. No account or sign-up needed.',
    '    Daemonless: no background service running as root. On Linux, containers run as your own user.',
  ]
  if (vm) lines.push('    On macOS and Windows it runs containers inside a small Linux virtual machine.')
  lines.push('')
  if (plan.platform === 'linux') {
    lines.push(
      '  Docker Engine',
      '    Open source on Linux. (Docker Desktop, Docker\'s separate desktop app, has its own license terms:',
      `    ${LINKS.dockerTerms})`,
    )
  } else {
    lines.push(
      '  Docker Desktop',
      '    Free for personal use, education, non-commercial open source projects and small businesses.',
      '    Larger companies and government organizations need a paid subscription.',
      `    Check Docker's current terms before you use it for work: ${LINKS.dockerTerms}`,
    )
  }
  lines.push('', '  Cancel', '    Install nothing now. You can install either one yourself later.')
  if (plan.platform === 'darwin') {
    lines.push('', `Also open source, on a Mac: Colima runs the Docker engine without Docker Desktop (${LINKS.colima}).`)
  }
  if (plan.platform === 'linux' && plan.distro) {
    lines.push('', `This looks like ${plan.distro}${plan.packageManager ? ` (${plan.packageManager})` : ''}.`)
  }
  return lines.join('\n')
}

function manualSummary(plan) {
  const linux = plan.platform === 'linux'
  return [
    `Install Podman (recommended, free and open source): ${LINKS.podman}`,
    linux
      ? `Or Docker Engine: ${LINKS.dockerEngine}`
      : `Or Docker Desktop: ${LINKS.dockerDesktop} (check Docker's license terms for work use: ${LINKS.dockerTerms})`,
    DOCTOR,
  ]
}

/**
 * Explain the choice, let the person pick, and run each install step only after an explicit yes.
 *
 * @param {object} io
 * @param {string} [io.platform]  defaults to process.platform
 * @param {(cmd: string) => boolean} [io.has]  is a program on PATH (defaults to a real PATH lookup)
 * @param {(question: string, opts: {default: boolean}) => Promise<boolean>} [io.confirm]  yes/no prompt
 * @param {(question: string, options: {key: string, label: string}[]) => Promise<string>} [io.choose]
 * @param {(cmd: string, args: string[]) => Promise<{code: number|null}>} [io.exec]  run a program, stdio inherited
 * @param {(text: string) => void} [io.out]  print
 * @param {() => string|null} [io.readOsRelease]  the text of /etc/os-release, or null
 * @param {boolean} [io.interactive]  false (or no confirm/choose) means: offer nothing, run nothing
 * @returns {Promise<{installed: boolean, runtime?: 'podman'|'docker', reason: string, nextSteps: string[]}>}
 *   installed: an install command ran and succeeded during this call.
 *   reason: 'installed' | 'non-interactive' | 'cancelled' | 'manual' | 'already-installed' | 'declined' | 'failed'
 *   Prompts that throw (Ctrl-C) propagate to the caller; nothing runs after them.
 */
export async function offerInstall({
  platform = process.platform,
  has = onPath,
  confirm,
  choose,
  exec = runCommand,
  out = text => process.stdout.write(`${text}\n`),
  readOsRelease: read = readOsRelease,
  interactive = true,
} = {}) {
  const plan = planInstall({ platform, has, osRelease: platform === 'linux' ? read() : null })
  if (interactive !== true || typeof confirm !== 'function' || typeof choose !== 'function') {
    return { installed: false, reason: 'non-interactive', nextSteps: manualSummary(plan) }
  }

  out(explainChoices(plan))
  const picked = await choose('Which would you like to install?', [
    { key: 'podman', label: `${plan.options.podman.name} (recommended)` },
    { key: 'docker', label: plan.options.docker.name },
    { key: 'cancel', label: 'Cancel' },
  ])
  // Only the two known keys select anything; anything else, including a typo, is a cancel.
  if (picked !== 'podman' && picked !== 'docker') {
    out('Cancelled. Nothing was installed.')
    return { installed: false, reason: 'cancelled', nextSteps: manualSummary(plan) }
  }
  const opt = plan.options[picked]
  const runtime = picked

  if (opt.installed || opt.steps.length === 0) {
    out(['', `${opt.name}:`, ...opt.notes.map(n => `  ${n}`), ...opt.manual.map(m => `  ${m}`)].join('\n'))
    return { installed: false, runtime, reason: opt.installed ? 'already-installed' : 'manual', nextSteps: opt.manual }
  }

  const total = opt.steps.length
  out(['', ...opt.notes, total === 1 ? 'This takes 1 step, and it asks you first.' : `This takes ${total} steps. Each one asks you first.`].join('\n'))
  let installed = false
  for (let i = 0; i < total; i++) {
    const step = opt.steps[i]
    const cmd = show(step.argv)
    const rest = opt.steps.slice(i).map(s => `Run: ${show(s.argv)}`)
    out(`\nStep ${i + 1} of ${total}: ${cmd}\n  ${step.what}`)
    if (await confirm(`Run "${cmd}" now?`, { default: false }) !== true) {
      out('Skipped. Nothing else was run.')
      return { installed, runtime, reason: 'declined', nextSteps: [...rest, ...opt.after] }
    }
    let result
    try {
      result = await exec(step.argv[0], step.argv.slice(1))
    } catch (e) {
      result = { code: null, error: e && e.message ? e.message : String(e) }
    }
    if (!result || result.code !== 0) {
      const why = result && result.code !== null && result.code !== undefined ? `exit code ${result.code}` : clean(result && result.error ? result.error : 'it could not be started')
      out(`"${cmd}" did not finish (${why}). Nothing else was run.`)
      return { installed, runtime, reason: 'failed', nextSteps: [`"${cmd}" did not finish (${why}). Its output above should say why.`, ...rest, ...opt.after] }
    }
    if (step.installs) installed = true
  }
  out(`\n${opt.name} is installed.`)
  return { installed, runtime, reason: 'installed', nextSteps: opt.after }
}

// ---------------------------------------------------------------------------------------------
// The real implementations of `has` and `exec`, used when the caller doesn't pass its own.

/** The text of /etc/os-release (or /usr/lib/os-release), or null. */
export function readOsRelease() {
  for (const file of ['/etc/os-release', '/usr/lib/os-release']) {
    try { return readFileSync(file, 'utf8').slice(0, 64 * 1024) } catch { /* try the next one */ }
  }
  return null
}

/**
 * Find a program on PATH and return its absolute path, or null.
 *
 * Relative PATH entries ("", ".", "bin") are skipped: they mean "the current folder", and the
 * current folder may be a repository you're about to check. On Windows only .com and .exe are
 * considered, because those are the only files a process can be started from without a shell.
 */
export function findOnPath(cmd, { env = process.env, platform = process.platform } = {}) {
  if (typeof cmd !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(cmd)) return null
  const win = platform === 'win32'
  const p = win ? path.win32 : path.posix
  const value = (win ? env.PATH ?? env.Path ?? env.path : env.PATH) ?? ''
  const names = win ? (/\.(com|exe)$/i.test(cmd) ? [cmd] : [`${cmd}.com`, `${cmd}.exe`]) : [cmd]
  for (const entry of value.split(win ? ';' : ':')) {
    const dir = win ? entry.replace(/^"(.*)"$/, '$1') : entry
    if (!dir || !p.isAbsolute(dir)) continue
    for (const name of names) {
      const file = p.join(dir, name)
      if (isProgram(file, win)) return file
    }
  }
  return null
}

/** Is a program on PATH? (The default `has`.) */
export function onPath(cmd, opts) {
  return findOnPath(cmd, opts) !== null
}

function isProgram(file, win) {
  try {
    if (!statSync(file).isFile()) return false
    if (!win) accessSync(file, constants.X_OK)
    return true
  } catch {
    // stat can fail on Windows "app execution aliases" (how winget.exe is installed); they still run.
    if (!win) return false
    try { lstatSync(file); return true } catch { return false }
  }
}

/**
 * Run a program with the terminal attached, so the person sees the installer's own output and
 * prompts. An argument array and no shell, so nothing is ever re-parsed. The program is resolved
 * to an absolute path first: on Windows, starting a bare name looks in the current folder before
 * PATH, so a "winget.exe" sitting in the current folder would otherwise run instead of the real one.
 * @returns {Promise<{code: number|null, signal?: string|null, error?: string}>}
 */
export function runCommand(cmd, args, { env = process.env, platform = process.platform } = {}) {
  return new Promise(resolve => {
    const file = path.isAbsolute(cmd) ? cmd : findOnPath(cmd, { env, platform })
    if (!file) return resolve({ code: null, error: `${cmd} was not found on your PATH` })
    let child
    try {
      child = spawn(file, args, { stdio: 'inherit', shell: false })
    } catch (e) {
      return resolve({ code: null, error: e.message })
    }
    child.on('error', e => resolve({ code: null, error: e.message }))
    child.on('close', (code, signal) => resolve({ code, signal }))
  })
}
