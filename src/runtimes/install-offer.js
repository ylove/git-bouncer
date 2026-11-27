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
//  3. Never escalate for you. Nothing here runs sudo. Some installers ask for your password or a
//     Windows UAC prompt themselves, and the step says so before you agree. On Linux, where
//     installing needs root, the commands are printed for the person to read and run themselves.
//  4. Never without a person at a terminal. It only asks when the caller says it may
//     (interactive: true), stdin and stderr are both terminals, and CI isn't set. Otherwise nothing
//     is offered and nothing runs; the caller gets the manual instructions to print instead.
//
// Everything that touches the outside world (finding programs, asking questions, running
// commands, printing) is passed in, so the tests drive every path without installing anything.

import { accessSync, constants, lstatSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { run, which } from '../proc.js'
import { clean } from '../ui/sanitize.js'

// Official pages only. Docker's terms change, so we link them instead of quoting numbers.
export const LINKS = Object.freeze({
  podman: 'https://podman.io/docs/installation',
  podmanSite: 'https://podman.io',
  podmanReleases: 'https://github.com/podman-container-tools/podman/releases',
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

// Podman's own words, from the macOS section of https://podman.io/docs/installation.
const PODMAN_ON_HOMEBREW = 'It\'s not recommended to install via Homebrew because it is a community-maintained package manager, and we cannot guarantee the stability of the Podman installation.'

// One yes, one action: without this, `brew install` first runs `brew update`, which can upgrade
// Homebrew and refresh every formula before it does the thing you agreed to.
const BREW_ENV = Object.freeze({ HOMEBREW_NO_AUTO_UPDATE: '1' })

const show = argv => argv.join(' ')
// Every program a plan may need. offerInstall looks them all up once, before planning.
const PROBES = ['brew', 'winget', 'podman', 'docker', ...PM_PROGRAMS.map(([, program]) => program)]
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
 *   preferManual, alternative   the vendor recommends the manual route: show it first, and run
 *           the steps only after a separate yes to alternative.question
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
    // Podman's docs recommend their own installer and advise against Homebrew, so that's the order here.
    podman = option('podman', 'Podman', {
      preferManual: true,
      alternative: packageManager ? {
        notes: [`Homebrew can install it too, but Podman's docs say: "${PODMAN_ON_HOMEBREW}"`],
        question: 'Install it with Homebrew instead?',
      } : null,
      steps: packageManager ? [
        { argv: ['brew', 'install', 'podman'], installs: true, env: BREW_ENV, what: 'Installs Podman with Homebrew. Homebrew may also install or upgrade the packages Podman depends on.' },
        { argv: ['podman', 'machine', 'init'], what: 'Creates the small Linux virtual machine that Podman runs containers in. It downloads a disk image, so it can take a few minutes.' },
        { argv: ['podman', 'machine', 'start'], what: 'Starts that virtual machine.' },
      ] : [],
      manual: [
        `Podman recommends its own installer. Download it from ${LINKS.podmanSite} (or the .pkg from ${LINKS.podmanReleases}).`,
        'Then run: podman machine init',
        'Then run: podman machine start',
        DOCTOR,
      ],
      after: [DOCTOR],
    })
    docker = option('docker', 'Docker Desktop', {
      steps: packageManager ? [
        { argv: ['brew', 'install', '--cask', 'docker-desktop'], installs: true, env: BREW_ENV, what: 'Installs Docker Desktop with Homebrew. Homebrew may ask for your Mac password, and may also install the packages it depends on.' },
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

function option(key, name, { installed = false, notes = [], steps = [], manual = [], after = [], preferManual = false, alternative = null }) {
  return { key, name, installed, notes, steps, manual, after, preferManual, alternative }
}

/** The one screen that explains the choice. */
export function explainChoices(plan) {
  const vm = plan.platform === 'darwin' || plan.platform === 'win32'
  // Installed but not usable (a stopped VM, a Docker Desktop that isn't open) is a different problem.
  const present = [plan.options.podman, plan.options.docker].filter(o => o.installed).map(o => o.name)
  const lines = present.length === 0
    ? [
        'git-bouncer checks repositories inside a throwaway container, so it needs Podman or Docker,',
        'and it couldn\'t find either one. It can help you install one now.',
      ]
    : [
        'git-bouncer checks repositories inside a throwaway container, so it needs Podman or Docker.',
        `${present.join(' and ')} ${present.length === 1 ? 'is' : 'are'} installed, but git-bouncer couldn't use ${present.length === 1 ? 'it' : 'them'}.`,
        present.length === 1 ? 'Pick it below to see how to start it, or install the other one.' : 'Pick one below to see how to start it.',
      ]
  lines.push(
    'Nothing is installed unless you say yes, and you can cancel at any step.',
    '',
    '  Podman (recommended)',
    '    Free and open source. No account or sign-up needed.',
    '    Daemonless: no background service running as root. On Linux, containers run as your own user.',
  )
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
      '    Free for personal use, education, non-commercial open source and small businesses (Docker',
      '    limits both headcount and revenue). Professional use in larger organizations, and government',
      `    use, needs a paid subscription. Check the current terms: ${LINKS.dockerTerms}`,
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

function manualSummary(platform) {
  const linux = platform === 'linux'
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
 * Every program is resolved to an absolute path before the person is asked, and the question shows
 * that path ("Run /opt/homebrew/bin/brew install podman now?"). Then exactly that file is run, so
 * what was approved is what runs, whatever `exec` does with it.
 *
 * @param {object} io
 * @param {string} [io.platform]  defaults to process.platform
 * @param {(cmd: string) => Promise<string|null>} [io.resolve]  a program's absolute path, or null
 *   (default: findProgram, which checks known install locations, then trusted PATH folders)
 * @param {(question: string, opts: {defaultYes: boolean, safeAnswer: boolean}) => Promise<boolean>} [io.confirm]
 *   yes/no prompt, same shape as ui/prompt.js
 * @param {(question: string, options: {key: string, label: string}[]) => Promise<string>} [io.choose]
 * @param {(file: string, args: string[], opts: {cwd: string, env: object}) => Promise<{code: number|null, signal?: string|null, error?: Error|string}>} [io.exec]
 *   run an absolute path with stdio inherited (default: runInstaller)
 * @param {(text: string) => void} [io.out]  print (default: stderr, where the prompts are)
 * @param {() => string|null} [io.readOsRelease]  the text of /etc/os-release, or null
 * @param {Record<string, string|undefined>} [io.env]  the environment installers run with
 * @param {string} [io.home]  installers start in this folder (default: your home folder)
 * @param {boolean} [io.interactive]  the caller's go-ahead to ask. Default false: offer nothing, run nothing
 * @param {{stdin?: boolean, stderr?: boolean}} [io.isTTY]  are these terminals? (default: process.*.isTTY)
 * @returns {Promise<{installed: boolean, runtime?: 'podman'|'docker', reason: string, nextSteps: string[]}>}
 *   installed: an install command ran and succeeded during this call.
 *   reason: 'installed' | 'non-interactive' | 'cancelled' | 'manual' | 'already-installed' |
 *           'declined' | 'not-found' | 'failed'
 *   Prompts that throw (Ctrl-C) propagate to the caller; nothing runs after them.
 */
export async function offerInstall({
  platform = process.platform,
  env = process.env,
  home = homedir(),
  resolve = cmd => findProgram(cmd, { env, platform }),
  confirm,
  choose,
  exec = runInstaller,
  out = text => process.stderr.write(`${text}\n`),
  readOsRelease: read = readOsRelease,
  interactive = false,
  isTTY = { stdin: process.stdin.isTTY, stderr: process.stderr.isTTY },
} = {}) {
  // Checked here, not left to the caller: a forgotten flag or an auto-answering prompter must not
  // be able to install anything in CI or with nobody at the keyboard.
  const someoneIsThere = interactive === true && isTTY.stdin === true && isTTY.stderr === true && !env.CI
  if (!someoneIsThere || typeof confirm !== 'function' || typeof choose !== 'function') {
    return { installed: false, reason: 'non-interactive', nextSteps: manualSummary(platform) }
  }
  const found = new Map()
  for (const program of PROBES) found.set(program, await resolve(program))
  const plan = planInstall({ platform, has: program => typeof found.get(program) === 'string', osRelease: platform === 'linux' ? read() : null })

  out(explainChoices(plan))
  const picked = await choose('Which would you like to install?', [
    { key: 'podman', label: `${plan.options.podman.name} (recommended)` },
    { key: 'docker', label: plan.options.docker.name },
    { key: 'cancel', label: 'Cancel' },
  ])
  // Only the two known keys select anything; anything else, including a typo, is a cancel.
  if (picked !== 'podman' && picked !== 'docker') {
    out('Cancelled. Nothing was installed.')
    return { installed: false, reason: 'cancelled', nextSteps: manualSummary(platform) }
  }
  const opt = plan.options[picked]
  const runtime = picked

  if (opt.installed || opt.steps.length === 0) {
    out(['', `${opt.name}:`, ...opt.notes.map(n => `  ${n}`), ...opt.manual.map(m => `  ${m}`)].join('\n'))
    return { installed: false, runtime, reason: opt.installed ? 'already-installed' : 'manual', nextSteps: opt.manual }
  }
  if (opt.preferManual) {
    // The vendor's way first. Their discouraged route only runs after its own, separate yes.
    out(['', `${opt.name}:`, ...opt.manual.map(m => `  ${m}`), '', ...opt.alternative.notes].join('\n'))
    if (await confirm(opt.alternative.question, ASK) !== true) {
      return { installed: false, runtime, reason: 'manual', nextSteps: opt.manual }
    }
  }

  const total = opt.steps.length
  out(['', ...opt.notes, total === 1 ? 'This takes 1 step, and it asks you first.' : `This takes ${total} steps. Each one asks you first.`].join('\n'))
  let installed = false
  for (let i = 0; i < total; i++) {
    const step = opt.steps[i]
    const rest = opt.steps.slice(i).map(s => `Run: ${show(s.argv)}`)
    // Looked up now, not at planning time: "podman" only exists once step 1 has installed it.
    const file = await resolve(step.argv[0])
    if (typeof file !== 'string') {
      out(`\nCouldn't find ${step.argv[0]} in a trusted folder on your PATH. Nothing else was run.`)
      return { installed, runtime, reason: 'not-found', nextSteps: [`Open a new terminal, then continue with: ${show(step.argv)}`, ...rest.slice(1), ...opt.after] }
    }
    const cmd = show([clean(file), ...step.argv.slice(1)])
    out(`\nStep ${i + 1} of ${total}: ${cmd}\n  ${step.what}`)
    if (await confirm(`Run "${cmd}" now?`, ASK) !== true) {
      out('Skipped. Nothing else was run.')
      return { installed, runtime, reason: 'declined', nextSteps: [...rest, ...opt.after] }
    }
    let result
    try {
      // Started in your home folder, never the current one: that may be the repo being checked,
      // and on Windows the current folder is where a program looks for DLLs it doesn't ship.
      result = await exec(file, step.argv.slice(1), { cwd: home, env: { ...env, ...step.env } })
    } catch (e) {
      result = { code: null, error: e }
    }
    if (!result || result.code !== 0) {
      const why = failure(result)
      out(`"${cmd}" did not finish (${why}). Nothing else was run.`)
      return { installed, runtime, reason: 'failed', nextSteps: [`"${cmd}" did not finish (${why}). Its output above should say why.`, ...rest, ...opt.after] }
    }
    if (step.installs) installed = true
  }
  out(`\n${opt.name} is installed.`)
  return { installed, runtime, reason: 'installed', nextSteps: opt.after }
}

// The answer for Enter alone, and for nobody-there, is always no.
const ASK = Object.freeze({ defaultYes: false, safeAnswer: false })

function failure(result) {
  if (result && result.signal) return `stopped by ${clean(result.signal)}`
  const error = result && result.error
  if (error) return clean(error instanceof Error ? error.message : error)
  if (result && Number.isInteger(result.code) && result.code >= 0) return `exit code ${result.code}`
  return 'it could not be started'
}

// ---------------------------------------------------------------------------------------------
// The real implementations of `resolve`, `exec` and `readOsRelease`, used when the caller doesn't
// pass its own.

/** The text of /etc/os-release (or /usr/lib/os-release), or null. */
export function readOsRelease() {
  for (const file of ['/etc/os-release', '/usr/lib/os-release']) {
    try { return readFileSync(file, 'utf8').slice(0, 64 * 1024) } catch { /* try the next one */ }
  }
  return null
}

const DRIVE_PATH = /^[A-Za-z]:[\\/]/

/**
 * Where these programs' own installers put them. Checked before PATH, so a program of the same
 * name earlier on PATH can't stand in for them.
 * @returns {string[]}
 */
export function knownLocations(cmd, platform = process.platform, env = process.env) {
  if (platform === 'darwin') {
    if (cmd === 'brew') return ['/opt/homebrew/bin/brew', '/usr/local/bin/brew'] // Apple silicon, Intel
    if (cmd === 'podman') return ['/opt/homebrew/bin/podman', '/usr/local/bin/podman', '/opt/podman/bin/podman'] // Homebrew, or Podman's .pkg
  }
  if (platform === 'win32' && cmd === 'winget' && typeof env.LOCALAPPDATA === 'string' && DRIVE_PATH.test(env.LOCALAPPDATA)) {
    return [`${env.LOCALAPPDATA.replace(/[\\/]+$/, '')}\\Microsoft\\WindowsApps\\winget.exe`]
  }
  return []
}

/**
 * The absolute path of an installer or runtime program, or null: its known install location if
 * it's there, otherwise the first match in a trusted PATH folder (see trustedPathDirs in proc.js:
 * nothing relative, nothing inside the current folder, nothing in node_modules). On Windows only
 * .exe and .com count, because those are the only files a process can start without a shell.
 */
export async function findProgram(cmd, { env = process.env, platform = process.platform, cwd, home, known = knownLocations(cmd, platform, env) } = {}) {
  if (typeof cmd !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(cmd)) return null
  for (const file of known) if (isProgram(file, platform)) return file
  return which(cmd, env, { cwd, home, exts: ['.EXE', '.COM'] })
}

function isProgram(file, platform) {
  const win = platform === 'win32'
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
 * Run an installer with the terminal attached, so the person sees its own output and prompts.
 * An argument array and no shell, so nothing is ever re-parsed. No timeout: an installer someone
 * is watching should never be killed halfway by a timer.
 * @returns {Promise<{code: number, signal: string|null, error?: Error}>}
 */
export function runInstaller(file, args, { cwd, env } = {}) {
  return run(file, args, { inherit: true, cwd, env, timeoutMs: 2 ** 31 - 1 })
}
