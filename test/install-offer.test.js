import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  planInstall, offerInstall, explainChoices, parseOsRelease, findOnPath, onPath, runCommand, LINKS, WINGET_IDS,
} from '../src/runtimes/install-offer.js'

const moduleFile = fileURLToPath(new URL('../src/runtimes/install-offer.js', import.meta.url))

// A fake machine: `programs` is what's "on PATH". Nothing in these tests installs or runs an installer.
const hasOnly = (...programs) => cmd => programs.includes(cmd)
const argvs = option => option.steps.map(s => s.argv)

const OS_RELEASE = {
  ubuntu: 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n',
  mint: 'NAME="Linux Mint"\nID=linuxmint\nID_LIKE="ubuntu debian"\n',
  fedora: 'NAME="Fedora Linux"\nID=fedora\nPRETTY_NAME="Fedora Linux 41 (Workstation Edition)"\n',
  rocky: 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\n',
  arch: 'NAME="Arch Linux"\nID=arch\n',
  manjaro: 'NAME="Manjaro Linux"\nID=manjaro\nID_LIKE=arch\n',
  tumbleweed: 'NAME="openSUSE Tumbleweed"\nID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n',
  alpine: 'NAME="Alpine Linux"\nID=alpine\n',
}

/** Drives offerInstall like a person at a keyboard, and records everything that happened. */
function session(opts = {}) {
  const { pick: _pick, answers = [], execResults = [], ...io } = opts
  const pick = Object.hasOwn(opts, 'pick') ? opts.pick : 'podman' // so a test can pick `undefined`
  const log = { out: '', questions: [], confirms: [], execs: [], choices: null }
  const yes = [...answers]
  const results = [...execResults]
  return {
    log,
    run: () => offerInstall({
      out: text => { log.out += `${text}\n` },
      choose: async (question, options) => { log.questions.push(question); log.choices = options; return pick },
      confirm: async (question, opts) => { log.confirms.push({ question, opts }); return yes.length ? yes.shift() : false },
      exec: async (cmd, args) => { log.execs.push([cmd, ...args]); return results.length ? results.shift() : { code: 0 } },
      readOsRelease: () => null,
      ...io,
    }),
  }
}

// --- planInstall: what each platform is offered ------------------------------------------------

test('macOS with Homebrew: Podman is brew install, then machine init and start; Docker Desktop is the cask', () => {
  const plan = planInstall({ platform: 'darwin', has: hasOnly('brew') })
  assert.equal(plan.packageManager, 'brew')
  assert.deepEqual(argvs(plan.options.podman), [
    ['brew', 'install', 'podman'],
    ['podman', 'machine', 'init'],
    ['podman', 'machine', 'start'],
  ])
  // Homebrew renamed the "docker" cask to "docker-desktop"; use the current name.
  assert.deepEqual(argvs(plan.options.docker), [['brew', 'install', '--cask', 'docker-desktop']])
  assert.match(plan.options.podman.notes.join(' '), /community/) // honest about who maintains the formula
})

test('macOS without Homebrew: nothing to run, just the official download pages (never "install Homebrew first")', () => {
  const plan = planInstall({ platform: 'darwin', has: hasOnly() })
  assert.equal(plan.packageManager, null)
  assert.deepEqual(argvs(plan.options.podman), [])
  assert.deepEqual(argvs(plan.options.docker), [])
  const manual = [...plan.options.podman.manual, ...plan.options.docker.manual].join('\n')
  assert.ok(manual.includes(LINKS.podman))
  assert.ok(manual.includes(LINKS.dockerDesktop))
  assert.doesNotMatch(manual, /curl|install\.sh|brew/)
})

test('Windows with winget: exact IDs, exact match, pinned to the winget source', () => {
  const plan = planInstall({ platform: 'win32', has: hasOnly('winget') })
  assert.equal(plan.packageManager, 'winget')
  assert.deepEqual(WINGET_IDS, { podman: 'RedHat.Podman', docker: 'Docker.DockerDesktop' })
  assert.deepEqual(argvs(plan.options.podman), [['winget', 'install', '-e', '--id', 'RedHat.Podman', '--source', 'winget']])
  assert.deepEqual(argvs(plan.options.docker), [['winget', 'install', '-e', '--id', 'Docker.DockerDesktop', '--source', 'winget']])
  // The installer's PATH change only reaches new terminals, so machine setup is a next step, not a step.
  assert.deepEqual(plan.options.podman.after.slice(0, 3), [
    'Open a new terminal, so that podman is on your PATH.',
    'Then run: podman machine init',
    'Then run: podman machine start',
  ])
})

test('Windows without winget: download pages only', () => {
  const plan = planInstall({ platform: 'win32', has: hasOnly() })
  assert.deepEqual(argvs(plan.options.podman), [])
  assert.deepEqual(argvs(plan.options.docker), [])
  assert.ok(plan.options.docker.manual.join('\n').includes(LINKS.dockerDesktop))
})

test('Linux: the right distro commands are printed, and nothing is ever run, even with every tool on PATH', () => {
  const everything = hasOnly('apt-get', 'dnf', 'pacman', 'zypper', 'apk', 'sudo')
  const want = {
    ubuntu: ['Run: sudo apt-get update', 'Run: sudo apt-get -y install podman'],
    mint: ['Run: sudo apt-get update', 'Run: sudo apt-get -y install podman'],
    fedora: ['Run: sudo dnf -y install podman'],
    rocky: ['Run: sudo dnf -y install podman'],
    arch: ['Run: sudo pacman -S podman'],
    manjaro: ['Run: sudo pacman -S podman'],
    tumbleweed: ['Run: sudo zypper install podman'],
    alpine: ['Run: sudo apk add podman'],
  }
  for (const [distro, commands] of Object.entries(want)) {
    const plan = planInstall({ platform: 'linux', has: everything, osRelease: OS_RELEASE[distro] })
    assert.deepEqual(plan.options.podman.manual.slice(0, commands.length), commands, distro)
    assert.deepEqual(argvs(plan.options.podman), [], distro)
    assert.deepEqual(argvs(plan.options.docker), [], distro)
  }
})

test('Linux: falls back to the package manager on PATH when os-release is missing or unfamiliar', () => {
  assert.equal(planInstall({ platform: 'linux', has: hasOnly('dnf'), osRelease: null }).packageManager, 'dnf')
  assert.equal(planInstall({ platform: 'linux', has: hasOnly('zypper'), osRelease: 'ID=mystery\n' }).packageManager, 'zypper')
  const unknown = planInstall({ platform: 'linux', has: hasOnly(), osRelease: 'ID=mystery\n' })
  assert.equal(unknown.packageManager, null)
  assert.match(unknown.options.podman.manual[0], /podman\.io\/docs\/installation/)
})

test('Linux Docker: points to Docker\'s own instructions and warns that the docker group is root-equivalent', () => {
  const plan = planInstall({ platform: 'linux', has: hasOnly('apt-get'), osRelease: OS_RELEASE.ubuntu })
  assert.equal(plan.options.docker.name, 'Docker Engine')
  const text = plan.options.docker.manual.join('\n')
  assert.ok(text.includes(LINKS.dockerEngine))
  assert.match(text, /equivalent to root/)
})

test('other platforms get links only', () => {
  const plan = planInstall({ platform: 'freebsd', has: hasOnly('pkg', 'brew', 'winget') })
  assert.deepEqual(argvs(plan.options.podman), [])
  assert.deepEqual(argvs(plan.options.docker), [])
})

test('a runtime that is already installed is not installed again', () => {
  const plan = planInstall({ platform: 'darwin', has: hasOnly('brew', 'podman') })
  assert.equal(plan.options.podman.installed, true)
  assert.deepEqual(argvs(plan.options.podman), [])
  assert.ok(plan.options.podman.manual.includes('Run: podman machine start'))
  assert.equal(plan.options.docker.installed, false) // Docker isn't, so it can still be offered
  assert.equal(argvs(plan.options.docker).length, 1)
})

test('planInstall refuses to guess when it is not told what is on PATH', () => {
  assert.throws(() => planInstall({ platform: 'darwin' }), TypeError)
})

// --- the explanation screen ---------------------------------------------------------------------

test('the explanation recommends Podman, links Docker\'s terms instead of quoting numbers, and offers Cancel', () => {
  for (const platform of ['darwin', 'win32', 'linux']) {
    const text = explainChoices(planInstall({ platform, has: hasOnly() }))
    assert.match(text, /Podman \(recommended\)/, platform)
    assert.match(text, /open source/, platform)
    assert.match(text, /Cancel/, platform)
    assert.ok(text.includes(LINKS.dockerTerms), platform)
    assert.doesNotMatch(text, /\$\s?\d|\d+\s*(employees|million)|\d+ ?%/, platform) // terms change; we link, we don't quote
  }
  const mac = explainChoices(planInstall({ platform: 'darwin', has: hasOnly() }))
  assert.match(mac, /paid subscription/)
  assert.match(mac, /Colima/)
})

test('the distro name from os-release is sanitized before it is printed', () => {
  const plan = planInstall({ platform: 'linux', has: hasOnly(), osRelease: 'ID=ubuntu\nPRETTY_NAME="Ubuntu\u001B[2K\u001B[32m PASS"\n' })
  const text = explainChoices(plan)
  assert.doesNotMatch(text, /\u001B/)
  assert.match(text, /Ubuntu<ESC>/)
})

test('parseOsRelease reads quoted values and ID_LIKE lists, and ignores junk', () => {
  assert.deepEqual(parseOsRelease(OS_RELEASE.rocky), { id: 'rocky', idLike: ['rhel', 'centos', 'fedora'], name: 'Rocky Linux' })
  assert.deepEqual(parseOsRelease('garbage\n=x\nID\n'), { id: null, idLike: [], name: null })
  assert.deepEqual(parseOsRelease(null), { id: null, idLike: [], name: null })
})

// --- offerInstall: consent ----------------------------------------------------------------------

test('non-interactive: nothing is offered, asked or run', async () => {
  let ran = false
  const exec = async () => { ran = true; return { code: 0 } }
  const noPrompts = await offerInstall({ platform: 'darwin', has: hasOnly('brew'), exec, out: () => { ran = true } })
  assert.equal(noPrompts.installed, false)
  assert.equal(noPrompts.reason, 'non-interactive')
  assert.ok(noPrompts.nextSteps.some(s => s.includes(LINKS.podman)))

  // Even with prompts available, interactive: false wins.
  const s = session({ platform: 'darwin', has: hasOnly('brew'), interactive: false, answers: [true, true, true], exec })
  const r = await s.run()
  assert.equal(r.reason, 'non-interactive')
  assert.equal(s.log.questions.length, 0)
  assert.equal(s.log.confirms.length, 0)
  assert.equal(ran, false)
})

test('macOS, yes to everything: runs exactly the three commands, in order, each after its own yes (default no)', async () => {
  const s = session({ platform: 'darwin', has: hasOnly('brew'), pick: 'podman', answers: [true, true, true] })
  const r = await s.run()
  assert.deepEqual(s.log.execs, [['brew', 'install', 'podman'], ['podman', 'machine', 'init'], ['podman', 'machine', 'start']])
  assert.deepEqual(s.log.confirms.map(c => c.question), [
    'Run "brew install podman" now?',
    'Run "podman machine init" now?',
    'Run "podman machine start" now?',
  ])
  assert.ok(s.log.confirms.every(c => c.opts.default === false))
  assert.deepEqual(s.log.choices.map(c => c.key), ['podman', 'docker', 'cancel'])
  assert.equal(r.installed, true)
  assert.equal(r.runtime, 'podman')
  assert.equal(r.reason, 'installed')
  assert.match(r.nextSteps.join(' '), /bouncer doctor/)
})

test('no means no: declining the first step runs nothing', async () => {
  const s = session({ platform: 'darwin', has: hasOnly('brew'), pick: 'podman', answers: [false] })
  const r = await s.run()
  assert.deepEqual(s.log.execs, [])
  assert.equal(s.log.confirms.length, 1) // it stops asking, too
  assert.deepEqual(r, {
    installed: false, runtime: 'podman', reason: 'declined',
    nextSteps: ['Run: brew install podman', 'Run: podman machine init', 'Run: podman machine start', 'Then run "bouncer doctor" to check that git-bouncer can use it.'],
  })
})

test('only the boolean true is a yes: "y", 1 and "true" all count as no', async () => {
  for (const answer of ['y', 'yes', 1, 'true', {}, null, undefined]) {
    const s = session({ platform: 'win32', has: hasOnly('winget'), pick: 'docker', answers: [answer] })
    const r = await s.run()
    assert.deepEqual(s.log.execs, [], String(answer))
    assert.equal(r.reason, 'declined')
  }
})

test('yes to installing, no to the virtual machine: Podman is installed and the rest are next steps', async () => {
  const s = session({ platform: 'darwin', has: hasOnly('brew'), pick: 'podman', answers: [true, false] })
  const r = await s.run()
  assert.deepEqual(s.log.execs, [['brew', 'install', 'podman']])
  assert.equal(r.installed, true)
  assert.equal(r.reason, 'declined')
  assert.deepEqual(r.nextSteps.slice(0, 2), ['Run: podman machine init', 'Run: podman machine start'])
})

test('a failed step stops everything after it', async () => {
  const s = session({ platform: 'darwin', has: hasOnly('brew'), pick: 'podman', answers: [true, true, true], execResults: [{ code: 1 }] })
  const r = await s.run()
  assert.deepEqual(s.log.execs, [['brew', 'install', 'podman']])
  assert.equal(s.log.confirms.length, 1)
  assert.equal(r.installed, false)
  assert.equal(r.reason, 'failed')
  assert.match(r.nextSteps[0], /exit code 1/)
})

test('an installer that cannot start (or throws) is a failure, not a crash, and its message is sanitized', async () => {
  const s = session({ platform: 'win32', has: hasOnly('winget'), pick: 'podman', answers: [true], exec: async () => { throw new Error('spawn failed\u001B[2K') } })
  const r = await s.run()
  assert.equal(r.reason, 'failed')
  assert.doesNotMatch(r.nextSteps[0], /\u001B/)
  assert.doesNotMatch(s.log.out, /\u001B/)
})

test('Cancel, and anything that is not a known choice, installs nothing', async () => {
  for (const pick of ['cancel', undefined, '', 'Podman', '__proto__', 'constructor', 'podman; rm -rf ~']) {
    const s = session({ platform: 'darwin', has: hasOnly('brew'), pick, answers: [true, true, true] })
    const r = await s.run()
    assert.equal(r.reason, 'cancelled', String(pick))
    assert.equal(r.installed, false)
    assert.deepEqual(s.log.confirms, [])
    assert.deepEqual(s.log.execs, [])
  }
})

test('Linux: shows the commands, never asks to run them, never runs anything', async () => {
  for (const pick of ['podman', 'docker']) {
    const s = session({ platform: 'linux', has: hasOnly('apt-get', 'sudo'), pick, answers: [true, true], readOsRelease: () => OS_RELEASE.ubuntu })
    const r = await s.run()
    assert.deepEqual(s.log.execs, [], pick)
    assert.deepEqual(s.log.confirms, [], pick)
    assert.equal(r.reason, 'manual')
    assert.equal(r.installed, false)
  }
  const s = session({ platform: 'linux', has: hasOnly('apt-get'), pick: 'podman', readOsRelease: () => OS_RELEASE.ubuntu })
  await s.run()
  assert.match(s.log.out, /sudo apt-get -y install podman/)
  assert.match(s.log.out, /prints the commands instead of running them/)
})

test('already installed: says so, runs nothing', async () => {
  const s = session({ platform: 'darwin', has: hasOnly('brew', 'podman'), pick: 'podman', answers: [true, true, true] })
  const r = await s.run()
  assert.equal(r.reason, 'already-installed')
  assert.deepEqual(s.log.execs, [])
})

// --- the real `has` and `exec` (no installers involved) -----------------------------------------

test('findOnPath finds programs in absolute PATH entries and ignores relative ones', t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-path-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const win = process.platform === 'win32'
  const file = path.join(dir, win ? 'fake-tool.exe' : 'fake-tool')
  writeFileSync(file, '')
  if (!win) chmodSync(file, 0o755)
  const sep = path.delimiter
  assert.equal(findOnPath('fake-tool', { env: { PATH: `${dir}${sep}` } }), file)
  assert.equal(onPath('fake-tool', { env: { PATH: dir } }), true)
  // Run from inside that folder, PATH entries meaning "the current folder" must not find it.
  const lookup = `import { findOnPath } from ${JSON.stringify(pathToFileURL(moduleFile).href)}
for (const PATH of ['.', '', '${sep}', '.${sep}x']) console.log(findOnPath('fake-tool', { env: { PATH } }))`
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', lookup], { cwd: dir, encoding: 'utf8' })
  assert.equal(child.status, 0, child.stderr)
  assert.deepEqual(child.stdout.trim().split(/\r?\n/), ['null', 'null', 'null', 'null'])
  // Only plain program names are looked up.
  for (const name of ['../fake-tool', 'a/b', '-x', '', 'fake tool']) assert.equal(findOnPath(name, { env: { PATH: dir } }), null, name)
  if (!win) {
    chmodSync(file, 0o644) // not executable
    assert.equal(findOnPath('fake-tool', { env: { PATH: dir } }), null)
  }
})

test('runCommand passes an argument array (no shell) and reports the exit code', async () => {
  const r = await runCommand(process.execPath, ['-e', 'process.exit(process.argv[1] === "a b; c" ? 7 : 1)', 'a b; c'])
  assert.equal(r.code, 7)
  const missing = await runCommand('no-such-program-for-bouncer-tests', [], { env: { PATH: '' } })
  assert.equal(missing.code, null)
  assert.match(missing.error, /not found/)
})
