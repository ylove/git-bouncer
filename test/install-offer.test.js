import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  planInstall, offerInstall, explainChoices, parseOsRelease, findProgram, knownLocations, runInstaller, LINKS, WINGET_IDS,
} from '../src/runtimes/install-offer.js'

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

// For offerInstall: where each program "is" on the fake machine, and what appears once a command
// succeeds (after brew installs podman, there is a podman to run).
const HOME = '/srv/me'
const BREW = '/opt/homebrew/bin/brew'
const PODMAN = '/opt/homebrew/bin/podman'
const WINGET = 'C:\\Tools\\winget.exe'
const MAC = { programs: { brew: BREW }, installs: { [`${BREW} install podman`]: { podman: PODMAN } } }

/** Drives offerInstall like a person at a keyboard, and records everything that happened. */
function session(opts = {}) {
  const { pick: _pick, answers = [], execResults = [], programs = {}, installs = {}, ...io } = opts
  const pick = Object.hasOwn(opts, 'pick') ? opts.pick : 'podman' // so a test can pick `undefined`
  const log = { out: '', questions: [], confirms: [], execs: [], choices: null }
  const found = { ...programs }
  const yes = [...answers]
  const results = [...execResults]
  return {
    log,
    run: () => offerInstall({
      home: HOME,
      env: { PATH: '/usr/bin' },
      interactive: true,
      isTTY: { stdin: true, stderr: true },
      resolve: async cmd => found[cmd] ?? null,
      out: text => { log.out += `${text}\n` },
      choose: async (question, options) => { log.questions.push(question); log.choices = options; return pick },
      confirm: async (question, opts) => { log.confirms.push({ question, opts }); return yes.length ? yes.shift() : false },
      exec: async (file, args, { cwd, env }) => {
        log.execs.push({ argv: [file, ...args], cwd, env })
        const result = results.length ? results.shift() : { code: 0 }
        if (result.code === 0) Object.assign(found, installs[[file, ...args].join(' ')])
        return result
      },
      readOsRelease: () => null,
      ...io,
    }),
  }
}
const ran = s => s.log.execs.map(e => e.argv)

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
  // Podman's own advice: their installer first; Homebrew is "not recommended", and we say so in their words.
  assert.equal(plan.options.podman.preferManual, true)
  assert.ok(plan.options.podman.manual[0].includes(LINKS.podmanSite))
  assert.match(plan.options.podman.alternative.notes.join(' '), /"It's not recommended to install via Homebrew because it is a community-maintained package manager/)
  // One yes, one action: no "brew update" first, and the step says what Homebrew may still do.
  for (const step of [plan.options.podman.steps[0], plan.options.docker.steps[0]]) {
    assert.deepEqual(step.env, { HOMEBREW_NO_AUTO_UPDATE: '1' })
    assert.match(step.what, /may also install/)
  }
})

test('macOS without Homebrew: nothing to run, just the official download pages (never "install Homebrew first")', () => {
  const plan = planInstall({ platform: 'darwin', has: hasOnly() })
  assert.equal(plan.packageManager, null)
  assert.deepEqual(argvs(plan.options.podman), [])
  assert.deepEqual(argvs(plan.options.docker), [])
  const manual = [...plan.options.podman.manual, ...plan.options.docker.manual].join('\n')
  assert.ok(manual.includes(LINKS.podmanSite))
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
  assert.match(mac, /couldn't find either one/)
  assert.match(mac, /Professional use in larger organizations, and government\s+use, needs a paid subscription/)
  assert.match(mac, /limits both headcount and revenue/)
  assert.match(mac, /Colima/)
})

test('when a runtime is installed but not working, the screen says that instead of "couldn\'t find either"', () => {
  const one = explainChoices(planInstall({ platform: 'darwin', has: hasOnly('podman') }))
  assert.doesNotMatch(one, /couldn't find either/)
  assert.match(one, /Podman is installed, but git-bouncer couldn't use it/)
  const both = explainChoices(planInstall({ platform: 'win32', has: hasOnly('podman', 'docker') }))
  assert.match(both, /Podman and Docker Desktop are installed, but git-bouncer couldn't use them/)
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
  let touched = false
  const exec = async () => { touched = true; return { code: 0 } }
  const noPrompts = await offerInstall({ platform: 'darwin', resolve: async () => { touched = true; return null }, exec, out: () => { touched = true } })
  assert.equal(noPrompts.installed, false)
  assert.equal(noPrompts.reason, 'non-interactive')
  assert.ok(noPrompts.nextSteps.some(s => s.includes(LINKS.podman)))

  // A caller with prompts that always say yes still gets nothing unless every condition holds:
  // it said interactive: true, stdin and stderr are terminals, and CI isn't set.
  for (const [why, io] of [
    ['interactive defaults to false', { interactive: undefined }],
    ['interactive: false', { interactive: false }],
    ['stdin is not a terminal', { isTTY: { stdin: false, stderr: true } }],
    ['stderr is not a terminal', { isTTY: { stdin: true, stderr: undefined } }],
    ['CI is set', { env: { PATH: '/usr/bin', CI: 'true' } }],
  ]) {
    const s = session({ platform: 'darwin', ...MAC, answers: [true, true, true], exec, ...io })
    const r = await s.run()
    assert.equal(r.reason, 'non-interactive', why)
    assert.equal(s.log.questions.length + s.log.confirms.length, 0, why)
  }
  assert.equal(touched, false)
})

test('the explanation goes to stderr, next to the prompts, so "> log.txt" can\'t hide it', () => {
  const mod = JSON.stringify(pathToFileURL(path.join(import.meta.dirname, '..', 'src', 'runtimes', 'install-offer.js')).href)
  const script = `import { offerInstall } from ${mod}
await offerInstall({ platform: 'linux', interactive: true, isTTY: { stdin: true, stderr: true }, env: {}, readOsRelease: () => null,
  resolve: async () => null, confirm: async () => false, choose: async () => 'cancel' })`
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' })
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout, '')
  assert.match(r.stderr, /Podman \(recommended\)/)
})

test('macOS, yes to everything: the three commands run by absolute path, in order, from your home folder', async () => {
  const s = session({ platform: 'darwin', ...MAC, pick: 'podman', answers: [true, true, true, true] })
  const r = await s.run()
  assert.deepEqual(ran(s), [[BREW, 'install', 'podman'], [PODMAN, 'machine', 'init'], [PODMAN, 'machine', 'start']])
  // The question names the exact file that then runs.
  assert.deepEqual(s.log.confirms.map(c => c.question), [
    'Install it with Homebrew instead?',
    `Run "${BREW} install podman" now?`,
    `Run "${PODMAN} machine init" now?`,
    `Run "${PODMAN} machine start" now?`,
  ])
  assert.ok(s.log.confirms.every(c => c.opts.defaultYes === false && c.opts.safeAnswer === false)) // ui/prompt.js's options
  assert.ok(s.log.execs.every(e => e.cwd === HOME), 'installers never start in the current folder')
  assert.equal(s.log.execs[0].env.HOMEBREW_NO_AUTO_UPDATE, '1')
  assert.equal(s.log.execs[1].env.HOMEBREW_NO_AUTO_UPDATE, undefined) // only brew gets it
  assert.deepEqual(s.log.choices.map(c => c.key), ['podman', 'docker', 'cancel'])
  assert.equal(r.installed, true)
  assert.equal(r.runtime, 'podman')
  assert.equal(r.reason, 'installed')
  assert.match(r.nextSteps.join(' '), /bouncer doctor/)
})

test('what the person approves is the file that runs, even when it is somewhere suspicious', async () => {
  // A resolver bug (or a planted program) can't hide behind a bare name in the question.
  const planted = '/srv/take-home/node_modules/.bin/brew'
  const s = session({ platform: 'darwin', programs: { brew: planted }, pick: 'docker', answers: [true] })
  await s.run()
  assert.equal(s.log.confirms[0].question, `Run "${planted} install --cask docker-desktop" now?`)
  assert.deepEqual(ran(s), [[planted, 'install', '--cask', 'docker-desktop']])
})

test('Windows: winget runs by absolute path too', async () => {
  const s = session({ platform: 'win32', programs: { winget: WINGET }, pick: 'podman', answers: [true] })
  await s.run()
  assert.deepEqual(ran(s), [[WINGET, 'install', '-e', '--id', 'RedHat.Podman', '--source', 'winget']])
  assert.equal(s.log.execs[0].cwd, HOME)
})

test('macOS Podman: Podman\'s own installer comes first, and Homebrew only runs after a separate yes', async () => {
  const s = session({ platform: 'darwin', ...MAC, pick: 'podman', answers: [false, true, true, true] })
  const r = await s.run()
  assert.deepEqual(ran(s), [])
  assert.equal(s.log.confirms.length, 1)
  assert.equal(r.reason, 'manual')
  assert.ok(r.nextSteps[0].includes(LINKS.podmanSite))
  assert.ok(s.log.out.indexOf(LINKS.podmanSite) < s.log.out.indexOf('Homebrew can install it too'))
  assert.match(s.log.out, /not recommended to install via Homebrew/)
})

test('no means no: declining the first step runs nothing', async () => {
  const s = session({ platform: 'darwin', ...MAC, pick: 'podman', answers: [true, false] })
  const r = await s.run()
  assert.deepEqual(ran(s), [])
  assert.equal(s.log.confirms.length, 2) // it stops asking, too
  assert.deepEqual(r, {
    installed: false, runtime: 'podman', reason: 'declined',
    nextSteps: ['Run: brew install podman', 'Run: podman machine init', 'Run: podman machine start', 'Then run "bouncer doctor" to check that git-bouncer can use it.'],
  })
})

test('only the boolean true is a yes: "y", 1 and "true" all count as no', async () => {
  for (const answer of ['y', 'yes', 1, 'true', {}, null, undefined]) {
    const s = session({ platform: 'win32', programs: { winget: WINGET }, pick: 'docker', answers: [answer] })
    const r = await s.run()
    assert.deepEqual(ran(s), [], String(answer))
    assert.equal(r.reason, 'declined')
  }
})

test('yes to installing, no to the virtual machine: Podman is installed and the rest are next steps', async () => {
  const s = session({ platform: 'darwin', ...MAC, pick: 'podman', answers: [true, true, false] })
  const r = await s.run()
  assert.deepEqual(ran(s), [[BREW, 'install', 'podman']])
  assert.equal(r.installed, true)
  assert.equal(r.reason, 'declined')
  assert.deepEqual(r.nextSteps.slice(0, 2), ['Run: podman machine init', 'Run: podman machine start'])
})

test('a program that is not in a trusted folder stops the steps instead of guessing', async () => {
  // brew "succeeds" but no podman appears where we'd trust it.
  const s = session({ platform: 'darwin', programs: { brew: BREW }, pick: 'podman', answers: [true, true, true, true] })
  const r = await s.run()
  assert.deepEqual(ran(s), [[BREW, 'install', 'podman']])
  assert.equal(s.log.confirms.length, 2)
  assert.equal(r.installed, true)
  assert.equal(r.reason, 'not-found')
  assert.deepEqual(r.nextSteps.slice(0, 2), ['Open a new terminal, then continue with: podman machine init', 'Run: podman machine start'])
})

test('a failed step stops everything after it', async () => {
  const s = session({ platform: 'darwin', ...MAC, pick: 'podman', answers: [true, true, true, true], execResults: [{ code: 1 }] })
  const r = await s.run()
  assert.deepEqual(ran(s), [[BREW, 'install', 'podman']])
  assert.equal(s.log.confirms.length, 2)
  assert.equal(r.installed, false)
  assert.equal(r.reason, 'failed')
  assert.match(r.nextSteps[0], /exit code 1/)
})

test('an installer stopped by a signal, or one that could not start, says so', async () => {
  const stopped = session({ platform: 'darwin', ...MAC, pick: 'podman', answers: [true, true], execResults: [{ code: -1, signal: 'SIGINT' }] })
  assert.match((await stopped.run()).nextSteps[0], /stopped by SIGINT/)
  const unstartable = session({ platform: 'darwin', ...MAC, pick: 'podman', answers: [true, true], execResults: [{ code: -1, signal: null, error: new Error('spawn EACCES') }] })
  assert.match((await unstartable.run()).nextSteps[0], /spawn EACCES/)
})

test('an installer that throws is a failure, not a crash, and its message is sanitized', async () => {
  const s = session({ platform: 'win32', programs: { winget: WINGET }, pick: 'podman', answers: [true], exec: async () => { throw new Error('spawn failed\u001B[2K') } })
  const r = await s.run()
  assert.equal(r.reason, 'failed')
  assert.doesNotMatch(r.nextSteps[0], /\u001B/)
  assert.doesNotMatch(s.log.out, /\u001B/)
})

test('Cancel, and anything that is not a known choice, installs nothing', async () => {
  for (const pick of ['cancel', undefined, '', 'Podman', '__proto__', 'constructor', 'podman; rm -rf ~']) {
    const s = session({ platform: 'darwin', ...MAC, pick, answers: [true, true, true] })
    const r = await s.run()
    assert.equal(r.reason, 'cancelled', String(pick))
    assert.equal(r.installed, false)
    assert.deepEqual(s.log.confirms, [])
    assert.deepEqual(ran(s), [])
  }
})

test('Linux: shows the commands, never asks to run them, never runs anything', async () => {
  for (const pick of ['podman', 'docker']) {
    const s = session({ platform: 'linux', programs: { 'apt-get': '/usr/bin/apt-get' }, pick, answers: [true, true], readOsRelease: () => OS_RELEASE.ubuntu })
    const r = await s.run()
    assert.deepEqual(ran(s), [], pick)
    assert.deepEqual(s.log.confirms, [], pick)
    assert.equal(r.reason, 'manual')
    assert.equal(r.installed, false)
  }
  const s = session({ platform: 'linux', programs: { 'apt-get': '/usr/bin/apt-get' }, pick: 'podman', readOsRelease: () => OS_RELEASE.ubuntu })
  await s.run()
  assert.match(s.log.out, /sudo apt-get -y install podman/)
  assert.match(s.log.out, /prints the commands instead of running them/)
})

test('already installed: says so, runs nothing', async () => {
  const s = session({ platform: 'darwin', programs: { brew: BREW, podman: PODMAN }, pick: 'podman', answers: [true, true, true] })
  const r = await s.run()
  assert.equal(r.reason, 'already-installed')
  assert.deepEqual(ran(s), [])
})

// --- the real resolve and exec (no installers involved) ----------------------------------------

test('knownLocations: the places Homebrew, Podman\'s installer and winget put their programs', () => {
  assert.deepEqual(knownLocations('brew', 'darwin'), ['/opt/homebrew/bin/brew', '/usr/local/bin/brew'])
  assert.deepEqual(knownLocations('podman', 'darwin'), ['/opt/homebrew/bin/podman', '/usr/local/bin/podman', '/opt/podman/bin/podman'])
  assert.deepEqual(knownLocations('winget', 'win32', { LOCALAPPDATA: 'C:\\me\\AppData\\Local' }), ['C:\\me\\AppData\\Local\\Microsoft\\WindowsApps\\winget.exe'])
  for (const LOCALAPPDATA of [undefined, '', '..\\x', '\\Local', 'AppData']) assert.deepEqual(knownLocations('winget', 'win32', { LOCALAPPDATA }), [], String(LOCALAPPDATA))
  assert.deepEqual(knownLocations('brew', 'linux'), [])
})

test('findProgram checks the known location before PATH, and only looks up plain names', async t => {
  const root = mkdtempSync(path.join(tmpdir(), 'bouncer-find-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const win = process.platform === 'win32'
  const plant = dir => {
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, win ? 'fake-brew.exe' : 'fake-brew')
    writeFileSync(file, '')
    chmodSync(file, 0o755)
    return file
  }
  const official = plant(path.join(root, 'official'))
  const onPathToo = plant(path.join(root, 'elsewhere'))
  const env = { PATH: path.join(root, 'elsewhere') }
  const same = (a, b) => assert.equal(win ? a?.toLowerCase() : a, win ? b.toLowerCase() : b)
  same(await findProgram('fake-brew', { env, known: [official] }), official)
  same(await findProgram('fake-brew', { env, known: [path.join(root, 'missing', 'fake-brew')] }), onPathToo)
  assert.equal(await findProgram('fake-brew', { env: { PATH: '.' }, known: [] }), null)
  for (const name of ['../fake-brew', 'a/b', '-x', '', 'fake brew']) assert.equal(await findProgram(name, { env, known: [] }), null, name)
  if (!win) {
    chmodSync(official, 0o644) // not executable: skipped
    same(await findProgram('fake-brew', { env, known: [official] }), onPathToo)
  }
})

test('runInstaller passes an argument array (no shell), the environment and the folder, and reports the exit code', async t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-run-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const want = realpathSync.native(dir)
  const script = 'const same = (a, b) => process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b; process.exit(process.argv[1] === "a b; c" && process.env.BOUNCER_TEST === "1" && same(process.cwd(), process.argv[2]) ? 7 : 1)'
  const r = await runInstaller(process.execPath, ['-e', script, 'a b; c', want], { cwd: dir, env: { ...process.env, BOUNCER_TEST: '1' } })
  assert.equal(r.code, 7)
  assert.equal(r.signal, null)
})
