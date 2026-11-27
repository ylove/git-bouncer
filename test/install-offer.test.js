import { test } from 'node:test'
import assert from 'node:assert/strict'
import { planInstall, explainChoices, parseOsRelease, LINKS, WINGET_IDS } from '../src/runtimes/install-offer.js'

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
