import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { shellInit, detectShell, SHELLS } from '../src/shell-init.js'
import { UsageError } from '../src/url.js'

const isWindows = process.platform === 'win32'
const works = (cmd, args) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 20000 })
  return !r.error && r.status === 0
}

// --- the generated text ----------------------------------------------------------------------

test('every shell gets a snippet that explains how to turn it on, how to turn it off, and the no-setup option', () => {
  const howToAdd = {
    bash: 'eval "$(bouncer shell-init bash)"',
    zsh: 'eval "$(bouncer shell-init zsh)"',
    fish: 'bouncer shell-init fish | source',
  }
  for (const shell of SHELLS) {
    const text = shellInit(shell)
    const comments = text.split('\n').filter(l => l.startsWith('#')).join('\n')
    assert.ok(comments.includes(howToAdd[shell]), shell)
    assert.match(comments, /Turn it on/, shell)
    assert.match(comments, /Turn it off/, shell)
    assert.match(comments, /"git bouncer <url>" already works/, shell)
    assert.ok(text.startsWith('# git-bouncer shell integration'), shell)
  }
})

test('only the known shell names are accepted', () => {
  for (const bad of ['sh', 'cmd', 'powershell', 'BASH', 'bash ', 'bash; rm -rf ~', '$(id)', '', undefined, null, '__proto__', 'toString', 'constructor']) {
    assert.throws(() => shellInit(bad), UsageError, String(bad))
  }
})

test('the snippets are constants: nothing from outside is ever put into text you eval', () => {
  for (const shell of SHELLS) assert.equal(shellInit(shell), shellInit(shell))
  // bash and zsh differ only in their comments.
  const code = s => shellInit(s).split('\n').filter(l => !l.startsWith('#')).join('\n')
  assert.equal(code('bash'), code('zsh'))
})

test('bash, zsh and fish wrap git with a function that falls through to the real git', () => {
  for (const shell of ['bash', 'zsh']) {
    assert.match(shellInit(shell), /^function git \{$/m, shell) // not "git() {", which aliases break
    assert.match(shellInit(shell), /command git "\$@"/, shell)
    assert.match(shellInit(shell), /command bouncer clone "\$@"/, shell)
  }
  assert.match(shellInit('fish'), /command git \$argv/)
})


test('detectShell reads $SHELL, and PSModulePath for PowerShell', () => {
  assert.equal(detectShell({ SHELL: '/bin/zsh' }, 'darwin'), 'zsh')
  assert.equal(detectShell({ SHELL: '/usr/bin/bash' }, 'linux'), 'bash')
  assert.equal(detectShell({ SHELL: '/opt/homebrew/bin/fish' }, 'darwin'), 'fish')
  assert.equal(detectShell({ SHELL: '/usr/bin/tcsh' }, 'linux'), null)
  assert.equal(detectShell({}, 'linux'), null)
  // Outside Windows, PSModulePath only exists inside PowerShell, even when $SHELL names another shell.
  assert.equal(detectShell({ SHELL: '/bin/zsh', PSModulePath: '/opt/microsoft/powershell/7/Modules' }, 'darwin'), 'powershell')
  // On Windows it's set system-wide, so Git Bash (which sets SHELL) still counts as bash.
  assert.equal(detectShell({ SHELL: '/usr/bin/bash', PSModulePath: 'x' }, 'win32'), 'bash')
  assert.equal(detectShell({ SHELL: 'C:\\Program Files\\Git\\usr\\bin\\bash.exe', PSModulePath: 'x' }, 'win32'), 'bash')
  assert.equal(detectShell({ PSModulePath: 'x' }, 'win32'), 'powershell')
})

// --- the snippets, actually running ---------------------------------------------------------
//
// A fake `git` and a fake `bouncer` go first on PATH. Each prints its name and every argument in
// <brackets> (so spaces and empty arguments are visible), then exits with $FAKE_EXIT.

function fakeBin(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-shell-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  for (const name of ['git', 'bouncer']) {
    const file = path.join(dir, name)
    writeFileSync(file, `#!/bin/sh\nprintf '%s' ${name}\nfor a do printf ' <%s>' "$a"; done\nprintf '\\n'\nexit "\${FAKE_EXIT:-0}"\n`)
    chmodSync(file, 0o755)
  }
  return dir
}

// [arguments typed after "git", what the fake programs should print]
const PASS_THROUGH = [
  [['status', '-s'], 'git <status> <-s>'],
  [['commit', '-m', 'a b'], 'git <commit> <-m> <a b>'],
  [[], 'git'],
  [['log', '--format=%H %s', '', '*', '$HOME', '"q"', "it's", '\\n', 'two\nlines', '--', 'file name'],
    'git <log> <--format=%H %s> <> <*> <$HOME> <"q"> <it\'s> <\\n> <two\nlines> <--> <file name>'],
  [['clone', 'https://github.com/a/b'], 'git <clone> <https://github.com/a/b>'],
  [['clone', 'https://github.com/a/b', '--', '--bouncer'], 'git <clone> <https://github.com/a/b> <--> <--bouncer>'], // after --, it's a name
  [['--bouncer', 'clone', 'x'], 'git <--bouncer> <clone> <x>'], // only "git clone ..." is ever rerouted
  [['clone', '--bouncer=yes', 'x'], 'git <clone> <--bouncer=yes> <x>'], // the flag is exactly --bouncer
  [['checkout', '--', 'main'], 'git <checkout> <--> <main>'],
]
const REROUTED = [
  [['clone', 'https://github.com/a/b', '--bouncer'], 'bouncer <clone> <https://github.com/a/b>'],
  [['clone', '--bouncer', 'https://github.com/a/b', 'my dir'], 'bouncer <clone> <https://github.com/a/b> <my dir>'],
  [['clone', 'https://github.com/a/b', 'dir', '--ref', 'v1.2', '--bouncer'], 'bouncer <clone> <https://github.com/a/b> <dir> <--ref> <v1.2>'],
  [['clone', '--bouncer', 'https://github.com/a/b', '--', '--bouncer'], 'bouncer <clone> <https://github.com/a/b> <--> <--bouncer>'],
  [['clone', '--bouncer'], 'bouncer <clone>'],
]

const POSIX_SHELLS = [
  // -f / --norc --noprofile: don't read the test machine's own startup files.
  ['bash', script => ['--norc', '--noprofile', '-c', script, 'bash']],
  ['zsh', script => ['-f', '-c', script, 'zsh']],
]

for (const [shell, argvFor] of POSIX_SHELLS) {
  const skip = isWindows ? 'the Windows job checks PowerShell; bash and zsh run on Linux and macOS' : !works(shell, ['-c', 'exit 0']) && `${shell} is not installed`

  const run = (bin, args, { exit = 0, prelude = '', load = 'eval "$GB_SNIPPET"' } = {}) => {
    // The snippet arrives through an environment variable and is eval'd, exactly like the
    // documented `eval "$(bouncer shell-init bash)"`. Arguments go in as "$@", never as text.
    const script = `${prelude}\n${load}\ngit "$@"`
    const r = spawnSync(shell, [...argvFor(script), ...args], {
      encoding: 'utf8',
      env: { PATH: `${bin}${path.delimiter}${process.env.PATH}`, HOME: bin, GB_SNIPPET: shellInit(shell), FAKE_EXIT: String(exit) },
    })
    return { out: r.stdout, err: r.stderr, code: r.status }
  }

  test(`${shell}: every git command without --bouncer reaches the real git exactly as typed`, { skip }, t => {
    const bin = fakeBin(t)
    for (const [args, want] of PASS_THROUGH) {
      const r = run(bin, args)
      assert.equal(r.out, `${want}\n`, JSON.stringify(args))
      assert.equal(r.err, '', JSON.stringify(args))
    }
  })

  test(`${shell}: git clone ... --bouncer runs bouncer clone with the other arguments in order`, { skip }, t => {
    const bin = fakeBin(t)
    for (const [args, want] of REROUTED) assert.equal(run(bin, args).out, `${want}\n`, JSON.stringify(args))
  })

  test(`${shell}: exit codes come back unchanged, from git and from bouncer`, { skip }, t => {
    const bin = fakeBin(t)
    assert.equal(run(bin, ['status'], { exit: 3 }).code, 3)
    assert.equal(run(bin, ['clone', 'https://github.com/a/b', '--bouncer'], { exit: 5 }).code, 5)
    assert.equal(run(bin, ['clone', 'https://github.com/a/b', '--bouncer'], { exit: 0 }).code, 0)
  })

  test(`${shell}: works under "set -u", and an existing alias named git doesn't break loading it`, { skip }, t => {
    const bin = fakeBin(t)
    assert.equal(run(bin, ['clone', 'x', '--bouncer'], { prelude: 'set -u' }).out, 'bouncer <clone> <x>\n')
    assert.equal(run(bin, [], { prelude: 'set -u' }).out, 'git\n')
    // Loaded while an alias named git exists. With `git() {`, bash would alias-expand the name
    // while defining it, and zsh would refuse to load it at all.
    const r = run(bin, ['clone', 'x', '--bouncer'], {
      prelude: "shopt -s expand_aliases 2>/dev/null; alias git='echo ALIAS'",
      load: 'eval "$GB_SNIPPET"\nunalias git',
    })
    assert.equal(r.err, '')
    assert.equal(r.out, 'bouncer <clone> <x>\n')
  })
}

test('fish: passes everything else through and reroutes only git clone ... --bouncer', { skip: isWindows || !works('fish', ['-c', 'exit 0']) ? 'fish is not installed' : false }, t => {
  const bin = fakeBin(t)
  const run = (args, exit = 0) => {
    const r = spawnSync('fish', ['--no-config', '-c', 'printf "%s\\n" "$GB_SNIPPET" | source; git $argv', '--', ...args], {
      encoding: 'utf8',
      env: { PATH: `${bin}${path.delimiter}${process.env.PATH}`, HOME: bin, GB_SNIPPET: shellInit('fish'), FAKE_EXIT: String(exit) },
    })
    return { out: r.stdout, err: r.stderr, code: r.status }
  }
  for (const [args, want] of [...PASS_THROUGH, ...REROUTED]) {
    const r = run(args)
    assert.equal(r.out, `${want}\n`, JSON.stringify(args))
    assert.equal(r.err, '', JSON.stringify(args))
  }
  assert.equal(run(['status'], 3).code, 3)
  assert.equal(run(['clone', 'x', '--bouncer'], 5).code, 5)
})

// --- failing safe ---------------------------------------------------------------------------

test('without the snippet, real git refuses --bouncer, so nothing is ever cloned unchecked', { skip: !works('git', ['--version']) && 'git is not installed' }, t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-git-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  // .invalid never resolves (RFC 2606), and git rejects the option before it would connect anyway.
  const r = spawnSync('git', ['clone', 'https://example.invalid/a/b', '--bouncer'], { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } })
  assert.equal(r.status, 129)
  assert.match(r.stderr, /unknown option/)
})
