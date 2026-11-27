import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
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

test('every shell gets a snippet that explains how to turn it on and off, and the no-setup options', () => {
  const howToAdd = {
    bash: 'eval "$(bouncer shell-init bash)"',
    zsh: 'eval "$(bouncer shell-init zsh)"',
    fish: 'bouncer shell-init fish | source',
    powershell: 'Invoke-Expression (& bouncer shell-init powershell | Out-String)',
  }
  for (const shell of SHELLS) {
    const text = shellInit(shell)
    const comments = text.split('\n').filter(l => l.startsWith('#')).join('\n')
    assert.ok(comments.includes(howToAdd[shell]), shell)
    assert.match(comments, /Turn it on/, shell)
    assert.match(comments, /Turn it off/, shell)
    assert.match(comments, /Without this, plain "git clone" runs unchecked/, shell)
    assert.match(comments, /"git bouncer <url>"/, shell)
    assert.ok(text.startsWith('# git-bouncer shell integration'), shell)
  }
})

test('only the four known shell names are accepted', () => {
  for (const bad of ['sh', 'cmd', 'BASH', 'bash ', 'bash; rm -rf ~', '$(id)', '', undefined, null, '__proto__', 'toString', 'constructor']) {
    assert.throws(() => shellInit(bad), UsageError, String(bad))
  }
})

test('the snippets are constants, and pure ASCII: nothing from outside is ever put into text you eval', () => {
  for (const shell of SHELLS) {
    assert.equal(shellInit(shell), shellInit(shell))
    // The dash look-alikes are written as escapes, so a terminal or code page can't mangle them.
    assert.match(shellInit(shell), /^[\n\x20-\x7e]*$/, shell)
  }
  // bash and zsh differ only in their comments.
  const code = s => shellInit(s).split('\n').filter(l => !l.startsWith('#')).join('\n')
  assert.equal(code('bash'), code('zsh'))
})

test('bash, zsh and fish wrap git with a function that falls through to the real git', () => {
  for (const shell of ['bash', 'zsh']) {
    assert.match(shellInit(shell), /^function git \{$/m, shell) // not "git() {", which aliases break
    assert.match(shellInit(shell), /command git "\$@"/, shell)
    // The distinctive name: an unrelated "bouncer" earlier on PATH can't take the request.
    assert.match(shellInit(shell), /command git-bouncer clone "\$@"/, shell)
  }
  assert.match(shellInit('fish'), /command git \$argv/)
  assert.match(shellInit('fish'), /command git-bouncer clone \$rest/)
})

test('PowerShell does not wrap git at all; it looks at the typed line', () => {
  const ps = shellInit('powershell')
  assert.doesNotMatch(ps, /function\s+(global:)?git\b/i)
  assert.match(ps, /Set-PSReadLineKeyHandler -Chord Enter/)
  assert.match(ps, /\[System\.Management\.Automation\.Language\.Parser\]::ParseInput/)
  assert.match(ps, /GetNewClosure\(\)/) // the handler keeps its own copy of the rewrite function
})

test('detectShell reads $SHELL and PSModulePath, and gives up when they disagree', () => {
  assert.equal(detectShell({ SHELL: '/bin/zsh' }), 'zsh')
  assert.equal(detectShell({ SHELL: '/usr/bin/bash' }), 'bash')
  assert.equal(detectShell({ SHELL: '/opt/homebrew/bin/fish' }), 'fish')
  assert.equal(detectShell({ SHELL: 'C:\\Program Files\\Git\\usr\\bin\\bash.exe' }), 'bash')
  assert.equal(detectShell({ SHELL: '/usr/bin/tcsh' }), null)
  assert.equal(detectShell({}), null)
  assert.equal(detectShell({ PSModulePath: 'x' }), 'powershell')
  assert.equal(detectShell({ SHELL: '/usr/local/bin/pwsh', PSModulePath: 'x' }), 'powershell')
  // zsh started from pwsh inherits PSModulePath; Windows sets it everywhere. Either way: ask.
  assert.equal(detectShell({ SHELL: '/bin/zsh', PSModulePath: '/opt/microsoft/powershell/7/Modules' }), null)
  assert.equal(detectShell({ SHELL: '/usr/bin/bash', PSModulePath: 'x' }), null)
})

// --- the snippets, actually running ---------------------------------------------------------
//
// A fake `git` and a fake `git-bouncer` go first on PATH. Each prints its name and every argument
// in <brackets> (so spaces and empty arguments are visible), then exits with $FAKE_EXIT.

function fakeBin(t) {
  const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-shell-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  for (const name of ['git', 'git-bouncer']) {
    const file = path.join(dir, name)
    writeFileSync(file, `#!/bin/sh\nprintf '%s' ${name}\nfor a do printf ' <%s>' "$a"; done\nprintf '\\n'\nexit "\${FAKE_EXIT:-0}"\n`)
    chmodSync(file, 0o755)
  }
  return dir
}

const URL = 'https://github.com/a/b'
// [arguments typed after "git", what the fake programs should print]
const PASS_THROUGH = [
  [['status', '-s'], 'git <status> <-s>'],
  [['commit', '-m', 'a b'], 'git <commit> <-m> <a b>'],
  [[], 'git'],
  [['log', '--format=%H %s', '', '*', '$HOME', '"q"', "it's", '\\n', 'two\nlines', '--', 'file name'],
    'git <log> <--format=%H %s> <> <*> <$HOME> <"q"> <it\'s> <\\n> <two\nlines> <--> <file name>'],
  [['clone', URL], `git <clone> <${URL}>`],
  [['clone', URL, 'bouncer'], `git <clone> <${URL}> <bouncer>`], // a folder that's just called bouncer
  [['clone', URL, 'my-bouncer'], `git <clone> <${URL}> <my-bouncer>`],
  [['--bouncer', 'clone', 'x'], 'git <--bouncer> <clone> <x>'], // only "git clone ..." is ever rerouted
  [['clone', '--bouncer=yes', 'x'], 'git <clone> <--bouncer=yes> <x>'], // the flag is exactly --bouncer
  [['checkout', '--', 'main'], 'git <checkout> <--> <main>'],
  [['log', '\u2014bouncer'], 'git <log> <\u2014bouncer>'], // look-alikes only matter for clone
]
// --bouncer anywhere after "clone", even after "--": git is never called.
const REROUTED = [
  [['clone', URL, '--bouncer'], `git-bouncer <clone> <${URL}>`],
  [['clone', '--bouncer', URL, 'my dir'], `git-bouncer <clone> <${URL}> <my dir>`],
  [['clone', URL, 'dir', '--ref', 'v1.2', '--bouncer'], `git-bouncer <clone> <${URL}> <dir> <--ref> <v1.2>`],
  [['clone', '--', URL, '--bouncer'], `git-bouncer <clone> <--> <${URL}>`],
  [['clone', '-q', '--', URL, '--bouncer'], `git-bouncer <clone> <-q> <--> <${URL}>`],
  [['clone', URL, '--', '--bouncer'], `git-bouncer <clone> <${URL}> <-->`],
  [['clone', '--end-of-options', URL, '--bouncer'], `git-bouncer <clone> <--end-of-options> <${URL}>`],
  [['clone', '--bouncer', URL, '--bouncer'], `git-bouncer <clone> <${URL}>`],
  [['clone', '--bouncer'], 'git-bouncer <clone>'],
]
// Mistyped --bouncer (smart punctuation, copy-paste): refused, exit 2, nothing runs.
const TYPOS = [
  ['clone', URL, '\u2014bouncer'], // em dash
  ['clone', URL, '\u2013-bouncer'], // en dash + hyphen
  ['clone', URL, '-bouncer'],
  ['clone', URL, '---bouncer'],
  ['clone', URL, '--Bouncer'],
  ['clone', URL, '--BOUNCER'],
  ['clone', '\u2010\u2010bouncer', URL],
  ['clone', URL, '\u2212\u2212bouncer'],
  ['clone', URL, '\uFF0D\uFF0Dbouncer'],
  ['clone', URL, '\uFE63bouncer'],
  ['clone', '--', URL, '\u2014bouncer'],
  ['clone', '--end-of-options', URL, '\u2015bouncer'],
]
const DID_YOU_MEAN = /Did you mean --bouncer\? Nothing was run\./

const POSIX_SHELLS = [
  // -f / --norc --noprofile: don't read the test machine's own startup files.
  ['bash', script => ['--norc', '--noprofile', '-c', script, 'bash']],
  ['zsh', script => ['-f', '-c', script, 'zsh']],
]
const UTF8 = process.platform === 'darwin' ? 'en_US.UTF-8' : 'C.UTF-8'

for (const [shell, argvFor] of POSIX_SHELLS) {
  const skip = isWindows ? 'the Windows job checks PowerShell; bash and zsh run on Linux and macOS' : !works(shell, ['-c', 'exit 0']) && `${shell} is not installed`

  const run = (bin, args, { exit = 0, prelude = '', load = 'eval "$GB_SNIPPET"', locale } = {}) => {
    // The snippet arrives through an environment variable and is eval'd, exactly like the
    // documented `eval "$(bouncer shell-init bash)"`. Arguments go in as "$@", never as text.
    const script = `${prelude}\n${load}\ngit "$@"`
    const env = { PATH: `${bin}${path.delimiter}${process.env.PATH}`, HOME: bin, GB_SNIPPET: shellInit(shell), FAKE_EXIT: String(exit) }
    if (locale) env.LC_ALL = locale
    const r = spawnSync(shell, [...argvFor(script), ...args], { encoding: 'utf8', env })
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

  test(`${shell}: --bouncer anywhere after clone, even after --, runs git-bouncer and never git`, { skip }, t => {
    const bin = fakeBin(t)
    for (const [args, want] of REROUTED) assert.equal(run(bin, args).out, `${want}\n`, JSON.stringify(args))
  })

  test(`${shell}: a mistyped --bouncer stops with "Did you mean --bouncer?" and exit 2, in any locale`, { skip }, t => {
    const bin = fakeBin(t)
    for (const locale of [undefined, 'C', UTF8]) {
      for (const args of TYPOS) {
        const r = run(bin, args, { locale })
        assert.equal(r.out, '', `${JSON.stringify(args)} ${locale}`) // neither git nor git-bouncer ran
        assert.match(r.err, DID_YOU_MEAN, `${JSON.stringify(args)} ${locale}`)
        assert.equal(r.code, 2, `${JSON.stringify(args)} ${locale}`)
      }
    }
  })

  test(`${shell}: exit codes come back unchanged, from git and from git-bouncer`, { skip }, t => {
    const bin = fakeBin(t)
    assert.equal(run(bin, ['status'], { exit: 3 }).code, 3)
    assert.equal(run(bin, ['clone', URL], { exit: 4 }).code, 4)
    assert.equal(run(bin, ['clone', URL, '--bouncer'], { exit: 5 }).code, 5)
    assert.equal(run(bin, ['clone', URL, '--bouncer'], { exit: 0 }).code, 0)
  })

  test(`${shell}: works under "set -u", and an existing alias named git doesn't break loading it`, { skip }, t => {
    const bin = fakeBin(t)
    assert.equal(run(bin, ['clone', 'x', '--bouncer'], { prelude: 'set -u' }).out, 'git-bouncer <clone> <x>\n')
    assert.equal(run(bin, [], { prelude: 'set -u' }).out, 'git\n')
    assert.match(run(bin, ['clone', 'x', '-bouncer'], { prelude: 'set -u' }).err, DID_YOU_MEAN)
    // Loaded while an alias named git exists. With `git() {`, bash would alias-expand the name
    // while defining it, and zsh would refuse to load it at all.
    const r = run(bin, ['clone', 'x', '--bouncer'], {
      prelude: "shopt -s expand_aliases 2>/dev/null; alias git='echo ALIAS'",
      load: 'eval "$GB_SNIPPET"\nunalias git',
    })
    assert.equal(r.err, '')
    assert.equal(r.out, 'git-bouncer <clone> <x>\n')
  })
}

test('fish: passes everything else through, reroutes git clone ... --bouncer, refuses look-alikes', { skip: isWindows || !works('fish', ['-c', 'exit 0']) ? 'fish is not installed' : false }, t => {
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
  for (const args of TYPOS) {
    const r = run(args)
    assert.equal(r.out, '', JSON.stringify(args))
    assert.match(r.err, DID_YOU_MEAN, JSON.stringify(args))
    assert.equal(r.code, 2, JSON.stringify(args))
  }
  assert.equal(run(['status'], 3).code, 3)
  assert.equal(run(['clone', 'x', '--bouncer'], 5).code, 5)
})

// PowerShell: the rewrite function is checked line by line, then rewritten lines are run against a
// fake git-bouncer.ps1. Runs with pwsh (any OS) and with Windows PowerShell 5.1 when present.
const REFUSED = 'git-bouncer: put "git clone <url> --bouncer" on a line by itself. Nothing was run.'
const MISTYPED = 'git-bouncer: an argument looks like --bouncer typed with a different dash (copy-paste often does this). Did you mean --bouncer? Nothing was run.'
const refusal = message => `$global:LASTEXITCODE = 2; Write-Error '${message}'`
const LINES = [
  [`git clone ${URL} --bouncer`, `git-bouncer clone ${URL}`],
  [`git clone --bouncer ${URL} my-dir`, `git-bouncer clone ${URL} my-dir`],
  [`git clone '${URL}'   'my dir'  --bouncer --ref v1.2`, `git-bouncer clone '${URL}'   'my dir' --ref v1.2`],
  ['git clone $url --bouncer', 'git-bouncer clone $url'],
  [`git clone -- ${URL} --bouncer`, `git-bouncer clone -- ${URL}`],
  [`git clone -q -- ${URL} --bouncer`, `git-bouncer clone -q -- ${URL}`],
  [`git clone ${URL} -- --bouncer`, `git-bouncer clone ${URL} --`],
  [`git clone --end-of-options ${URL} --bouncer`, `git-bouncer clone --end-of-options ${URL}`],
  [`git clone ${URL} '--bouncer'`, `git-bouncer clone ${URL}`], // quoted is still the flag
  ['Git clone a --bouncer', 'git-bouncer clone a'],
  ['git status -s', null],
  ['git checkout -- main', null],
  [`git clone ${URL}`, null],
  ['git clone a bouncer', null],
  ['git log --bouncer', null],
  ['git clone a --bouncer | Out-Null', refusal(REFUSED)],
  ['git clone a --bouncer; Remove-Item x', refusal(REFUSED)],
  ['git clone a --bouncer;', refusal(REFUSED)],
  ['git clone a --bouncer > out.txt', refusal(REFUSED)],
  ['& git clone a --bouncer', refusal(REFUSED)],
  ['git clone a \u2014bouncer', refusal(MISTYPED)],
  ['git clone a -bouncer', refusal(MISTYPED)],
  ['git clone a --Bouncer', refusal(MISTYPED)],
  ['git clone -- a \u2013-bouncer', refusal(MISTYPED)],
  ['git clone a \uFF0D\uFF0Dbouncer', refusal(MISTYPED)],
  ['git clone a \u2014bouncer; ls', refusal(REFUSED)],
  ['git clone a --bouncer "unterminated', null], // a parse error: PowerShell won't run it anyway
  ['', null],
]
// Background jobs: a parse error in Windows PowerShell 5.1, a refusal in pwsh.
const BACKGROUND = ['git clone a --bouncer &', { pwsh: refusal(REFUSED), powershell: null }]

for (const ps of ['pwsh', 'powershell']) {
  const skip = ps === 'powershell' && !isWindows ? 'Windows PowerShell 5.1 only exists on Windows'
    : !works(ps, ['-NoProfile', '-NonInteractive', '-Command', 'exit 0']) ? `${ps} is not installed` : false
  test(`${ps}: rewrites only "git clone ... --bouncer", refuses what it can't rewrite safely, never wraps git`, { skip }, t => {
    const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-ps-'))
    t.after(() => rmSync(dir, { recursive: true, force: true }))
    const lines = [...LINES, [BACKGROUND[0], BACKGROUND[1][ps]]]
    writeFileSync(path.join(dir, 'git-bouncer.ps1'), '"git-bouncer" + (($args | ForEach-Object { " <$_>" }) -join "")\n')
    writeFileSync(path.join(dir, 'lines.txt'), lines.map(([line]) => line).join('\n'))
    writeFileSync(path.join(dir, 'test.ps1'), [
      '$ErrorActionPreference = "Stop"',
      'Invoke-Expression $env:GB_SNIPPET',
      'if (Get-Command git -CommandType Function -ErrorAction Ignore) { "git is wrapped" } else { "git is not wrapped" }',
      '"leftover variables: " + @(Get-Variable -Name gitBouncer* -ErrorAction Ignore).Count',
      'foreach ($line in [System.IO.File]::ReadAllText($env:GB_LINES) -split "\\n") {',
      '  $r = ConvertTo-BouncerClone $line',
      '  if ($null -eq $r) { "<unchanged>" } else { "=> $r" }',
      '}',
      'Invoke-Expression (ConvertTo-BouncerClone "git clone \'https://github.com/a/b\' \'my dir\' --bouncer")',
      'try { Invoke-Expression (ConvertTo-BouncerClone "git clone a -bouncer") } catch { "refused, exit code $LASTEXITCODE" }',
    ].join('\n'))
    const r = spawnSync(ps, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(dir, 'test.ps1')], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${dir}${path.delimiter}${process.env.PATH}`, GB_SNIPPET: shellInit('powershell'), GB_LINES: path.join(dir, 'lines.txt') },
    })
    assert.equal(r.status, 0, r.stderr)
    assert.deepEqual(r.stdout.trim().split(/\r?\n/), [
      'git is not wrapped',
      'leftover variables: 0',
      ...lines.map(([, want]) => (want === null ? '<unchanged>' : `=> ${want}`)),
      'git-bouncer <clone> <https://github.com/a/b> <my dir>',
      'refused, exit code 2',
    ])
  })
}

// --- without the snippet: what real git does ---------------------------------------------------
// These pin down the docs' warning. git rejects --bouncer only in some positions; elsewhere it's
// just a folder name, and the clone happens unchecked.

test('without the snippet, real git refuses --bouncer before "--"', { skip: !works('git', ['--version']) && 'git is not installed' }, t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-git-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  // .invalid never resolves (RFC 2606), and git rejects the option before it would connect anyway.
  const r = spawnSync('git', ['clone', 'https://example.invalid/a/b', '--bouncer'], { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } })
  assert.equal(r.status, 129)
  assert.match(r.stderr, /unknown option/)
})

test('without the snippet, real git clones unchecked when --bouncer comes after "--" or uses a look-alike dash', { skip: !works('git', ['--version']) && 'git is not installed' }, t => {
  const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-git-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const git = (args, cwd) => spawnSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } })
  assert.equal(git(['init', '-q', 'src'], dir).status, 0) // a local, empty repo: no network
  const src = path.join(dir, 'src')
  for (const [i, args, folder] of [
    [1, ['clone', '-q', '--', src, '--bouncer'], '--bouncer'],
    [2, ['clone', '-q', '--end-of-options', src, '--bouncer'], '--bouncer'],
    [3, ['clone', '-q', src, '\u2014bouncer'], '\u2014bouncer'],
  ]) {
    const work = path.join(dir, `w${i}`)
    mkdirSync(work)
    const r = git(args, work)
    assert.equal(r.status, 0, `${JSON.stringify(args)} ${r.stderr}`)
    assert.ok(existsSync(path.join(work, folder)), `${JSON.stringify(args)} cloned into ${folder}`)
  }
})
