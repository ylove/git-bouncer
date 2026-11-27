// Opt-in shell integration: `git clone <url> [dir] --bouncer` runs `bouncer clone <url> [dir]`.
//
// git doesn't let a tool add a flag to its built-in `clone`. But your shell decides what the word
// "git" means before git ever runs, so a small shell function can send that one flag to
// git-bouncer. `bouncer shell-init <shell>` prints the snippet; you add it to your shell's config
// yourself. Nothing here edits your dotfiles, and nothing is installed behind your back.
//
// The properties that matter, each one tested:
//  - Every git command without --bouncer reaches the real git with exactly the same arguments
//    (spaces, quotes, empty strings, "--") and returns git's exit code.
//  - The snippets are constants. The only input is the shell name, checked against four known
//    values, so nothing from outside can end up inside text you are going to eval.
//  - It fails safe. If the snippet isn't loaded, git itself rejects --bouncer as an unknown
//    option, so "git clone <url> --bouncer" can never quietly clone without the check.
//
// Every argument except --bouncer is passed to "bouncer clone" in order, so `--ref v1.2` works.
// git-only options such as --depth are refused by bouncer with an error, never silently dropped.
// A --bouncer after "--" is left alone: after "--", git reads everything as a name.

import path from 'node:path'
import { UsageError } from './url.js'

export const SHELLS = Object.freeze(['bash', 'zsh', 'fish', 'powershell'])

const NO_SETUP = [
  'No setup at all: "git bouncer <url>" already works, because git runs any',
  'git-<name> program on your PATH as "git <name>".',
]

const header = (title, lines) => [`git-bouncer shell integration for ${title} (printed by: bouncer shell-init)`, '', ...lines, ...NO_SETUP]
  .map(l => (l ? `# ${l}` : '#')).join('\n')

// bash and zsh share one function body. Notes for readers:
//  - `function git {` rather than `git() {`: if you have an alias named git, the `git()` form is
//    alias-expanded while being defined (bash defines the wrong function; zsh refuses to).
//  - `command git` / `command bouncer` run the programs on PATH, skipping shell functions, so the
//    function never calls itself.
//  - No arrays: the arguments are rebuilt in place with `set --`, which keeps every argument
//    exactly as it was and works the same in bash 3.2 (macOS), bash 5 and zsh.
const POSIX_FUNCTION = `function git {
  case "\${1-}" in
    clone) ;;
    *) command git "$@"; return ;;
  esac
  local __gb_arg __gb_on=0
  for __gb_arg in "$@"; do
    case $__gb_arg in
      --) break ;;
      --bouncer) __gb_on=1; break ;;
    esac
  done
  if [ "$__gb_on" = 0 ]; then
    command git "$@"
    return
  fi
  # Rebuild the arguments without "clone" and without --bouncer, keeping the rest in order.
  shift
  local __gb_n=$# __gb_ended=0
  while [ "$__gb_n" -gt 0 ]; do
    __gb_arg=$1
    shift
    __gb_n=$((__gb_n - 1))
    if [ "$__gb_ended" = 0 ]; then
      case $__gb_arg in
        --bouncer) continue ;;
        --) __gb_ended=1 ;;
      esac
    fi
    set -- "$@" "$__gb_arg"
  done
  command bouncer clone "$@"
}`

const posix = (shell, rcFile) => `${header(shell, [
  'This adds one thing: "git clone <url> [dir] --bouncer" runs "bouncer clone <url> [dir]".',
  'Every other git command goes straight to the real git, unchanged.',
  '',
  `Turn it on:  add this line to ${rcFile}, then open a new terminal:`,
  `               eval "$(bouncer shell-init ${shell})"`,
  'Turn it off: delete that line and open a new terminal (or run: unset -f git).',
  'If you also have an alias named git, the alias wins and this does nothing.',
])}
${POSIX_FUNCTION}
`

const FISH = `${header('fish', [
  'This adds one thing: "git clone <url> [dir] --bouncer" runs "bouncer clone <url> [dir]".',
  'Every other git command goes straight to the real git, unchanged.',
  '',
  'Turn it on:  add this line to ~/.config/fish/config.fish, then open a new terminal:',
  '               bouncer shell-init fish | source',
  'Turn it off: delete that line and open a new terminal (or run: functions --erase git).',
])}
function git --description 'git, plus "git clone <url> --bouncer" for git-bouncer'
    if test (count $argv) -eq 0; or test "$argv[1]" != clone
        command git $argv
        return $status
    end
    set -l on 0
    for arg in $argv
        if test "$arg" = --
            break
        else if test "$arg" = --bouncer
            set on 1
            break
        end
    end
    if test $on -eq 0
        command git $argv
        return $status
    end
    # Everything after "clone" except --bouncer, in order.
    set -l rest
    set -l ended 0
    for arg in $argv[2..-1]
        if test $ended -eq 0; and test "$arg" = --bouncer
            continue
        end
        if test "$arg" = --
            set ended 1
        end
        set -a rest $arg
    end
    command bouncer clone $rest
    return $status
end
`

// PowerShell is different on purpose. A PowerShell function can't wrap git transparently: before
// a function sees its arguments, PowerShell removes a bare `--` and splits `-a:b` into two, so a
// git function would turn "git checkout -- file" into "git checkout file". Instead, the snippet
// rewrites the line you typed when you press Enter, and only when it is exactly
// `git clone ... --bouncer`. git itself is never wrapped. The rewrite uses PowerShell's own parser
// and edits only the "git" and "--bouncer" words, so the rest of the line is byte-for-byte yours.
const POWERSHELL = `${header('PowerShell', [
  'This adds one thing: when you type "git clone <url> [dir] --bouncer" and press Enter,',
  'the line is rewritten to "bouncer clone <url> [dir]" before it runs, and you see the rewrite.',
  'Nothing else you type is changed. git itself is not wrapped, so every other git command,',
  'and every script, runs the real git exactly as before.',
  '(Why not a git function, as in bash, zsh and fish? PowerShell changes a function\'s arguments',
  'before the function sees them: it removes a bare -- and splits -a:b into two.)',
  '',
  'Turn it on:  add this line to your profile (notepad $PROFILE), then open a new terminal:',
  '               Invoke-Expression (& bouncer shell-init powershell | Out-String)',
  'Turn it off: delete that line and open a new terminal (or, in this one, run:',
  '               Set-PSReadLineKeyHandler -Chord Enter -Function AcceptLine)',
  'Needs PSReadLine, which PowerShell loads by default in a terminal window.',
])}
function global:ConvertTo-BouncerClone {
  # Returns the rewritten line, or $null to leave the line exactly as typed.
  # (global: so the Enter handler finds it however this snippet was loaded.)
  param([string]$Line)
  $tokens = $null
  $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($Line, [ref]$tokens, [ref]$errors)
  if ($errors.Count -ne 0 -or $null -eq $ast.EndBlock -or $ast.EndBlock.Statements.Count -ne 1) { return $null }
  $pipeline = $ast.EndBlock.Statements[0]
  if ($pipeline -isnot [System.Management.Automation.Language.PipelineAst] -or $pipeline.PipelineElements.Count -ne 1) { return $null }
  $command = $pipeline.PipelineElements[0]
  if ($command -isnot [System.Management.Automation.Language.CommandAst]) { return $null }
  if ($command.InvocationOperator -ne 'Unknown' -or $command.Redirections.Count -ne 0) { return $null }
  $words = $command.CommandElements
  $isWord = {
    param($element, $value)
    ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) -and
      $element.StringConstantType -eq 'BareWord' -and $element.Value -ceq $value
  }
  if ($words.Count -lt 3 -or -not (& $isWord $words[0] 'git') -or -not (& $isWord $words[1] 'clone')) { return $null }
  $flags = @()
  for ($i = 2; $i -lt $words.Count; $i++) {
    if ($words[$i].Extent.Text -in @('--', "'--'", '"--"')) { break }
    if (& $isWord $words[$i] '--bouncer') { $flags += $i }
  }
  if ($flags.Count -eq 0) { return $null }
  # Remove each --bouncer and the space before it, last one first so earlier offsets stay valid.
  $new = $Line
  for ($k = $flags.Count - 1; $k -ge 0; $k--) {
    $from = $words[$flags[$k] - 1].Extent.EndOffset
    $new = $new.Remove($from, $words[$flags[$k]].Extent.EndOffset - $from)
  }
  $git = $words[0].Extent
  return $new.Remove($git.StartOffset, $git.EndOffset - $git.StartOffset).Insert($git.StartOffset, 'bouncer')
}

if (Get-Command Set-PSReadLineKeyHandler -ErrorAction Ignore) {
  $enter = Get-PSReadLineKeyHandler -Bound | Where-Object { $_.Key -eq 'Enter' } | Select-Object -First 1
  if ($null -eq $enter -or $enter.Function -in @('AcceptLine', 'GitBouncerAcceptLine')) {
    Set-PSReadLineKeyHandler -Chord Enter -BriefDescription GitBouncerAcceptLine -Description 'Rewrite "git clone <url> --bouncer" to "bouncer clone <url>", then run the line' -ScriptBlock {
      param($key, $arg)
      try {
        $line = $null
        $cursor = $null
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
        $new = ConvertTo-BouncerClone $line
        if ($null -ne $new) { [Microsoft.PowerShell.PSConsoleReadLine]::Replace(0, $line.Length, $new) }
      } catch {
        # Never get in the way of Enter. If this fails, the line runs as typed, and git rejects
        # --bouncer as an unknown option, so nothing is cloned without the check.
      }
      [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine($key, $arg)
    }
  } else {
    Write-Warning "git-bouncer: Enter is already bound to $($enter.Function), so 'git clone <url> --bouncer' was not set up. 'git bouncer <url>' works without it."
  }
}
`

const SNIPPETS = Object.freeze({
  bash: posix('bash', '~/.bashrc (on macOS, ~/.bash_profile)'),
  zsh: posix('zsh', '~/.zshrc'),
  fish: FISH,
  powershell: POWERSHELL,
})

/**
 * The snippet to add to your shell's config.
 * @param {string} shell  one of SHELLS
 * @returns {string}
 */
export function shellInit(shell) {
  if (typeof shell !== 'string' || !SHELLS.includes(shell)) {
    throw new UsageError(
      shell ? 'That shell isn\'t supported.' : 'Couldn\'t tell which shell you use.',
      `Name it: bouncer shell-init ${SHELLS.join('|')}`,
    )
  }
  return SNIPPETS[shell]
}

/**
 * Best guess at your shell, or null. Name it to be sure: `bouncer shell-init fish`.
 *
 * $SHELL is your login shell, which is usually the one you're typing in. PSModulePath is set
 * inside PowerShell; outside Windows that's the only place it exists, so it wins. On Windows it's
 * set system-wide, so there it only counts when $SHELL (which Git Bash sets) says nothing.
 * @param {Record<string, string|undefined>} [env]
 * @param {string} [platform]
 * @returns {'bash'|'zsh'|'fish'|'powershell'|null}
 */
export function detectShell(env = process.env, platform = process.platform) {
  if (platform !== 'win32' && env.PSModulePath) return 'powershell'
  const login = typeof env.SHELL === 'string' ? path.basename(env.SHELL.replace(/\\/g, '/')).replace(/\.exe$/i, '') : ''
  if (['bash', 'zsh', 'fish'].includes(login)) return login
  if (login === 'pwsh' || login === 'powershell') return 'powershell'
  if (env.PSModulePath) return 'powershell'
  return null
}
