// Opt-in shell integration: `git clone <url> [dir] --bouncer` runs `git-bouncer clone <url> [dir]`.
//
// git doesn't let a tool add a flag to its built-in `clone`. But your shell decides what the word
// "git" means before git ever runs, so a small shell function can send that one flag to
// git-bouncer. `bouncer shell-init <shell>` prints the snippet; you add it to your shell's config
// yourself. Nothing here edits your dotfiles, and nothing is installed behind your back.
//
// The properties that matter, each one tested:
//  - Every git command without --bouncer reaches the real git with exactly the same arguments
//    (spaces, quotes, empty strings, "--") and returns git's exit code.
//  - --bouncer means the check runs. Once the first word after git is "clone", a --bouncer
//    anywhere, even after "--" or "--end-of-options", sends the command to git-bouncer and git is
//    never called. (git itself would read a --bouncer after "--" as a folder name and clone
//    unchecked.) Every other argument goes along in order, so `--ref v1.2` works, and git-only
//    options such as --depth are refused by git-bouncer with an error, never silently dropped.
//  - A look-alike (an em dash before "bouncer", -bouncer, --Bouncer: smart punctuation and
//    copy-paste make these) stops with "Did you mean --bouncer?" and exit 2. It never reaches git either.
//  - The snippets are constants, and pure ASCII. The only input is the shell name, checked
//    against four known values, so nothing from outside can end up inside text you eval.
//
// What it can't do: without the snippet loaded, nothing stands between you and git, and a plain
// `git clone` runs unchecked as always. `git bouncer <url>` and `bouncer clone <url>` need no setup.
//
// It calls `git-bouncer` rather than `bouncer`: same program, but a name no other tool is likely
// to have put earlier on your PATH.

import { UsageError } from './url.js'

export const SHELLS = Object.freeze(['bash', 'zsh', 'fish', 'powershell'])

// "-" and its look-alikes: U+2010 hyphen, U+2011 non-breaking hyphen, U+2012 figure dash,
// U+2013 en dash, U+2014 em dash, U+2015 horizontal bar, U+2212 minus sign, U+FE58 small em dash,
// U+FE63 small hyphen-minus, U+FF0D fullwidth hyphen-minus. Each shell gets them as escapes, so
// the snippets stay ASCII (and survive a terminal or code page that would mangle the characters).
const DASHES = [0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0xFE58, 0xFE63, 0xFF0D]
const hex = cp => cp.toString(16).toUpperCase().padStart(4, '0')
const BASH_DASHES = DASHES.map(cp => `$'${[...Buffer.from(String.fromCodePoint(cp), 'utf8')].map(b => `\\x${b.toString(16)}`).join('')}'`).join(' ')
const PCRE_DASHES = `-${DASHES.map(cp => `\\x{${hex(cp)}}`).join('')}`
const DOTNET_DASHES = `\\-${DASHES.map(cp => `\\u${hex(cp)}`).join('')}`

const TYPO_MESSAGE = 'git-bouncer: an argument looks like --bouncer typed with a different dash (copy-paste often does this). Did you mean --bouncer? Nothing was run.'

const NO_SETUP = [
  'Without this, plain "git clone" runs unchecked. No setup needed for these:',
  '"git bouncer <url>" (git runs any git-<name> program on your PATH) and "bouncer clone <url>".',
]

const header = (title, lines) => [`git-bouncer shell integration for ${title} (printed by: bouncer shell-init)`, '', ...lines, ...NO_SETUP]
  .map(l => (l ? `# ${l}` : '#')).join('\n')

// bash and zsh share one function body. Notes for readers:
//  - `function git {` rather than `git() {`: if you have an alias named git, the `git()` form is
//    alias-expanded while being defined (bash defines the wrong function; zsh refuses to).
//  - `command git` / `command git-bouncer` run the programs on PATH, skipping shell functions, so
//    the function never calls itself.
//  - No arrays: the arguments are rebuilt in place with `set --`, which keeps every argument
//    exactly as it was and works the same in bash 3.2 (macOS), bash 5 and zsh.
//  - The dash look-alikes are $'\xe2\x80\x94'-style byte strings, compared as plain strings, so
//    the check works in any locale.
const POSIX_FUNCTION = `function git {
  case "\${1-}" in
    clone) ;;
    *) command git "$@"; return ;;
  esac
  local __gb_arg __gb_on=0 __gb_typo=0 __gb_s __gb_d __gb_more __gb_n
  for __gb_arg in "$@"; do
    case $__gb_arg in
      --bouncer) __gb_on=1; continue ;;
    esac
    # Strip a leading run of dashes, look-alikes included. If "bouncer" is what's left, it's a typo.
    __gb_s=$__gb_arg
    __gb_more=1
    while [ "$__gb_more" = 1 ]; do
      __gb_more=0
      for __gb_d in - ${BASH_DASHES}; do
        case $__gb_s in
          "$__gb_d"*) __gb_s=\${__gb_s#"$__gb_d"}; __gb_more=1 ;;
        esac
      done
    done
    if [ "$__gb_s" != "$__gb_arg" ]; then
      case $__gb_s in
        [Bb][Oo][Uu][Nn][Cc][Ee][Rr]) __gb_typo=1 ;;
      esac
    fi
  done
  if [ "$__gb_on" = 1 ]; then
    # You asked for the check, so git is never called. Pass on everything after "clone" except
    # --bouncer, in order.
    shift
    __gb_n=$#
    while [ "$__gb_n" -gt 0 ]; do
      __gb_arg=$1
      shift
      __gb_n=$((__gb_n - 1))
      case $__gb_arg in
        --bouncer) continue ;;
      esac
      set -- "$@" "$__gb_arg"
    done
    command git-bouncer clone "$@"
    return
  fi
  if [ "$__gb_typo" = 1 ]; then
    printf '%s\\n' '${TYPO_MESSAGE}' >&2
    return 2
  fi
  command git "$@"
}`

const posix = (shell, rcFile) => `${header(shell, [
  'This adds one thing: "git clone <url> [dir] --bouncer" runs "git-bouncer clone <url> [dir]"',
  '(the same check as "bouncer clone"). Every other git command goes to the real git, unchanged.',
  '',
  `Turn it on:  add this line to ${rcFile}, then open a new terminal:`,
  `               eval "$(bouncer shell-init ${shell})"`,
  'Turn it off: delete that line and open a new terminal (or run: unset -f git).',
  'An alias named git that runs another program (like hub) wins over this function.',
])}
${POSIX_FUNCTION}
`

const FISH = `${header('fish', [
  'This adds one thing: "git clone <url> [dir] --bouncer" runs "git-bouncer clone <url> [dir]"',
  '(the same check as "bouncer clone"). Every other git command goes to the real git, unchanged.',
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
    set -l typo 0
    set -l rest
    for arg in $argv[2..-1]
        if test "$arg" = --bouncer
            set on 1
            continue
        end
        # Dashes (look-alikes included), then "bouncer": a mistyped --bouncer.
        if string match -qr -- '^[${PCRE_DASHES}]+(?i:bouncer)$' $arg
            set typo 1
        end
        set -a rest $arg
    end
    if test $on -eq 1
        # You asked for the check, so git is never called.
        command git-bouncer clone $rest
        return $status
    end
    if test $typo -eq 1
        printf '%s\\n' '${TYPO_MESSAGE}' >&2
        return 2
    end
    command git $argv
end
`

// PowerShell is different on purpose. A PowerShell function can't wrap git transparently: before
// a function sees its arguments, PowerShell removes a bare `--` and splits `-a:b` into two, so a
// git function would turn "git checkout -- file" into "git checkout file". Instead, the snippet
// looks at the line you typed when you press Enter. git itself is never wrapped.
//  - `git clone ... --bouncer` alone on the line is rewritten to `git-bouncer clone ...`. The
//    rewrite uses PowerShell's own parser and edits only the "git" and "--bouncer" words.
//  - A `git clone` with --bouncer (or a look-alike) anywhere else (a pipeline, after ";", in the
//    background with "&", with a redirection, after "& ") is replaced by a line that only prints
//    an error, because running it as typed would hand the flag to git.
//  - Anything else is left exactly as typed.
const REFUSE = `$global:LASTEXITCODE = 2; Write-Error ''{0}''`
const POWERSHELL = `${header('PowerShell', [
  'This adds one thing: when you type "git clone <url> [dir] --bouncer" and press Enter,',
  'the line is rewritten to "git-bouncer clone <url> [dir]" before it runs, and you see the rewrite.',
  'Nothing else you type is changed. git itself is not wrapped, so every other git command,',
  'and every script, runs the real git exactly as before.',
  '(Why not a git function, as in bash, zsh and fish? PowerShell changes a function\'s arguments',
  'before the function sees them: it removes a bare -- and splits -a:b into two.)',
  '',
  'Turn it on:  add this line to your profile (notepad $PROFILE), then open a new terminal:',
  '               Invoke-Expression (& bouncer shell-init powershell | Out-String)',
  'Turn it off: delete that line and open a new terminal (or, in this one, run:',
  '               Set-PSReadLineKeyHandler -Chord Enter -Function AcceptLine)',
  'Needs PSReadLine, which PowerShell loads by default in a terminal window. A later',
  'Set-PSReadLineOption -EditMode in your profile resets Enter; load this after it.',
])}
function ConvertTo-BouncerClone {
  # Returns the line to run instead, or $null to leave the line exactly as typed.
  param([string]$Line)
  $tokens = $null
  $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput($Line, [ref]$tokens, [ref]$errors)
  if ($errors.Count -ne 0) { return $null }
  $refuse = '${REFUSE}'
  $text = {
    param($element)
    if ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $element.Value } else { $element.Extent.Text }
  }
  $dashed = '^[${DOTNET_DASHES}]+bouncer$'
  $clone = $null
  $flag = $false
  foreach ($command in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $words = $command.CommandElements
    if ($words.Count -lt 2 -or (& $text $words[0]) -notin @('git', 'git.exe') -or (& $text $words[1]) -cne 'clone') { continue }
    for ($i = 2; $i -lt $words.Count; $i++) {
      $value = & $text $words[$i]
      if ($value -ceq '--bouncer') { $flag = $true; $clone = $command }
      elseif ($value -match $dashed) { $clone = $command }
    }
  }
  if ($null -eq $clone) { return $null }
  $statements = $ast.EndBlock.Statements
  $alone = $statements.Count -eq 1 -and $statements[0] -is [System.Management.Automation.Language.PipelineAst] -and
    $statements[0].PipelineElements.Count -eq 1 -and [object]::ReferenceEquals($statements[0].PipelineElements[0], $clone) -and
    $clone.InvocationOperator -eq 'Unknown' -and $clone.Redirections.Count -eq 0 -and
    @($tokens | Where-Object { $_.Kind -in @('Semi', 'Ampersand') }).Count -eq 0
  if (-not $alone) { return $refuse -f 'git-bouncer: put "git clone <url> --bouncer" on a line by itself. Nothing was run.' }
  if (-not $flag) { return $refuse -f '${TYPO_MESSAGE}' }
  # Remove every --bouncer and the space before it, last one first so earlier offsets stay valid.
  $words = $clone.CommandElements
  $new = $Line
  for ($i = $words.Count - 1; $i -ge 2; $i--) {
    if ((& $text $words[$i]) -ceq '--bouncer') {
      $from = $words[$i - 1].Extent.EndOffset
      $new = $new.Remove($from, $words[$i].Extent.EndOffset - $from)
    }
  }
  $git = $words[0].Extent
  return $new.Remove($git.StartOffset, $git.EndOffset - $git.StartOffset).Insert($git.StartOffset, 'git-bouncer')
}

if (Get-Command Set-PSReadLineKeyHandler -ErrorAction Ignore) {
  $gitBouncerEnter = Get-PSReadLineKeyHandler -Bound | Where-Object { $_.Key -eq 'Enter' } | Select-Object -First 1
  if ($null -eq $gitBouncerEnter -or $gitBouncerEnter.Function -in @('AcceptLine', 'GitBouncerAcceptLine')) {
    # Captured now, so redefining ConvertTo-BouncerClone later can't change what Enter does.
    $gitBouncerConvert = \${function:ConvertTo-BouncerClone}
    $gitBouncerHandler = {
      param($key, $arg)
      $line = $null
      $cursor = $null
      try {
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
        $new = & $gitBouncerConvert $line
        if ($null -ne $new) { [Microsoft.PowerShell.PSConsoleReadLine]::Replace(0, $line.Length, $new) }
      } catch {
        # Never let a failure here turn --bouncer into a plain git clone: a line that mentions
        # bouncer is replaced with one that only reports the problem.
        try {
          if ($line -match 'bouncer') { [Microsoft.PowerShell.PSConsoleReadLine]::Replace(0, $line.Length, ('${REFUSE}' -f 'git-bouncer: could not check this line. Nothing was run.')) }
        } catch { }
      }
      [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine($key, $arg)
    }.GetNewClosure()
    Set-PSReadLineKeyHandler -Chord Enter -BriefDescription GitBouncerAcceptLine -Description 'Send "git clone <url> --bouncer" to git-bouncer, then run the line' -ScriptBlock $gitBouncerHandler
  } else {
    Write-Warning "git-bouncer: Enter is already bound to $($gitBouncerEnter.Function), so 'git clone <url> --bouncer' was not set up. 'git bouncer <url>' works without it."
  }
  Remove-Variable -Name gitBouncerEnter, gitBouncerConvert, gitBouncerHandler -ErrorAction Ignore
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
 * Best guess at your shell, or null when it can't tell. Name it to be sure: `bouncer shell-init fish`.
 *
 * $SHELL is your login shell, which is usually the one you're typing in. PSModulePath is set inside
 * PowerShell, but also in every shell started from PowerShell (it's inherited), and on Windows it's
 * set everywhere. So when $SHELL names bash, zsh or fish and PSModulePath is set too, it's a guess
 * either way, and the answer is null: printing the wrong snippet for eval would only be confusing.
 * @param {Record<string, string|undefined>} [env]
 * @returns {'bash'|'zsh'|'fish'|'powershell'|null}
 */
export function detectShell(env = process.env) {
  const login = typeof env.SHELL === 'string' ? env.SHELL.split(/[\\/]/).pop().replace(/\.exe$/i, '') : ''
  const named = ['bash', 'zsh', 'fish'].includes(login) ? login : ['pwsh', 'powershell'].includes(login) ? 'powershell' : null
  if (env.PSModulePath) return named === null || named === 'powershell' ? 'powershell' : null
  return named
}
