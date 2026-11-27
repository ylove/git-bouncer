# Shell integration: `git clone <url> --bouncer`

You can keep typing `git clone`. Add `--bouncer` anywhere after `clone`, and git-bouncer checks the repository first:

```sh
git clone https://github.com/someone/take-home-test --bouncer
# runs: git-bouncer clone https://github.com/someone/take-home-test   (the same as bouncer clone)
```

This is **opt-in**. It needs one line in your shell's config file, and you add that line yourself. Without that line, nothing changes: a plain `git clone` runs unchecked, as it always has (see [Without the snippet](#without-the-snippet)).

## No setup at all: `git bouncer <url>`

This already works, with nothing to configure:

```sh
git bouncer https://github.com/someone/take-home-test
```

When you type `git <name>` and `<name>` isn't one of git's own commands, git looks for a program called `git-<name>` on your PATH and runs it. Installing git-bouncer puts a `git-bouncer` program on your PATH, so `git bouncer` works anywhere git does. `bouncer clone <url>` does the same thing. These are the forms to use when it matters: they work on any machine with git-bouncer installed, with no setup. If that's enough for you, you can stop reading here.

## Turning it on

First, read what you're about to add. `bouncer shell-init zsh` (or `bash`, `fish`, `powershell`) prints the whole snippet, and it's short. A line in your shell config runs every time you open a terminal, so you should know what it does.

| Shell | Add this line to | The line |
|---|---|---|
| zsh (the macOS default) | `~/.zshrc` | `eval "$(bouncer shell-init zsh)"` |
| bash | `~/.bashrc` (on macOS, `~/.bash_profile`) | `eval "$(bouncer shell-init bash)"` |
| fish | `~/.config/fish/config.fish` | `bouncer shell-init fish \| source` |
| PowerShell | your profile (run `notepad $PROFILE`) | `Invoke-Expression (& bouncer shell-init powershell \| Out-String)` |

Then open a new terminal.

With no shell name, `bouncer shell-init` guesses your shell from `$SHELL` (and from `PSModulePath` for PowerShell). `$SHELL` is your *login* shell, so if you use a different one, name it. If the two disagree (say, zsh started from a PowerShell window, which passes `PSModulePath` on), it doesn't guess and asks you to name it.

## Turning it off

Delete the line and open a new terminal. To turn it off in the current terminal only:

| Shell | Run |
|---|---|
| bash, zsh | `unset -f git` |
| fish | `functions --erase git` |
| PowerShell | `Set-PSReadLineKeyHandler -Chord Enter -Function AcceptLine` |

## What it does, exactly

- `git clone <args> --bouncer` runs `git-bouncer clone <args>`. Every argument except `--bouncer` is passed along, in order.
- **`--bouncer` anywhere after `clone` means the check runs, and git is never called.** That includes after `--` or `--end-of-options`: `git clone -- <url> --bouncer` runs `git-bouncer clone -- <url>`. (Plain git would read that `--bouncer` as a folder name and clone into it, unchecked.)
- So git-bouncer's own options work: `git clone <url> my-dir --ref v1.2 --bouncer`.
- Options only git understands (`--depth 1`, `-b main`) are passed along too, and git-bouncer refuses them with an error. Nothing is dropped silently.
- **A look-alike stops everything.** Smart punctuation and copy-paste turn `--` into an em dash or an en dash. On a `git clone` line, an argument that is dashes (any of the look-alikes) followed by `bouncer`, like `—bouncer`, `-bouncer` or `--Bouncer`, prints `Did you mean --bouncer?` and exits with code 2. Neither git nor git-bouncer runs.
- **Everything else goes to the real git, untouched:** every other git command, and `git clone` without `--bouncer`.
- Only `git clone ...` with `clone` as the first word is rerouted. `git -C some-dir clone <url> --bouncer` goes to the real git.
- It runs `git-bouncer`, not `bouncer`: the same program, under a name no other tool is likely to have put earlier on your PATH.

## Without the snippet

If the snippet isn't loaded (a new laptop, a typo in your config, a different shell, a script), nothing stands between you and git. A plain `git clone <url>` runs unchecked, as it always has.

git itself only rejects `--bouncer` in some positions. Typed with plain hyphens before any `--`, git refuses it (`error: unknown option 'bouncer'`) and nothing is cloned. But `git clone -- <url> --bouncer`, `git clone --end-of-options <url> --bouncer` and `git clone <url> —bouncer` (an em dash) are ordinary folder names to git: it clones into a folder called `--bouncer` or `—bouncer`, with no check and no warning. The tests show both behaviors against the real git.

So treat `--bouncer` as a convenience, not a safety net. When it matters, use `git bouncer <url>` or `bouncer clone <url>`. Those work with no setup, and they can't silently fall back to a plain clone.

## Why it's opt-in

- **Your shell config is yours.** A tool that edits your dotfiles during install, or quietly wraps `git`, changes something about every command you type. That should be your decision, made knowing what the change is.
- **A wrapper is code in front of every git command.** This one is small, and the tests check that it passes every other command through exactly. But no wrapper at all is smaller still, and `git bouncer <url>` doesn't need one.
- **It's easy to undo** because you know exactly where it is: one line you wrote.

## How it works

### bash, zsh and fish: a function named `git`

Shells look up functions before they look for programs on your PATH, so when you type `git`, the function runs. If the first argument is `clone` and `--bouncer` is among the rest, it runs `git-bouncer clone` with the other arguments. If one of the rest looks like a mistyped `--bouncer`, it stops with an error. Otherwise it runs `command git "$@"`. `command` skips shell functions and runs the real git program, and `"$@"` passes every argument exactly as received, including spaces, quotes and empty arguments. The exit code you get back is git's (or git-bouncer's).

Functions from your shell config only apply to what you type and to files you `source`. Scripts that run as their own process (`./build.sh`, a Makefile, your editor's git integration) don't read your config, so they never see the function.

Three details worth knowing:

- It's written `function git {`, not `git() {`. If you also have an alias named `git`, the `git()` form is alias-expanded while it's being defined: with `alias git=hub`, bash would define a function called `hub`, and zsh refuses to load it at all. When you type `git`, an alias still comes first. An alias that runs another program (`alias git=hub`) means this function never runs. One that calls `git` again (`alias git='noglob git'`) reaches the function as usual.
- It uses no arrays. The arguments are rebuilt in place with `set --`, so it behaves the same in bash 3.2 (still the default bash on macOS), bash 5 and zsh, including with `set -u`.
- The dash look-alikes are written as byte escapes (`$'\xe2\x80\x94'` is the em dash) and compared as plain strings, so the snippet is pure ASCII and the check works in any locale.

### PowerShell: the line you typed is rewritten, and git is not wrapped

A PowerShell function can't wrap git transparently. Before a function sees its arguments, PowerShell's parameter binder changes some of them: it removes a bare `--` and splits `-a:b` into two arguments. Try it:

```powershell
function f { $args }
f checkout -- main     # prints "checkout" and "main": the -- is gone
```

A `git` function would quietly turn `git checkout -- main` ("restore the file called main") into `git checkout main` ("switch to the branch called main"). And functions from your PowerShell profile are visible to the scripts you run in that session, so the change would reach them too.

So the PowerShell snippet doesn't define a `git` function. It binds the Enter key (through PSReadLine, the line editor PowerShell uses by default) to look at the line you typed, using PowerShell's own parser:

- **A plain `git clone ... --bouncer` on a line by itself** (`--bouncer` anywhere, quoted or not, even after `--`) is rewritten to `git-bouncer clone ...` before it runs. Only the `git` and `--bouncer` words are edited, so the rest of the line stays exactly as you typed it. You see the rewritten line on screen, and that's what goes into your history.
- **A `git clone` with `--bouncer` anywhere else** can't be rewritten safely, and running it as typed would hand the flag to git. That covers a pipeline, a line with more than one statement or a `;`, a redirection, `& git ...`, and a background job ending in `&`, where nobody could answer git-bouncer's questions. These lines are replaced with one that only prints an error and sets `$LASTEXITCODE` to 2.
- **A look-alike** (`—bouncer`, `-bouncer`, `--Bouncer`) is replaced the same way, with `Did you mean --bouncer?`.
- **Every other line is left exactly as typed.** Scripts never go through the Enter key, so they're never affected.

If your Enter key is already bound to something custom, the snippet doesn't touch it and prints a warning instead. A `Set-PSReadLineOption -EditMode ...` later in your profile resets the key bindings and removes the handler, so load this line after it. The handler keeps its own copy of the rewrite function, so redefining `ConvertTo-BouncerClone` later in the session doesn't change what Enter does. If the handler ever fails, a line that mentions `bouncer` is replaced with an error rather than run as typed.

## Is it safe to `eval`?

`eval "$(bouncer shell-init zsh)"` runs whatever `bouncer shell-init` prints, so that output must never contain anything someone else could influence. It doesn't. The four snippets are constants in [`src/shell-init.js`](../src/shell-init.js), built only from text in that file, and they're pure ASCII. The only input is the shell name, which is checked against `bash`, `zsh`, `fish` and `powershell`. Nothing from your environment, a repository or the network ends up in the text. The tests check that too.

The usual rule for any `eval "$(some-tool init)"` line still applies: it trusts `some-tool` to be what it claims. Add it only for a git-bouncer you installed yourself. See "Trusting git-bouncer itself" in the [threat model](../THREAT_MODEL.md).
