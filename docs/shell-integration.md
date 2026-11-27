# Shell integration: `git clone <url> --bouncer`

You can keep typing `git clone`. Add `--bouncer` anywhere after `clone`, and git-bouncer checks the repository first:

```sh
git clone https://github.com/someone/take-home-test --bouncer
# runs: bouncer clone https://github.com/someone/take-home-test
```

This is **opt-in**. It needs one line in your shell's config file, and you add that line yourself.

## No setup at all: `git bouncer <url>`

This already works, with nothing to configure:

```sh
git bouncer https://github.com/someone/take-home-test
```

When you type `git <name>` and `<name>` isn't one of git's own commands, git looks for a program called `git-<name>` on your PATH and runs it. Installing git-bouncer puts a `git-bouncer` program on your PATH, so `git bouncer` works anywhere git does. If that's enough for you, you can stop reading here.

## Turning it on

First, read what you're about to add. `bouncer shell-init zsh` (or `bash`, `fish`, `powershell`) prints the whole snippet, and it's short. A line in your shell config runs every time you open a terminal, so you should know what it does.

| Shell | Add this line to | The line |
|---|---|---|
| zsh (the macOS default) | `~/.zshrc` | `eval "$(bouncer shell-init zsh)"` |
| bash | `~/.bashrc` (on macOS, `~/.bash_profile`) | `eval "$(bouncer shell-init bash)"` |
| fish | `~/.config/fish/config.fish` | `bouncer shell-init fish \| source` |
| PowerShell | your profile (run `notepad $PROFILE`) | `Invoke-Expression (& bouncer shell-init powershell \| Out-String)` |

Then open a new terminal.

With no shell name, `bouncer shell-init` guesses your shell from `$SHELL` (and from `PSModulePath` for PowerShell). `$SHELL` is your *login* shell, so if you use a different one, name it.

## Turning it off

Delete the line and open a new terminal. To turn it off in the current terminal only:

| Shell | Run |
|---|---|
| bash, zsh | `unset -f git` |
| fish | `functions --erase git` |
| PowerShell | `Set-PSReadLineKeyHandler -Chord Enter -Function AcceptLine` |

## What it does, exactly

- `git clone <args> --bouncer` runs `bouncer clone <args>`. Every argument except `--bouncer` is passed along, in order. `--bouncer` can go anywhere after `clone`.
- So bouncer's own options work: `git clone <url> my-dir --ref v1.2 --bouncer`.
- Options only git understands (`--depth 1`, `-b main`) are passed along too, and bouncer refuses them with an error. Nothing is dropped silently.
- **Everything else goes to the real git, untouched:** every other git command, `git clone` without `--bouncer`, and a `--bouncer` that comes after `--`. (After `--`, git reads every argument as a name, not an option, so the snippet does too.)
- Only `git clone ...` with `clone` as the first word is rerouted. `git -C some-dir clone <url> --bouncer` goes to the real git, which refuses it (see the next section).
- The flag is exactly `--bouncer`. `--bouncer=yes` or `--Bouncer` go to git, which refuses them.

## It fails safe

If the snippet isn't loaded (a new laptop, a typo in your config, a different shell), `git clone <url> --bouncer` reaches the real git, and git refuses it:

```
error: unknown option `bouncer'
```

Nothing is cloned. Forgetting the setup can never turn into an unchecked clone. The tests check this against the real git on every CI run.

## Why it's opt-in

- **Your shell config is yours.** A tool that edits your dotfiles during install, or quietly wraps `git`, changes something about every command you type. That should be your decision, made knowing what the change is.
- **A wrapper is code in front of every git command.** This one is small, and the tests check that it passes every other command through exactly. But no wrapper at all is smaller still, and `git bouncer <url>` doesn't need one.
- **It's easy to undo** because you know exactly where it is: one line you wrote.

## How it works

### bash, zsh and fish: a function named `git`

Shells look up functions before they look for programs on your PATH, so when you type `git`, the function runs. If the first argument is `clone` and `--bouncer` is among the rest, it runs `bouncer clone` with the other arguments. Otherwise it runs `command git "$@"`. `command` skips shell functions and runs the real git program, and `"$@"` passes every argument exactly as received, including spaces, quotes and empty arguments. The exit code you get back is git's (or bouncer's).

Functions from your shell config only apply to what you type and to files you `source`. Scripts that run as their own process (`./build.sh`, a Makefile, your editor's git integration) don't read your config, so they never see the function.

Two details worth knowing:

- It's written `function git {`, not `git() {`. If you also have an alias named `git`, the `git()` form is alias-expanded while it's being defined: with `alias git=hub`, bash would define a function called `hub`, and zsh refuses to load it at all. (When you type `git`, an alias still wins over any function, so if you have one, this does nothing until you remove it.)
- It uses no arrays. The arguments are rebuilt in place with `set --`, so it behaves the same in bash 3.2 (still the default bash on macOS), bash 5 and zsh, including with `set -u`.

### PowerShell: the line you typed is rewritten, and git is not wrapped

A PowerShell function can't wrap git transparently. Before a function sees its arguments, PowerShell's parameter binder changes some of them: it removes a bare `--` and splits `-a:b` into two arguments. Try it:

```powershell
function f { $args }
f checkout -- main     # prints "checkout" and "main": the -- is gone
```

A `git` function would quietly turn `git checkout -- main` ("restore the file called main") into `git checkout main` ("switch to the branch called main"). And functions from your PowerShell profile are visible to the scripts you run in that session, so the change would reach them too.

So the PowerShell snippet doesn't define a `git` function. It binds the Enter key (through PSReadLine, the line editor PowerShell uses by default) to look at the line you typed. Only if the line is a single, plain `git clone ... --bouncer` command is it rewritten to `bouncer clone ...` before it runs. You see the rewritten line on screen, and that's what goes into your history. The check uses PowerShell's own parser, and it edits only the `git` and `--bouncer` words, so the rest of the line stays exactly as you typed it.

Every other line is left alone, including pipelines, lines with `;`, redirections, `& git ...`, and a quoted `'--bouncer'`. Scripts never go through the Enter key, so they're never affected. If your Enter key is already bound to something custom, the snippet doesn't touch it and prints a warning instead.

## Is it safe to `eval`?

`eval "$(bouncer shell-init zsh)"` runs whatever `bouncer shell-init` prints, so that output must never contain anything someone else could influence. It doesn't. The four snippets are constants in [`src/shell-init.js`](../src/shell-init.js), and the only input is the shell name, which is checked against `bash`, `zsh`, `fish` and `powershell`. Nothing from your environment, a repository or the network ends up in the text. The tests check that too.

The usual rule for any `eval "$(some-tool init)"` line still applies: it trusts `some-tool` to be what it claims. Add it only for a git-bouncer you installed yourself. See "Trusting git-bouncer itself" in the [threat model](../THREAT_MODEL.md).
