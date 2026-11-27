# git-bouncer

**Don't just `git clone`. Let the bouncer check it first.**

[![CI](https://github.com/ylove/git-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/ylove/git-bouncer/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ylove/git-bouncer/badge)](https://scorecard.dev/viewer/?uri=github.com/ylove/git-bouncer)

Malicious repositories are now a routine way to attack developers: poisoned "starter kits", fake take-home tests from fake recruiters, and look-alike accounts like `micr0s0ft`. Open one in your editor, or run `npm install` on your everyday laptop, and it can take your SSH keys and GitHub tokens, then push malware into **your** repos.

git-bouncer is a door check for code you didn't write.

```sh
npm install -g git-bouncer

bouncer clone <url>      # instead of: git clone <url>
git bouncer <url>        # the same thing, as a git subcommand
```

![A clean repository is checked in a sandbox and let in](site/img/let-in.gif)

## What it does

1. **ID check**, on your machine, before anything downloads. Who published this repo, and are they who they look like? Look-alike owners (`micr0s0ft`, `vercell`), impersonated famous projects, accounts that changed hands, brand-new accounts, and repos named in public malware reporting.
2. **Pat-down**, in a throwaway container with **none of your credentials**: no capabilities, read-only filesystem, nothing from your machine mounted. The repo is cloned there and checked for the techniques real campaigns use. **None of its code is run.**
3. **Verdict.** Clean: it asks before cloning to your machine, at the **exact commit it checked**, and installs only the dependency tree it verified. Not clean: it tells you what it found, in plain language, and deletes the sandbox.

![A look-alike account is turned away before anything is downloaded](site/img/turned-away.gif)

### What the pat-down looks for

- **Runs when you open the folder:** VS Code tasks set to `folderOpen`, dev container commands that run on your host, AI-agent hooks and MCP servers.
- **Runs when you install:** every install script npm would run (including `binding.gyp` builds and workspace scripts), plus `.npmrc`, `.yarnrc` and `.pnpmfile.cjs` tricks that work even with `--ignore-scripts`.
- **Poisoned dependencies:** known-malicious packages (OSV), checksum mismatches against the lockfile, invalid registry signatures, typosquats, packages from outside the registry.
- **Hidden code:** payloads pushed off-screen with whitespace, decode-then-execute, fake font files that are JavaScript, blockchain command-and-control, invisible Unicode and Trojan Source.
- **Git tricks:** symlinks out of the repo, `.git` look-alike paths, case collisions, odd submodules. The clone itself happens inside the sandbox, because malicious repos have attacked `git clone` itself.

Every check, with its severity and a plain-language explanation: [docs/checks.md](docs/checks.md). The ID check: [docs/id-check.md](docs/id-check.md).

## No Docker?

- **Podman** works with the same command: free, open source, no account. If you have neither, git-bouncer offers to install Podman (or Docker Desktop), one yes per step.
- **Your own cloud:** `--runtime gcp` (Cloud Build) or `--runtime aws` (CodeBuild), with `--dry-run` to see exactly what it would run. These cost money and aren't live-tested by the maintainer; see [docs/cloud.md](docs/cloud.md) for setup and what to check. Issues and PRs for other providers are welcome.
- **GitHub Codespaces:** coming in [#23](https://github.com/ylove/git-bouncer/pull/23).

## More ways to use it

| | |
|---|---|
| `bouncer scan <url>` | Check only; never touches your disk. Exit code 0 let in, 1 turned away, 3 warning, 2 incomplete/error. Good for scripts. |
| `bouncer clone <url> --ref v1.2.3` | Check a branch, tag or exact commit. |
| `bouncer scan <url> --json` | Machine-readable result. Never asks, never installs. |
| `bouncer doctor` | Which sandbox runtimes and extras it can use here. |
| `bouncer shell-init` | Opt in to `git clone <url> --bouncer` ([details](docs/shell-integration.md)). |

If you already use **Snyk**, git-bouncer offers to run it on copies of the dependency manifests. Your Snyk token stays on your machine and never enters the sandbox.

## What it can't do

A clean result means **no known red flags**, not "safe". Static checks can be evaded, brand-new malware isn't in the databases yet, and nothing is run, so behavior that only shows up at runtime isn't seen. git-bouncer shrinks the blast radius of your first contact with an unfamiliar repo. It doesn't replace your judgment. The full list is in [THREAT_MODEL.md](THREAT_MODEL.md#known-limitations-read-these).

## Built in public

Every change landed through a pull request, and every pull request was attacked by an adversarial reviewer before it merged. Their findings, the fixes and the arguments are all on GitHub, and every finding became a regression test. If you're learning how a security tool gets built, read the [issues](https://github.com/ylove/git-bouncer/issues?q=is%3Aissue) and then the [pull requests](https://github.com/ylove/git-bouncer/pulls?q=is%3Apr) in order. #14, #15 and #16 are good starting points.

- How it's put together: [docs/DESIGN.md](docs/DESIGN.md)
- Contributing (new detections especially welcome): [CONTRIBUTING.md](CONTRIBUTING.md)
- Found a vulnerability in git-bouncer itself? Please report it privately: [SECURITY.md](SECURITY.md)
- Releases are published from CI with npm provenance and no long-lived tokens: [RELEASING.md](RELEASING.md)

Licensed under [Apache-2.0](LICENSE).
