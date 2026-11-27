# git-bouncer

**Don't just `git clone`. Let the bouncer check it first.**

> 🚧 **Being built in public.** This repo is under active construction. Follow along: read the [issues](https://github.com/ylove/git-bouncer/issues) in order, then the [pull requests](https://github.com/ylove/git-bouncer/pulls?q=is%3Apr). Every design decision, review comment and fix is there on purpose, so you can see how a security tool gets built. The first release will be `v1.0.0`.

Malicious repositories are now a routine way to attack developers: poisoned "starter kits", fake take-home tests from fake recruiters, and look-alike repos under names like `micr0s0ft`. Open one in VS Code, or run `npm install` on your everyday laptop, and it can take your SSH keys and GitHub tokens, then push malware into **your** repos.

git-bouncer is a door check for code you didn't write:

```sh
npm install -g git-bouncer        # once

bouncer clone <url>               # instead of: git clone <url>
git bouncer <url>                 # same thing, as a git subcommand
```

1. **ID check.** Before anything downloads, it checks who published the repo: look-alike names, brand-new accounts, impersonated projects, known-bad repos.
2. **Pat-down.** It clones the repo into a **throwaway, locked-down container** with none of your credentials. There it checks for known-malicious dependencies, checksum mismatches, install scripts, auto-run editor tasks, hidden code and invisible Unicode. **None of the repo's code is run.**
3. **Verdict.** If the repo is clean, it asks whether to bring it onto your machine and install its dependencies, at the exact commit it checked. If not, it tells you what it found and deletes the sandbox.

No Docker? It can use **Podman** (free and open source, no sign-up), a throwaway **GitHub Codespace**, or your own cloud account.

- How it works and why: [docs/DESIGN.md](docs/DESIGN.md)
- What it protects against, and what it can't: [THREAT_MODEL.md](THREAT_MODEL.md)
- Found a security problem in git-bouncer itself? [SECURITY.md](SECURITY.md)

Licensed under [Apache-2.0](LICENSE).
