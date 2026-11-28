# git-bouncer threat model

git-bouncer is a door check for code you didn't write. You run `bouncer clone <url>` instead of `git clone <url>` the first time you touch an unfamiliar repository: a take-home test from a recruiter, a starter kit from a tutorial, a repo someone sent you. It inspects the repository in a throwaway sandbox before any of it reaches your machine.

This document says what it protects, what it assumes, what it does about each threat, and what it **cannot** do. If you find a gap, please report it privately (see [SECURITY.md](SECURITY.md)).

## What we're protecting

| Asset | Why an attacker wants it |
|---|---|
| Credentials on your machine: `~/.ssh`, git credential helpers, `gh` tokens, `~/.npmrc`, cloud CLIs (`~/.aws`, `gcloud`), browser cookies and saved passwords, crypto wallets | Push malware into *your* repos (PolinRider did exactly this), take over cloud accounts, steal money |
| Your other repositories and their CI/CD | Supply-chain spread: one compromised developer infects every project they can push to |
| Your machine itself | Persistence, remote access, a foothold into your employer's network |

## Who we're defending against

- **A malicious repository author.** They control every file in the repo, the repo's metadata (name, description, stars can be bought), its dependencies' names and versions, and any package registry entries they publish. They know this tool exists and can read its source.
- **A compromised legitimate repository.** A real project whose maintainer was phished, so the history and reputation look fine but recent commits don't.
- **Look-alike identities.** `micr0s0ft/vscode`, `expresss`, `cross-env` vs `crossenv`.

Out of scope: an attacker who already controls your machine, your DNS or your network path to GitHub/npm (TLS is trusted), the container runtime, GitHub/npm/OSV themselves, or the npm package you installed git-bouncer from (see "Trusting git-bouncer itself" below).

## Trust boundaries

```
  your machine (trusted)                       throwaway sandbox (untrusted)
 ┌────────────────────────────────┐           ┌─────────────────────────────────────┐
 │ bouncer CLI                    │  argv     │ scanner (git-bouncer's own code)    │
 │  · validates the URL           │ ────────► │  · hardened git fetch of ONE commit │
 │  · ID check (GitHub API)       │           │  · static checks, no repo code runs │
 │  · reads the report            │ ◄──────── │  · npm ci --ignore-scripts, OSV,    │
 │  · asks you before anything    │  JSON     │    npm audit signatures             │
 │    touches your disk           │ (size-    │  · no credentials, no host mounts   │
 │  · clones at the scanned SHA   │  capped,  │  · non-root, no capabilities,       │
 │  · Snyk (optional) on copied   │  schema-  │    read-only root, noexec tmpfs     │
 │    manifests only              │  checked) └─────────────────────────────────────┘
 └────────────────────────────────┘
```

Rule of the boundary: **secrets never cross into the sandbox, and nothing from the sandbox is trusted on the way out.** The report is treated as attacker-influenced data.

## Threats and mitigations

### T1. The repo runs code during install
npm/yarn/pnpm lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) run automatically. So do Python `setup.py` builds, `.pth` files, MSBuild targets on `dotnet build`, and husky hooks once installed.
- In the sandbox, dependencies are installed with `--ignore-scripts`, so **no repo or dependency code is executed**.
- The install scripts the scan can see are listed: the repo's own (including workspaces, the `dependencies` hook and `binding.gyp` builds) and every dependency the lockfile marks `hasInstallScript`, read from that package's own `package.json`. Download-and-execute patterns are FAIL. Unknown install scripts are WARN. A short, documented allowlist of well-known native packages (esbuild, sharp, …) is informational.
- **That list can be incomplete** (old v1 lockfiles, `file:` and git dependencies, projects in subfolders), so "no scripts found" is never treated as "no scripts". **git-bouncer never runs install scripts on your machine:** the handoff always installs with `npm ci --ignore-scripts`. Running them is a separate step you take yourself (`npm rebuild`) after reading the list.

### T2. The repo runs code when you merely open it
- `.vscode/tasks.json` with `"runOn": "folderOpen"` → FAIL. Workspace settings that select executables (`typescript.tsdk`, interpreter paths, terminal profiles) → WARN.
- Dev containers: `initializeCommand` runs **on your host** → FAIL. Mounting `~/.ssh`, cloud credentials or the Docker socket → FAIL. In-container lifecycle commands → listed.
- AI coding agents: committed `.claude/settings.json` hooks, MCP server configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) that launch local commands → WARN (FAIL with download-and-execute), plus download-and-run instructions in `AGENTS.md`/`CLAUDE.md`.
- Build/dev config files (`next.config.js`, `vite.config.ts`, `tailwind.config.js`, `eslint` configs, …) that spawn processes, open network connections or read home-directory secrets → WARN, or FAIL when combined.

### T3. Hidden code
- Code pushed hundreds of columns right (PolinRider's trick) → FAIL.
- Decode-then-execute (`eval(atob(…))`, `exec(base64.b64decode(…))`) → FAIL.
- Trojan Source bidi controls, Unicode tag characters and variation-selector smuggling → FAIL in code; invisible characters → WARN/FAIL by density.
- Files that lie about their type (a `.woff2` "font" that is JavaScript) → FAIL; executables disguised under other extensions → FAIL; committed executables → WARN.
- Blockchain dead-drop C2 (reading Ethereum/Tron transaction data and executing it) → FAIL.
- Indicators of compromise from public reporting (wallets, C2 IPs, package and repo names) → FAIL. This is a **dated snapshot**; see limitations.

### T4. Poisoned or tampered dependencies
- Known-malicious packages (OSV `MAL-` advisories via osv-scanner, which covers npm, PyPI, NuGet, Go, crates and more) → FAIL.
- **Checksum mismatch:** `npm ci` verifies every tarball against the lockfile's sha512 `integrity`; a mismatch (`EINTEGRITY`) → FAIL. Invalid registry signatures (`npm audit signatures`) → FAIL.
- Lockfile tampering: `resolved` URLs that point anywhere but the registry (http, git, random tarball hosts) → FAIL/WARN. Missing or weak (sha1) integrity → WARN.
- Project `.npmrc` that redirects the registry, or sets `git`, `script-shell`, `node-options` and similar (which can make npm run arbitrary programs even with `--ignore-scripts`) → FAIL. In the sandbox the project `.npmrc` is moved aside before npm runs.
- Typosquatted dependency names (`expresss`, `crossenv`) → WARN.
- Ordinary known vulnerabilities (CVEs) → LOW: shown with counts, but they don't block. git-bouncer answers "will this repo attack *me*?", not "is this app secure?". A tutorial repo with an old lodash isn't an attack on you.

### T5. The repo attacks git during clone
Malicious repos have exploited git itself (CVE-2024-32002, CVE-2025-48384).
- The clone happens **inside the sandbox**, never on your machine first.
- Only `https` is allowed (`protocol.allow=never` + `protocol.https.allow=always`, `GIT_ALLOW_PROTOCOL=https`): no `ext::`, `file://`, `ssh` command tricks.
- No hooks (`core.hooksPath=/dev/null`, empty template dir), no symlink creation (`core.symlinks=false`), object verification on (`transfer.fsckObjects=true`), submodules never fetched, NTFS/HFS path protections on, empty credential helper, no terminal prompts.
- Symlinks are resolved the way the operating system would (one path component at a time, and under case variants): any that escape the repo, or that sit at a sensitive path (`node_modules`, `.vscode`, `package.json`, …), are FAIL. `.git` look-alike paths, paths that collide once case and Unicode are folded the way macOS and Windows fold them (FAIL), and suspicious submodule URLs/paths are reported.
- Projects in subfolders (`frontend/package.json`) get their install scripts listed too; their dependencies aren't installed in the sandbox, which is reported as an incomplete check.

### T6. Look-alike and low-reputation sources (the ID check)
Runs on your machine **before** anything is downloaded, using the GitHub API (through `gh` if you're signed in, so the token stays host-side; otherwise anonymously):
- Owner or repo name within a small edit distance of a well-known org or project, including digit/letter swaps (`micr0s0ft`, `vercell`) → FAIL.
- A famous project name under an unrelated owner that isn't a GitHub fork of the original → WARN.
- Brand-new owner account or repo, archived repo, a stranger's fork of a famous project, accounts whose name changed hands → reported with context. New accounts are common for real take-home tests too, so this is WARN, not FAIL. (Commit signatures and release/ref comparison are not checked yet.)
- Repos named in public IOC reporting → FAIL.
- Non-GitHub hosts get a reduced ID check, and the report says so.

### T7. Time-of-check vs. time-of-use
An attacker could swap the repo between the scan and your install.
- The sandbox scans **one exact commit**. Your local clone checks out **that commit SHA** and verifies the commit and tree IDs. If the branch moved, git-bouncer stops and tells you.
- IDs describe what git *stores*; what lands on *your* disk can still differ (filters, hooks, LFS, symlinks, and filesystems that fold case or Unicode). So the host checkout runs with your system and global git config switched off, no hooks, no filters, no LFS, and **symlinks written as plain text files** (as in the sandbox). After checkout, `git status` must show no difference between the files on disk and the commit; if two paths collided on your filesystem, nothing is kept.
- Dependencies are installed automatically only for npm projects that the sandbox installed, with no symlinks and no package-manager config in the repo, from the lockfile (`npm ci --ignore-scripts`). If the repo had no lockfile, the one generated and verified in the sandbox is copied in. Everything else gets the exact command to run yourself, with scripts off.

### T8. The report lies, or attacks your terminal
- File names and contents are attacker-controlled. Every string shown to you is stripped of ANSI escape sequences and control characters, so a file name can't rewrite your terminal to hide a FAIL.
- The sandbox report is size-capped, schema-validated, and framed by a random per-run marker, so text that comes from the repo can't fake where the report starts or ends.
- If the sandbox itself were compromised it could under-report. That's why the ID check runs independently on the host, and why no repo code runs in the sandbox in the first place.

### T9. Secrets leaking into the sandbox
- No host directories are mounted. No environment variables are passed except a fixed minimal set. No Docker socket. The `gh`/`git` credentials on your machine are never used for the sandbox clone (public repos only).
- **Snyk** (optional): your `SNYK_TOKEN` must not enter the sandbox, so Snyk runs on your machine against **copies of the manifest and lockfiles only**, never the repo's code.
- **Codespaces fallback (planned, #8 / PR #23, not in 1.0.0):** the Codespace will be created from *git-bouncer's own* repo with a pinned devcontainer that has no lifecycle commands, never from the suspect repo (whose `devcontainer.json` could run code at creation). `GITHUB_TOKEN`, `GH_TOKEN` and the git credential helper are removed before the suspect repo is cloned. The Codespace is deleted afterwards.

### T10. Resource abuse in the sandbox
A repo can try to fill the disk or fork-bomb: pids, memory and CPU are capped, the work area is a size-limited tmpfs, and every step has a timeout.

## Trusting git-bouncer itself

A security tool you install from npm is itself a supply-chain risk, so:
- **Zero runtime dependencies.** The only code is ours plus Node's standard library.
- Published from GitHub Actions with **npm trusted publishing** (OIDC, no long-lived token) and **provenance**, so `npm audit signatures` can prove the package came from this repo's release workflow.
- The sandbox image is **built locally** from the Dockerfile shipped in the package. The base image is pinned by digest. osv-scanner is pinned by version and SHA256, taken from its release's published checksums.
- Every GitHub Action is pinned by commit SHA; CI runs CodeQL, OpenSSF Scorecard and zizmor; `main` is protected by a ruleset; Dependabot keeps pins current.

## Known limitations (read these)

- **Static analysis can be evaded.** A determined attacker can write malware none of these checks match, or hide it in a dependency's code that only runs at runtime. A clean result means "no known red flags", **not** "safe".
- **Brand-new malware isn't in OSV yet.** Detection lags publication, sometimes by hours, sometimes by days. The IOC snapshot is dated and goes stale.
- **Runtime behavior isn't observed.** git-bouncer doesn't run the project. Anything that only happens when you `npm run dev` is only caught if it's visible statically (T2/T3).
- **npm gets the deepest dependency checks.** yarn, pnpm, bun, Python, NuGet and others get lockfile parsing and OSV matching, but not install-time checksum verification inside the sandbox.
- **Private repositories aren't supported in v1**, because that would mean putting credentials in the sandbox.
- **Network egress from the sandbox is allowed** (git, the npm registry and OSV need it). No repo code runs there, but a container on your network is still a container on your network.
- **Hosts are an allowlist, but DNS isn't checked.** Only github.com, gitlab.com, bitbucket.org, codeberg.org and hosts you name with `--allow-host` are accepted, and internal or wildcard-DNS names are always refused. git-bouncer doesn't verify what an allowed name *resolves* to, so an attacker who controls your DNS is out of scope.
- **The cloud runtimes (GCP Cloud Build, AWS CodeBuild) are not live-tested by the maintainer**, because they cost money. They're documented as a starting point for your own configuration.
- **You're the last check.** A WARN asks you to look. If you don't understand why something was flagged, don't install it on your daily machine.
