# git-bouncer design

This is the plan written before the code. The [issues](https://github.com/ylove/git-bouncer/issues) break it into pieces, and each piece lands as its own pull request. The [threat model](../THREAT_MODEL.md) explains *why* each defense exists; this doc explains *how* the tool is put together.

## The one-step experience

```sh
npm install -g git-bouncer
bouncer clone https://github.com/someone/take-home-test
```

That's the whole interface for most people. Everything else is optional:

| Command | What it does |
|---|---|
| `bouncer clone <url> [dir]` | ID check → sandbox pat-down → asks before cloning to your machine and installing dependencies |
| `git bouncer <url> [dir]` | Same, as a git subcommand (the package ships a `git-bouncer` binary, and git finds `git-*` programs on your PATH automatically) |
| `bouncer scan <url>` | Check only, never touch your disk. Exit code 0 = let in, 1 = turned away, 3 = warnings. Good for scripts. |
| `bouncer doctor` | Shows which sandbox runtimes it found and what it would use |
| `bouncer shell-init` | Prints an opt-in shell function so `git clone <url> --bouncer` works too |

Useful flags: `--ref <branch|tag|sha>`, `--runtime docker|podman|codespace|gcp|aws`, `--json`, `--keep` (keep the sandbox to inspect it), `--no-install`, `--snyk` / `--no-snyk`.

## Architecture

```
bouncer (host CLI, Node.js, zero dependencies)
 ├─ url.js            parse + strictly validate the repository URL and ref
 ├─ id-check/         GitHub API metadata, look-alike detection, known-bad repos   ← runs on the host
 ├─ runtimes/         docker | podman | codespace | gcp | aws  (pick the first that works)
 │    └─ each one starts a sandbox, runs the scanner inside it, returns its JSON report
 ├─ report.js         validates the sandbox report (schema, sizes) — it is untrusted data
 ├─ verdict.js        critical/high → turned away, medium → warning, low/info → let in
 ├─ ui/               plain-language output; strips control characters from untrusted text
 └─ handoff.js        clone to your machine at the scanned SHA, verify it, install from the lockfile

sandbox/ (copied into the sandbox image; runs as an unprivileged user)
 ├─ Dockerfile        node base pinned by digest + git + osv-scanner pinned by SHA256
 └─ scanner/          hardened clone + every check; prints one JSON report
```

Why the split: the **ID check** needs nothing from the repo, so it runs on your machine where it can use your `gh` login without exposing the token. Everything that touches the repo's files happens in the **sandbox**. The host never trusts the sandbox's report beyond what it can validate.

## Sandbox runtimes

1. **Docker or Podman** (local). The image (Debian trixie `node:24-trixie-slim` pinned by digest, git 2.47, osv-scanner pinned by SHA256, no curl or wget) is built on first use from the Dockerfile inside the npm package, and tagged with a hash of the sandbox folder, so changing the scanner rebuilds it. Containers run with:
   `--cap-drop=ALL --security-opt=no-new-privileges --read-only --user 10001:10001`
   `--tmpfs /work:noexec,nosuid,nodev,size=…` `--tmpfs /tmp:noexec,nosuid,nodev`
   `--pids-limit --memory --cpus`, and no mounts, no Docker socket, no inherited environment.
2. **GitHub Codespaces (planned, not in 1.0.0; see PR #23).** For when there's no local runtime but `gh` is signed in with the `codespace` scope. The Codespace is created from **this** repo's pinned `.devcontainer/sandbox` config, never from the suspect repo. The scanner is copied in with `gh codespace cp`, tokens are unset, and the Codespace is deleted afterwards.
3. **Cloud** (opt-in): GCP Cloud Build or AWS CodeBuild run the same scanner in an ephemeral build VM. **Not live-tested by the maintainer** (it costs money). `--dry-run` prints exactly what would run. See `docs/cloud.md`.
4. **Nothing available:** offers to install **Podman** (open source, no account) or Docker Desktop, with your consent.

## What the scanner checks

See [THREAT_MODEL.md](../THREAT_MODEL.md) T1–T6 for the full list and severities. In order:

1. Hardened fetch of one commit; record the commit SHA and tree hash.
2. Git-level checks: escaping symlinks, `.git` look-alike paths, case collisions, submodules.
3. Content checks on every file: hidden code, decode-and-execute, invisible Unicode, fake file types, executables, blockchain C2, the IOC snapshot.
4. Auto-run checks: VS Code tasks/settings, dev containers, AI-agent hooks and MCP configs, git hooks, build config files.
5. Dependency checks: `.npmrc` overrides, lockfile `resolved`/`integrity`, `npm ci --ignore-scripts` (checksum verification), `npm audit signatures`, every install script in the tree, typosquats, and osv-scanner for known-malicious packages and CVEs across ecosystems.

The repository **cannot configure the scanner**. No ignore files or settings are read from it, because the attacker controls those files.

## The report

One JSON object per run, printed between two lines containing a random nonce chosen by the host:

```json
{ "schema": 1, "target": { "url": "...", "commit": "<sha>", "tree": "<sha>" },
  "packageManager": { "kind": "npm", "lockfile": "package-lock.json", "generatedLockfile": false },
  "findings": [ { "id": "AUTORUN-VSCODE-FOLDEROPEN", "severity": "high", "title": "...", "detail": "...",
                  "file": ".vscode/tasks.json", "line": null, "evidence": "..." } ],
  "stats": { ... }, "tools": { ... } }
```

Finding IDs are stable and documented in `docs/checks.md`.

## Dependency policy

Runtime dependencies: **none**. Dev dependencies: none planned (Node's built-in `node:test` runner). A security tool you install with npm shouldn't ask you to trust a dependency tree.

## Test strategy

- **Unit tests** (`node --test`) for URL validation (including argument-injection and credential-in-URL cases), the terminal sanitizer, look-alike detection, report validation, the verdict policy, every scanner check, and the command lines each runtime would run. They run on Linux, macOS and Windows with Node 22 and 24.
- **Fixtures are generated by the tests at runtime**, not committed, so this repository scans itself clean and nobody downloads "malicious-looking" files by cloning it.
- **Integration tests** build the sandbox image and scan generated fixture trees in Docker (and Podman on Linux CI).
- **Smoke test** against a tiny, stable public repository over the real network.
