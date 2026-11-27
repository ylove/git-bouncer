# Changelog

## 1.0.0

The first release. git-bouncer is a door check for repositories you didn't write:

- **ID check** (on your machine, before anything downloads): look-alike owners and repos (`micr0s0ft`), impersonated famous projects, accounts that changed hands, brand-new accounts and repos, and repos named in public malware reporting. If GitHub can't be asked, the result is INCOMPLETE, never a pass.
- **Pat-down** in a throwaway, locked-down Docker or Podman container (non-root, no capabilities, read-only root, noexec work area, no mounts, no credentials, no host environment):
  - hardened one-commit clone (https only, no hooks, no symlinks, object verification, no submodules)
  - auto-run on open: VS Code `folderOpen` tasks, dev container `initializeCommand` and credential mounts, AI-agent hooks and MCP servers
  - install-time execution: every script npm would run (`hasInstallScript`, `binding.gyp`, workspaces, the `dependencies` hook), plus `.npmrc`/`.yarnrc`/`.pnpmfile.cjs` tricks that work even with `--ignore-scripts`
  - poisoned dependencies: known-malicious packages (OSV), lockfile checksum mismatches (`npm ci --ignore-scripts`), invalid registry signatures, non-registry sources, typosquats
  - hidden code: off-screen payloads, decode-then-execute, fake fonts, blockchain C2, invisible Unicode, Trojan Source
- **Verdict and handoff:** let in / warning / turned away / incomplete. A clean repo is cloned to your machine at the exact scanned commit (verified by commit and tree hash) with isolated git, and npm projects the sandbox installed are installed lockfile-exact with your consent for any install script.
- **No Docker?** Podman, an install offer (Podman recommended), or GCP Cloud Build / AWS CodeBuild in your own account (`--runtime gcp|aws`, `--dry-run`; not live-tested by the maintainer).
- **Opt-in shell integration:** `git clone <url> --bouncer`.
- Optional **Snyk** on copies of the manifests, with your token kept on the host.

Built in public: every change went through a pull request with an adversarial review, and every finding from those reviews is a regression test.

Known limitations are in [THREAT_MODEL.md](THREAT_MODEL.md#known-limitations-read-these).
