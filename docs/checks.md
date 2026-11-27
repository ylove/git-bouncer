# What the pat-down checks

Every finding has a stable ID, a severity and a plain-language explanation in the report. Severity decides the verdict:

| Severity | Verdict | Meaning |
|---|---|---|
| critical, high | **turned away** (FAIL) | Strong signal the repo may attack you when you open, build or install it |
| medium | **warning** (WARN) | A person should look before trusting it |
| low, info | **let in** (PASS) | Context. Never blocks on its own |

All of these run inside the sandbox. None of them executes code from the repository. The repository can't configure the scanner: no ignore files or settings are read from it. It can still try to *evade* the checks (see the limitations in [THREAT_MODEL.md](../THREAT_MODEL.md)), which is why the most important ones are written to be hard to dodge and are covered by regression tests for every bypass found in review.

The **ID check** (look-alike owners, account age and more) runs on your machine before anything is downloaded. Its findings are documented with that feature in [#2](https://github.com/ylove/git-bouncer/issues/2).

## Git (the clone itself)

| ID | Severity | What it means |
|---|---|---|
| `GIT-FSCK` | critical | git's object verification rejected the download. Malformed objects have been used to exploit git clients. |
| `GIT-UNSAFE-PATH` | high | git refused to check out a path (for example a `.git` look-alike) because of its NTFS/HFS protections. |
| `GIT-DOTGIT-PATH` | high | A path component impersonates `.git` (case or trailing-dot variants, `GIT~1`). |
| `GIT-SYMLINK-ESCAPE` | high | A symlink points outside the repo or at an absolute path (for example `~/.ssh`). |
| `GIT-SUBMODULE-PATH` | high | A submodule path contains `..`, `.git` or a leading `-`, which are known exploit patterns. |
| `GIT-CASE-COLLISION` | medium | Two paths differ only by case. On macOS/Windows they overwrite each other; this was the trigger for CVE-2024-32002. |
| `GIT-SUBMODULE-URL` | medium | A submodule uses a non-https URL. |
| `GIT-SUBMODULES` | low | Submodules exist and were not fetched or scanned. |
| `GIT-SYMLINKS` | info | Symlinks exist (checked out as plain files in the sandbox). |
| `GIT-SYMLINKS-RESOLVED` | info | In-repo symlinks were replaced with copies of their targets for scanning, because tools on your machine would follow them (`package.json -> tools/manifest.json`). |

## Runs when you open the folder or start an AI agent

| ID | Severity | What it means |
|---|---|---|
| `AUTORUN-VSCODE-FOLDEROPEN` | high | `.vscode/tasks.json` runs a command as soon as the folder is opened in VS Code or Cursor. |
| `AUTORUN-DEVCONTAINER-HOST` | high | The dev container's `initializeCommand` runs **on your host**. |
| `AUTORUN-DEVCONTAINER-MOUNTS` | high | The dev container mounts `~/.ssh`, cloud credentials or the Docker socket, or runs privileged. |
| `AUTORUN-GIT-HOOK` | high | A husky git hook downloads or executes code. |
| `AUTORUN-AGENT-HOOKS` | medium / high | `.claude/settings.json` defines hooks: shell commands an AI agent runs automatically. High if they download and execute. |
| `AUTORUN-AGENT-MCP` | medium / high | MCP server configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`) that launch local programs. |
| `AUTORUN-AGENT-INSTRUCTIONS` | medium | `AGENTS.md`, `CLAUDE.md` or similar tells the agent to download and run something. |
| `AUTORUN-VSCODE-SETTINGS` | medium | Workspace settings choose which programs the editor runs (`typescript.tsdk`, interpreter paths, terminal profiles). |
| `AUTORUN-DEVCONTAINER` | low / medium | Dev container lifecycle commands (run inside the container or Codespace). |
| `AUTORUN-CONFIG-UNPARSABLE` | medium | An editor or agent config couldn't be parsed strictly. Editors are lenient, so it was checked with text matching too. |
| `CONFIG-EXEC` | medium / high | A build or dev config (`next.config.js`, `vite.config.ts`, `eslint.config.js`, …) spawns processes, uses the network, or reads home-directory secrets. High when it does two of those. |

## Hidden code and hidden text

| ID | Severity | What it means |
|---|---|---|
| `HIDDEN-WHITESPACE-PAYLOAD` | high | Code pushed 150+ columns to the right, off-screen (PolinRider's build-config trick). |
| `OBFUSCATION-DECODE-EXEC` | high | Decodes base64/hex/char codes and executes the result (`eval(atob(...))`, `exec(base64.b64decode(...))`). |
| `UNICODE-BIDI` | high (code) / low (prose) | Trojan Source direction controls (CVE-2021-42574). |
| `UNICODE-TAG-SMUGGLING` | high | Unicode tag characters: invisible text that programs and AI models can still read. |
| `UNICODE-VARIATION-SMUGGLING` | high (code) / medium | Invisible variation selectors that can encode hidden bytes (GlassWorm). |
| `UNICODE-INVISIBLE` | medium / high | Zero-width, format and other invisible characters in code, found by Unicode property. Emoji joiners and a leading BOM are ignored. |
| `OBFUSCATION-LONG-LINE` | low | A 5,000+ character line in a non-minified source file. |
| `C2-BLOCKCHAIN` | high / low | Reads Ethereum/Tron transaction data. High if the same file also executes code (a "dead-drop" C2 that can't be taken down). |
| `C2-NODE-REPL` | high | Spawns an interactive `node -i`, a live interpreter for remote commands. |
| `PY-IMPORT-TIME-LOADER` | high | `conftest.py`, `setup.py`, `__init__.py` or `sitecustomize.py` that downloads and executes. |
| `PY-PTH-EXEC` | medium | A `.pth` file with an import line (runs on every Python start once installed). |
| `PY-CODEC-DECLARATION` | high | A Python file declares a source encoding like UTF-7, which hides statements from anyone reading it as UTF-8. |
| `MSBUILD-RESPONSE-FILE` | medium | `Directory.Build.rsp` adds options (including loggers, which are DLLs) to every `dotnet build`. |
| `MSBUILD-EXEC` | medium / high | MSBuild `<Exec>`/`<UsingTask>` runs on `dotnet build`. High if it downloads an executable. |
| `IOC-MATCH` | critical | A wallet address, C2 IP, campaign marker, file name, or package/repo name from public reporting on an active campaign (dated snapshot, sources cited in `sandbox/scanner/checks/iocs.js`). |

## Files that aren't what they claim

| ID | Severity | What it means |
|---|---|---|
| `FILETYPE-FAKE-FONT` | high | A font file (`.woff2`, `.ttf`, `.llf`, …) that is actually text, as with PolinRider's fake Font Awesome files. |
| `FILETYPE-MISMATCH` | medium / high | An image, font, archive or wasm file whose bytes don't match its format. High if it's text. |
| `BIN-EXECUTABLE` | medium / high | A compiled program is committed. High if it hides under a non-program extension. |
| `REPO-COMMITTED-NODE-MODULES` | medium | `node_modules` is committed (anywhere in the tree), bypassing every lockfile and registry check. It is still scanned. |
| `LFS-CODE` | high | A code or config file is stored in Git LFS: its real contents weren't scanned and the commit hash doesn't vouch for them. |
| `LFS-POINTERS` | info | Other files (images, data) are stored in Git LFS and weren't downloaded. |

## Dependencies

| ID | Severity | What it means |
|---|---|---|
| `DEP-MALWARE` | critical | A dependency version is in the OSV malicious-packages database. |
| `DEP-INTEGRITY-MISMATCH` | critical | `npm ci` found a package whose sha512 doesn't match the lockfile (`EINTEGRITY`). |
| `DEP-SIGNATURE-INVALID` | critical | `npm audit signatures` found an invalid registry signature. |
| `NPMRC-OVERRIDE` | high | A project `.npmrc`/`.yarnrc.yml` redirects the registry or sets `git`, `node-gyp`, `script-shell`, `node-options`, a proxy and similar. It's moved aside in the sandbox, but would apply on your machine. |
| `NPMRC-ENV-EXFIL` | high | `.npmrc` would send one of your environment variables (like `${GITHUB_TOKEN}`) to a server other than the npm registry. |
| `PNPMFILE` | medium / high | `.pnpmfile.cjs` runs on every pnpm install, even with `--ignore-scripts`. |
| `SCRIPT-ROOT-DANGEROUS` | high | The repo's own `preinstall`/`install`/`postinstall`/`prepare` downloads or decodes something and runs it. |
| `DEP-INSTALL-SCRIPT-DANGEROUS` | high | A dependency's install script downloads or decodes something and runs it. |
| `LOCK-RESOLVED-INSECURE` | high | A lockfile entry downloads over plain http. |
| `DEP-SPEC-URL` | high (http) / low | A dependency is installed from a URL instead of the registry. |
| `SCRIPT-ROOT-LIFECYCLE` | medium / low | The repo (or a workspace in it) has an install-time script, including `dependencies` and the implicit `node-gyp rebuild` from a `binding.gyp`. `npm run x` references are expanded one level. Low for well-known ones like `husky` or `svelte-kit sync`. |
| `DEP-INSTALL-SCRIPT` | medium | A dependency not on the well-known list (or not from the npm registry) has an install script. Taken from the lockfile's `hasInstallScript`, so packages the Linux sandbox didn't install (macOS- or Windows-only) are listed too. |
| `SCRIPT-RUN-DANGEROUS` | medium | `npm run dev/start/test/build` downloads or decodes something and runs it. |
| `DEP-TYPOSQUAT` | medium | A direct dependency's name (or an `npm:` alias's real name) is one edit away from a popular package (`expresss`, `crossenv`). Siblings in the same scope are not compared. |
| `LOCK-RESOLVED-NONREGISTRY` | medium | Lockfile entries come from servers other than the npm registry. |
| `LOCK-MISSING-INTEGRITY` | medium | Lockfile entries have no integrity hash. |
| `LOCK-OUT-OF-SYNC` | medium | `package.json` and the lockfile disagree, so the exact tree couldn't be verified. |
| `LOCK-UNPARSABLE`, `LOCK-RESOLVED-ODD` | medium | The lockfile is broken or points somewhere unusual. |
| `YARN-PATH` | low / medium / high | Yarn would run a JavaScript file from the repo: low for Berry's standard `.yarn/releases/yarn-x.y.z.cjs`, medium for anything else, high for classic `.yarnrc` `yarn-path`. |
| `NPMRC-SCOPED-REGISTRY` | medium | Some scopes come from a third-party registry (common for paid packages like Font Awesome Pro). |
| `BUNFIG-PRELOAD` | medium | `bunfig.toml` preloads scripts before your code runs. |
| `PY-INDEX-OVERRIDE` | medium | A requirements file adds or replaces the Python package index (dependency confusion). |
| `DEP-VULN` | medium | Known vulnerabilities (CVEs) in dependencies. A warning, not a fail: they make the app vulnerable, not your machine at install time. |
| `NPMRC-TOKEN` | medium | An npm auth token is committed (poor hygiene, possibly stolen). |
| `DEP-INSTALL-FAILED`, `DEP-INSTALL-SKIPPED`, `DEP-OSV-UNAVAILABLE`, `DEP-OSV-PARTIAL`, `DEP-SIGNATURES-UNCHECKED` | medium / low | A dependency check couldn't complete (or was deliberately skipped, because the lockfile points at servers the sandbox shouldn't contact), so the result is incomplete. |
| `DEP-PLATFORM-RESTRICTED` | low | The project refuses to install on Linux; the sandbox installed it anyway to check the dependencies. |
| `LOCK-RESOLVED-GIT`, `LOCK-WEAK-INTEGRITY` | low | Git dependencies (no registry signatures) or SHA-1-only integrity. |
| `DEP-INSTALL-SCRIPT-KNOWN` | info | Well-known packages with install scripts (esbuild, sharp, …). |

## Coverage

| ID | Severity | What it means |
|---|---|---|
| `SCAN-TRUNCATED` | medium | The repo was too big to scan completely (60,000 files or 400 MiB). |
| `SCAN-LARGE-FILES` | info | Files over 2 MiB had only their first 2 MiB checked. |
| `SCAN-FINDINGS-TRUNCATED` | info | More findings existed than the report lists (25 per rule, 400 total). The verdict already counts the listed ones. |

## Adding a check

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-detection). Every check needs a public write-up of the technique, a test that generates a minimal fixture, and a test proving a legitimate look-alike doesn't trigger it.
