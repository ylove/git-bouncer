# What the pat-down checks

Every finding has a stable ID, a severity and a plain-language explanation in the report. Severity decides the verdict:

| Severity | Verdict | Meaning |
|---|---|---|
| critical, high | **turned away** (FAIL) | Strong signal the repo may attack you when you open, build or install it |
| medium | **warning** (WARN) | A person should look before trusting it |
| low, info | **let in** (PASS) | Context. Never blocks on its own |

All of these run inside the sandbox. None of them executes code from the repository. The repository can't configure the scanner: no ignore files or settings are read from it. It can still try to *evade* the checks (see the limitations in [THREAT_MODEL.md](../THREAT_MODEL.md)), which is why the most important ones are written to be hard to dodge and are covered by regression tests for every bypass found in review.

Paths are compared the way macOS (APFS) and Windows (NTFS) compare them: case-insensitively, ignoring Unicode normalization and invisible code points, and folding look-alike letters such as U+017F (a long s) into the letter they uppercase to. `.VSCode/tasks.json` and `.vſcode/tasks.json` are both checked as `.vscode/tasks.json`, `Package.json` as `package.json`, and when several spellings exist every one is checked and the worst result counts.

The **ID check** (look-alike owners, account age and more) runs on your machine before anything is downloaded. Its findings are documented with that feature in [#2](https://github.com/ylove/git-bouncer/issues/2).

## Git (the clone itself)

| ID | Severity | What it means |
|---|---|---|
| `GIT-FSCK` | critical | git's object verification rejected the download. Malformed objects have been used to exploit git clients. |
| `GIT-UNSAFE-PATH` | high | git refused to check out a path (for example a `.git` look-alike) because of its NTFS/HFS protections. |
| `GIT-DOTGIT-PATH` | high | A path component impersonates `.git` (case or trailing-dot variants, `GIT~1`). |
| `GIT-SYMLINK-ESCAPE` | high | A symlink points outside the repo or at an absolute path (for example `~/.ssh`). Links are followed one path component at a time, the way the OS does (`node_modules -> s/..` where `s -> .` climbs out), and also the way tools that tidy up `..` first do; an escape either way counts. |
| `GIT-SYMLINK-SENSITIVE` | high | A symlink sits where a tool reads automatically: in or as `node_modules`, `.vscode`, `.devcontainer`, `.claude`, `.cursor`, `.husky` or any `.git*` path, or named `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `.npmrc`, `.yarnrc*`, `.pnpmfile*`, `bunfig.toml`, `binding.gyp`, `tasks.json`, `settings.json`, `AGENTS.md`, `CLAUDE.md` and similar. Where the link lands depends on how your OS and tools resolve it, which the scanner can only approximate. One exception: an agent instruction file linked to another one (`CLAUDE.md -> AGENTS.md`) that resolves unambiguously inside the repo, because the copy put in its place is scanned with the same rules. |
| `GIT-CASE-COLLISION` | high | Two paths are the same file on macOS/Windows: they differ only by letter case, Unicode normalization, or a look-alike letter those filesystems fold together (U+017F, a long s, is "s"). A file whose name folds onto another entry's folder counts too. They overwrite each other at checkout, so the file you get may not be the one that was scanned; this was the trigger for CVE-2024-32002. |
| `GIT-SUBMODULE-PATH` | high | A submodule path contains `..`, `.git` or a leading `-`, which are known exploit patterns. |
| `GIT-SUBMODULE-URL` | medium | A submodule uses a non-https URL. |
| `GIT-SYMLINK-UNRESOLVED` | medium | A symlink couldn't be replaced with a faithful copy of its target for scanning: the target is missing or unreadable, it's a loop or a folder that contains the link itself, it's a folder with more than the 5,000 files the scanner copies, or it means one thing on macOS/Linux and another to tools that resolve `..` first (Windows). A coverage gap: the result is incomplete. |
| `GIT-LISTING-INCOMPLETE` | medium | `git ls-files` failed or its output was cut off, so the git-level checks above are incomplete. A coverage gap: the result is incomplete. |
| `GIT-SUBMODULES` | low | Submodules exist and were not fetched or scanned. |
| `GIT-SYMLINKS` | info | Symlinks exist (checked out as plain files in the sandbox). |
| `GIT-SYMLINKS-RESOLVED` | info | In-repo symlinks were replaced with copies of their targets for scanning, because tools on your machine would follow them (`package.json -> tools/manifest.json`). Links are resolved the way the OS resolves them, through other links, and under any spelling macOS or Windows would match; links inside a linked folder are resolved before the folder is copied. |

## Runs when you open the folder or start an AI agent

| ID | Severity | What it means |
|---|---|---|
| `AUTORUN-VSCODE-FOLDEROPEN` | high | `.vscode/tasks.json` runs a command as soon as the folder is opened in VS Code or Cursor. |
| `AUTORUN-DEVCONTAINER-HOST` | high | The dev container's `initializeCommand` runs **on your host**. |
| `AUTORUN-DEVCONTAINER-MOUNTS` | high | The dev container mounts `~/.ssh`, cloud credentials or the Docker socket, or runs privileged. |
| `AUTORUN-GIT-HOOK` | high | A husky git hook downloads or executes code. |
| `AUTORUN-AGENT-HOOKS` | medium / high | `.claude/settings.json` (or `settings.local.json`) defines hooks, a status line or helper commands, or `.cursor/hooks.json` defines Cursor hooks: shell commands an AI agent runs automatically. High if they download and execute. |
| `AUTORUN-AGENT-ENV` | medium / high | `.claude/settings.json` (or `settings.local.json`) sets `env` variables that make every command the agent starts load extra code or pick a different program (`NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_*`, `PYTHONSTARTUP`, `BASH_ENV`, `PATH`, ...) or send traffic elsewhere (proxies, `ANTHROPIC_BASE_URL`). High when a value points at a file or folder in the repo (`--require ./x.js`, `PATH=.:$PATH`). |
| `AUTORUN-AGENT-MCP` | medium / high | MCP server configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`) that launch local programs. |
| `AUTORUN-AGENT-INSTRUCTIONS` | medium | `AGENTS.md`, `CLAUDE.md` or `GEMINI.md` (in any folder, up to five deep) or `.cursorrules`, `.github/copilot-instructions.md`, `.windsurfrules` tells the agent to download and run something. |
| `AUTORUN-VSCODE-SETTINGS` | medium | Workspace settings choose which programs the editor runs (`typescript.tsdk`, interpreter paths, terminal profiles). |
| `AUTORUN-DEVCONTAINER` | low / medium | Dev container lifecycle commands (run inside the container or Codespace). |
| `AUTORUN-CONFIG-UNPARSABLE` | medium | An editor or agent config couldn't be parsed strictly. Editors are lenient, so it was checked with text matching too. |
| `CONFIG-EXEC` | medium / high | A build or dev config (`next.config.js`, `vite.config.ts`, `eslint.config.js`, …) spawns processes, uses the network, or reads home-directory secrets. High when it does two of those. |

## Hidden code and hidden text

| ID | Severity | What it means |
|---|---|---|
| `HIDDEN-WHITESPACE-PAYLOAD` | high | Code pushed 150+ columns to the right, off-screen (PolinRider's build-config trick). Every kind of blank counts toward the gap: Unicode spaces, blank-looking glyphs (Braille blank U+2800, the Hangul fillers), zero-width characters, and comments of any length with nothing visible in them. |
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

Known-malware and known-vulnerability lookups use [osv-scanner](https://github.com/google/osv-scanner) with git-bouncer's own config file and `--no-resolve`. Lockfiles (`package-lock.json`, `yarn.lock`, `Cargo.lock`, `poetry.lock`, ...) list the full tree, so nothing is lost. Manifest-only ecosystems (`pom.xml`, `requirements.txt` without pins, `build.gradle`) are matched on the versions they **declare**: transitive dependencies are not resolved, because resolving them means downloading metadata from wherever the manifest says (a `pom.xml` `<repositories>` URL or parent POM), which would let the repo steer the sandbox at a server of its choosing.

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
| `SCRIPT-ROOT-LIFECYCLE` | medium / low | The repo has an install-time script, including `dependencies` and the implicit `node-gyp rebuild` from a `binding.gyp`. Every `package.json` outside `node_modules` up to five folders deep is checked (the root, workspaces, `file:` dependencies, and separate projects like `frontend/`), the first 100 of them. `npm run x` references are expanded one level. Low for well-known ones like `husky` or `svelte-kit sync`. |
| `DEP-INSTALL-SCRIPT` | medium | A dependency not on the well-known list (or not from the npm registry) has an install script. Taken from the lockfile's `hasInstallScript`, so packages the Linux sandbox didn't install (macOS- or Windows-only) are listed too, and so are the ones in nested projects' lockfiles (`frontend/package-lock.json`). |
| `DEP-NESTED-PROJECT` | medium | An npm project in a sub-folder (say `frontend/`, installed with `cd frontend && npm install`) that isn't a workspace or `file:` dependency of the root, so the sandbox didn't install it and nothing verified its downloads' checksums or signatures. Its scripts and lockfile were still checked. Also reported when there are more than 100 `package.json` files, so only the first 100 were checked. A coverage gap: the result is incomplete. |
| `SCRIPT-RUN-DANGEROUS` | medium | `npm run dev/start/test/build` downloads or decodes something and runs it. |
| `DEP-TYPOSQUAT` | medium | A direct dependency's name (or an `npm:` alias's real name) is one edit away from a popular package (`expresss`, `crossenv`). Siblings in the same scope are not compared. |
| `LOCK-RESOLVED-NONREGISTRY` | medium | Lockfile entries come from servers other than the npm registry. |
| `LOCK-MISSING-INTEGRITY` | medium | Lockfile entries have no integrity hash. |
| `LOCK-OUT-OF-SYNC` | medium | `package.json` and the lockfile disagree, so the exact tree couldn't be verified. |
| `LOCK-UNPARSABLE`, `LOCK-RESOLVED-ODD` | medium | The lockfile is broken or points somewhere unusual. |
| `YARN-PATH` | medium / high | Yarn would run a JavaScript file from the repo on every command. Medium for Berry's `yarnPath`, including the standard `.yarn/releases/yarn-x.y.z.cjs`: that file is repo-controlled code, not checked against a real Yarn release. High for classic `.yarnrc` `yarn-path`. |
| `NPMRC-SCOPED-REGISTRY` | medium | Some scopes come from a third-party registry (common for paid packages like Font Awesome Pro). |
| `BUNFIG-PRELOAD` | medium | `bunfig.toml` preloads scripts before your code runs. |
| `PY-INDEX-OVERRIDE` | medium | A requirements file adds or replaces the Python package index (dependency confusion). |
| `NPMRC-TOKEN` | medium | An npm auth token is committed (poor hygiene, possibly stolen). |
| `DEP-INSTALL-FAILED`, `DEP-INSTALL-SKIPPED`, `DEP-OSV-UNAVAILABLE`, `DEP-OSV-PARTIAL`, `DEP-SIGNATURES-UNCHECKED` | medium / low | A dependency check couldn't complete, so the result is incomplete. The install is deliberately skipped when the lockfile points at servers the sandbox shouldn't contact, or when `package.json` or the lockfile is spelled unusually (`Package.json`): npm on macOS/Windows reads that spelling, the sandbox's npm on Linux doesn't, so its install would verify a different tree. |
| `DEP-PLATFORM-RESTRICTED` | low | The project refuses to install on Linux; the sandbox installed it anyway to check the dependencies. |
| `DEP-VULN` | low | Known vulnerabilities (CVEs) in dependencies, with the critical and high counts in the title. Low, because the verdict answers "will this repo attack me?" and a CVE answers "is this app vulnerable?": it makes the app vulnerable, not your machine at install time. |
| `LOCK-RESOLVED-GIT`, `LOCK-WEAK-INTEGRITY` | low | Git dependencies (no registry signatures) or SHA-1-only integrity. |
| `DEP-INSTALL-SCRIPT-KNOWN` | info | Well-known packages with install scripts (esbuild, sharp, …). |

## Coverage

| ID | Severity | What it means |
|---|---|---|
| `SCAN-TRUNCATED` | medium | The repo was too big to scan completely (60,000 files or 400 MiB). |
| `SCAN-LARGE-CODE-FILE` | medium | A code or build-config file is over 16 MiB (or `package.json`, a lockfile, `.npmrc` and similar are over the size the dependency checks read), so only part of it was checked. Padding a file past a scanner's limit is a known way to hide a payload. A coverage gap: the result is incomplete. |
| `SCAN-LARGE-FILES` | info | Data files over 2 MiB had only their first 2 MiB checked. Code and config files are read up to 16 MiB. |
| `SCAN-FINDINGS-TRUNCATED` | info | More findings existed than the report lists (25 per rule, 400 total). The verdict already counts the listed ones. |

## Adding a check

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-detection). Every check needs a public write-up of the technique, a test that generates a minimal fixture, and a test proving a legitimate look-alike doesn't trigger it.
