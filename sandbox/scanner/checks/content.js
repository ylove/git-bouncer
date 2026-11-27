// Content checks: walk every file in the checked-out repo and look for the techniques
// real campaigns used to hide code in "normal-looking" repositories.
//
// Sources for these patterns (public reporting, Nov 2026):
//  - PolinRider (Apiiro, SafeDep, OpenSourceMalware via The Hacker News, 2026-11-26):
//    loaders in conftest.py / small utils packages, a loader hidden after hundreds of spaces
//    in a build config, fake font files (fa-solid-400.woff2, fa-solid-300.llf), payloads
//    read from Ethereum transaction input data, then run with Node.js.
//  - Fake .NET take-home tests (Socket via The Hacker News, 2026-11-26): MSBuild .targets
//    that run a DLL after every build; DLL sideloading.
//  - Trojan Source (CVE-2021-42574) and invisible-Unicode smuggling (GlassWorm, 2025).
//
// Nothing here executes repository code. Files are read as bytes and inspected.

import { readdir, lstat, open } from 'node:fs/promises'
import path from 'node:path'
import { excerpt } from '../findings.js'
import { iocIndex, matchIocStrings, IOC_SNAPSHOT_DATE } from './iocs.js'

const MAX_FILE_BYTES = 2 * 1024 * 1024
const MAX_TOTAL_BYTES = 400 * 1024 * 1024
const MAX_FILES = 60000

const CODE_EXT = new Set(['js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx', 'vue', 'svelte', 'astro',
  'py', 'pyw', 'rb', 'php', 'pl', 'sh', 'bash', 'zsh', 'ps1', 'psm1', 'bat', 'cmd', 'cs', 'vb', 'fs',
  'csproj', 'vbproj', 'fsproj', 'props', 'targets', 'java', 'kt', 'go', 'rs', 'lua', 'html', 'htm', 'json', 'toml', 'yml', 'yaml'])
const SCRIPT_EXT = new Set(['js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx', 'vue', 'svelte', 'py', 'pyw', 'rb', 'php', 'pl', 'sh', 'bash', 'zsh', 'ps1', 'psm1', 'bat', 'cmd'])
const SKIP_DIRS = new Set(['.git', 'node_modules'])

// Magic bytes for formats that malware has impersonated. Text content with these extensions is a red flag.
const MAGIC = {
  woff: [[0x77, 0x4f, 0x46, 0x46]],
  woff2: [[0x77, 0x4f, 0x46, 0x32]],
  ttf: [[0x00, 0x01, 0x00, 0x00], [0x74, 0x72, 0x75, 0x65]],
  otf: [[0x4f, 0x54, 0x54, 0x4f]],
  png: [[0x89, 0x50, 0x4e, 0x47]],
  jpg: [[0xff, 0xd8, 0xff]],
  jpeg: [[0xff, 0xd8, 0xff]],
  gif: [[0x47, 0x49, 0x46, 0x38]],
  ico: [[0x00, 0x00, 0x01, 0x00]],
  pdf: [[0x25, 0x50, 0x44, 0x46]],
  wasm: [[0x00, 0x61, 0x73, 0x6d]],
  zip: [[0x50, 0x4b, 0x03, 0x04], [0x50, 0x4b, 0x05, 0x06]],
}
const FONT_LIKE = /\.(woff2?|ttf|otf|eot|llf)$/i

const startsWith = (buf, sig) => sig.every((b, i) => buf[i] === b)

function executableKind(buf) {
  if (buf.length >= 4 && startsWith(buf, [0x7f, 0x45, 0x4c, 0x46])) return 'ELF (Linux executable)'
  if (buf.length >= 4) {
    const be = buf.readUInt32BE(0)
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(be)) return 'Mach-O (macOS executable)'
  }
  if (buf.length >= 0x40 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const peOffset = buf.readUInt32LE(0x3c)
    if (peOffset + 4 <= buf.length && buf.readUInt32BE(peOffset) === 0x50450000) return 'PE (Windows .exe/.dll)'
  }
  return null
}

const isLfsPointer = text => text.startsWith('version https://git-lfs.github.com/spec/v1')

// --- text patterns -----------------------------------------------------------------------

// Code pushed far to the right so it's off-screen in editors and GitHub's diff view.
const HIDDEN_AFTER_WHITESPACE = /[ \t]{150,}(?=\S)(.{0,120})/
const CODEISH = /[;(){}=]|\b(require|import|eval|exec|Function|fetch|http|atob|Buffer|subprocess|base64)\b/

// Decode-then-execute: the core move of most JS/Python droppers.
const JS_EXEC = /\b(eval|Function|execSync|exec|spawn|runInNewContext|runInThisContext)\s*\(/
const JS_DECODE = /\batob\s*\(|Buffer\.from\s*\([^)]{0,200}['"](base64|hex)['"]|String\.fromCharCode\s*\(\s*(\d+\s*,\s*){8,}|(\\x[0-9a-fA-F]{2}){24,}/
const PY_EXEC_DECODE = /\b(exec|eval)\s*\(\s*(compile\s*\()?\s*(base64\.\w*decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|codecs\.decode|__import__\s*\(\s*['"](base64|zlib|marshal)['"])/

// Ethereum/Tron transaction data used as a dead-drop for the next stage (PolinRider, EtherHiding).
// (Written with groups so this file's own source doesn't contain the literal method names it looks for.)
const CHAIN_RPC = /(eth_get(?:Transaction(?:ByHash|Receipt)|BlockByNumber)|eth_cal[l]|getTransaction\s*\(|api\.etherscan\.io|api\.trongrid\.io|bsc-datase[e]d|mainnet\.infura\.io|cloudflare-eth\.com|eth\.llamarpc\.com|rpc\.ankr\.com|ethereum\.publicnode\.com|g\.alchemy\.com)/
const CHAIN_EXEC = /\b(eval|new\s+Function|Function\s*\(|vm\.run\w*|child_[p]rocess|exec[S]ync|spawn\s*\(\s*['"`]node)/
const DETACHED_NODE_REPL = /spawn\s*\(\s*['"`](process\.execPath|node)['"`]?\s*,\s*\[\s*['"`]-i['"`]/

// Download-and-run in shell-ish strings (install scripts, tasks, hooks).
export const DOWNLOAD_EXEC = /(\b(curl|wget|iwr|Invoke-WebRequest|Invoke-Expression|iex|certutil|bitsadmin|mshta)\b|powershell(\.exe)?\s+-(e|enc|encodedcommand)\b|base64\s+(-d|--decode)|\|\s*(ba|z|da)?sh\b|\bnode\s+-e\b|\bpython3?\s+-c\b|\bbash\s+-c\b|\beval\b)/i

const BIDI = /[\u202A-\u202E\u2066-\u2069]/g
// Invisible characters by Unicode property, not a hand-made list (which always misses some):
// format characters, line/paragraph separators, private use and default-ignorable code points.
// Bidi controls, tags and variation selectors have their own, stricter rules.
const INVISIBLE = /[\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Default_Ignorable_Code_Point}]/gu
const HANDLED_ELSEWHERE = /[\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}\uFE00-\uFE0F]/u
const TAGS = /[\u{E0000}-\u{E007F}]/gu
const VARIATION_SUPPLEMENT = /[\u{E0100}-\u{E01EF}]/gu
const VS_RUN = /[\uFE00-\uFE0F]{4,}/g
const PICTO = /\p{Extended_Pictographic}/u

function codePointName(cp) {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`
}

/** Lines + 1-based line number of a character index. */
function lineOf(text, index) {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++
  return line
}

function unicodeChecks(rel, text, ext, findings) {
  const isCode = CODE_EXT.has(ext)
  for (const m of text.matchAll(BIDI)) {
    findings.add({
      id: 'UNICODE-BIDI', severity: isCode ? 'high' : 'low', file: rel, line: lineOf(text, m.index),
      evidence: codePointName(m[0].codePointAt(0)),
      title: 'Bidirectional control character (Trojan Source)',
      detail: 'Invisible Unicode direction controls can make code display differently from how it runs (CVE-2021-42574). There is almost never a legitimate reason for them in source code.',
    })
    break // one per file is enough to make the point
  }
  for (const [re, id, sev, title, detail] of [
    [TAGS, 'UNICODE-TAG-SMUGGLING', 'high', 'Unicode "tag" characters (invisible text)',
      'Characters from the Unicode Tags block are invisible but readable by programs and AI models. They have been used to hide instructions and payloads.'],
    [VARIATION_SUPPLEMENT, 'UNICODE-VARIATION-SMUGGLING', isCode ? 'high' : 'medium', 'Invisible variation-selector characters',
      'Runs of variation selectors can encode hidden bytes. The GlassWorm campaign used invisible Unicode like this to hide malware in plain sight.'],
    [VS_RUN, 'UNICODE-VARIATION-SMUGGLING', isCode ? 'high' : 'medium', 'Run of invisible variation selectors',
      'Long runs of variation selectors can encode hidden bytes.'],
  ]) {
    const m = re.exec(text)
    re.lastIndex = 0
    if (m) findings.add({ id, severity: sev, file: rel, line: lineOf(text, m.index), evidence: codePointName(m[0].codePointAt(0)), title, detail })
  }
  if (isCode) {
    let count = 0
    let first = null
    for (const m of text.matchAll(INVISIBLE)) {
      const cp = m[0].codePointAt(0)
      if (HANDLED_ELSEWHERE.test(m[0])) continue
      if (cp === 0xfeff && m.index === 0) continue // a byte-order mark at the start of a file is normal
      // Zero-width joiners inside emoji sequences (👩\u200D💻) are normal.
      if (cp === 0x200d && PICTO.test(text.slice(Math.max(0, m.index - 2), m.index)) && PICTO.test(text.slice(m.index + 1, m.index + 3))) continue
      count++
      if (!first) first = m
    }
    if (count) {
      findings.add({
        id: 'UNICODE-INVISIBLE', severity: count >= 5 ? 'high' : 'medium', file: rel, line: lineOf(text, first.index),
        evidence: `${count}\u00D7 invisible, first ${codePointName(first[0].codePointAt(0))}`,
        title: 'Invisible characters in code',
        detail: 'Zero-width and filler characters can hide identifiers or split keywords so code looks harmless when reviewed.',
      })
    }
  }
}

function patternChecks(rel, text, ext, base, findings) {
  const isCode = CODE_EXT.has(ext)
  const isScript = SCRIPT_EXT.has(ext)
  const minified = /\.min\.(js|css)$|(^|\/)(dist|build|vendor|public\/assets)\//.test(rel)
  const lines = text.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (line.length > 150 && isCode) {
      const hm = HIDDEN_AFTER_WHITESPACE.exec(line)
      if (hm && CODEISH.test(hm[1])) {
        findings.add({
          id: 'HIDDEN-WHITESPACE-PAYLOAD', severity: 'high', file: rel, line: i + 1, evidence: hm[1].trim(),
          title: 'Code hidden after a long run of spaces',
          detail: 'Code pushed hundreds of columns to the right is invisible in most editors and in GitHub diffs. PolinRider hid its loader in build config files exactly this way.',
        })
      }
    }
    if (isScript && !minified && JS_EXEC.test(line) && JS_DECODE.test(line)) {
      findings.add({
        id: 'OBFUSCATION-DECODE-EXEC', severity: 'high', file: rel, line: i + 1, evidence: excerpt(line, line.search(JS_EXEC)),
        title: 'Decodes data and executes it',
        detail: 'Decoding a base64/hex/char-code blob and passing it to eval, Function or a process launcher is how most droppers hide their real behavior.',
      })
    }
    if ((ext === 'py' || ext === 'pyw') && PY_EXEC_DECODE.test(line)) {
      findings.add({
        id: 'OBFUSCATION-DECODE-EXEC', severity: 'high', file: rel, line: i + 1, evidence: excerpt(line, line.search(/\b(exec|eval)\s*\(/)),
        title: 'Python decodes data and executes it',
        detail: 'exec/eval of base64-, zlib- or marshal-decoded data hides what the code really does.',
      })
    }
    if (isScript && !minified && line.length > 5000) {
      findings.add({
        id: 'OBFUSCATION-LONG-LINE', severity: 'low', file: rel, line: i + 1, evidence: `${line.length} characters`,
        title: 'Extremely long line in a source file',
        detail: 'Not proof of anything (generated code does this), but obfuscated payloads are often a single enormous line.',
      })
    }
  }

  if (isScript && CHAIN_RPC.test(text)) {
    const exec = CHAIN_EXEC.test(text)
    findings.add({
      id: 'C2-BLOCKCHAIN', severity: exec ? 'high' : 'low', file: rel,
      evidence: text.match(CHAIN_RPC)[0],
      title: exec ? 'Reads blockchain transaction data and executes code' : 'Reads blockchain transaction data',
      detail: exec
        ? 'Fetching data from an Ethereum/Tron transaction and running it is a "dead-drop" command-and-control channel that can\'t be taken down. PolinRider decoded the newest transaction a wallet sent to itself and ran it with Node.js.'
        : 'Normal for web3 apps. Suspicious in a project that has nothing to do with crypto.',
    })
  }
  if (isScript && DETACHED_NODE_REPL.test(text)) {
    findings.add({
      id: 'C2-NODE-REPL', severity: 'high', file: rel, evidence: text.match(DETACHED_NODE_REPL)[0],
      title: 'Spawns an interactive Node.js process',
      detail: 'Starting `node -i` and feeding it input gives remote code a live interpreter. PolinRider started a detached `node -i` after decoding its payload.',
    })
  }

  // Python files that run on import or during test discovery.
  if ((base === 'conftest.py' || base === 'setup.py' || base === 'sitecustomize.py' || base === 'usercustomize.py' || base === '__init__.py') && ext === 'py') {
    const net = /\b(urllib\.request|urlopen|requests\.(get|post)|http\.client|socket\.socket|httpx\.)/.test(text)
    const execy = /\b(exec|eval|compile)\s*\(|subprocess\.|os\.system|os\.popen|__import__\s*\(/.test(text)
    if (net && execy) {
      findings.add({
        id: 'PY-IMPORT-TIME-LOADER', severity: 'high', file: rel,
        title: `${base} downloads and executes code`,
        detail: `${base} runs automatically (on import, test discovery or install). Network access combined with exec/subprocess here is the PolinRider loader pattern.`,
      })
    }
  }
  if (ext === 'pth' && /^\s*import\s/m.test(text)) {
    findings.add({
      id: 'PY-PTH-EXEC', severity: 'medium', file: rel,
      title: '.pth file with an import line',
      detail: 'Lines in .pth files that start with "import" run every time Python starts, once the file is installed into site-packages.',
    })
  }

  // MSBuild runs targets on every build (the fake .NET take-home tests).
  if (['csproj', 'vbproj', 'fsproj', 'props', 'targets'].includes(ext)) {
    const execTask = /<\s*(Exec|UsingTask)\b/i.test(text)
    const dl = /(DownloadFile|Invoke-WebRequest|curl|wget|https?:\/\/[^"<\s]+\.(exe|dll|ps1|zip))/i.test(text)
    if (execTask) {
      findings.add({
        id: 'MSBUILD-EXEC', severity: dl ? 'high' : 'medium', file: rel,
        evidence: (text.match(/<\s*(Exec|UsingTask)\b[^>]{0,160}/i) || [''])[0],
        title: 'Build file runs commands or loads custom tasks',
        detail: 'MSBuild <Exec> and <UsingTask> run during `dotnet build`. The fake .NET take-home repos ran a DLL after every build this way.',
      })
    }
  }

  // Build/dev config files execute when you run the dev server or tests.
  if (/^(next|vite|vitest|tailwind|postcss|webpack|rollup|babel|jest|nuxt|svelte|astro|eslint|tsup|esbuild|metro|gulpfile|gruntfile)(\.config)?\.(c|m)?(j|t)s$|^\.eslintrc\.(c)?js$/i.test(base)) {
    const proc = /child_process|execSync|spawnSync|\bexec\s*\(|\bspawn\s*\(/.test(text)
    const net = /\b(https?\.get|https?\.request|fetch\s*\(|axios|XMLHttpRequest|net\.connect|dgram)\b/.test(text)
    const home = /(os\.homedir|process\.env\.HOME|~\/\.ssh|\.npmrc|\.gitconfig|\.aws\/credentials|id_rsa|id_ed25519)/.test(text)
    const n = [proc, net, home].filter(Boolean).length
    if (n >= 1) {
      findings.add({
        id: 'CONFIG-EXEC', severity: n >= 2 ? 'high' : 'medium', file: rel,
        title: `${base} launches processes, uses the network, or reads home-directory files`,
        detail: `Config files like ${base} run as code whenever you start the dev server, build, lint or test. Malicious repos hide loaders in them because nobody reviews config.`,
      })
    }
  }
}

function binaryChecks(rel, buf, ext, findings) {
  const kind = executableKind(buf)
  if (kind) {
    const disguised = !['exe', 'dll', 'so', 'dylib', 'bin', 'node', 'o', 'a', ''].includes(ext)
    findings.add({
      id: 'BIN-EXECUTABLE', severity: disguised ? 'high' : 'medium', file: rel, evidence: kind,
      title: disguised ? `Executable disguised as .${ext}` : 'Compiled executable committed to the repo',
      detail: disguised
        ? 'A program with a non-program file extension is a strong sign something is being hidden.'
        : 'Source repos rarely need committed binaries; you can\'t review what they do. The fake .NET take-home repos sideloaded DLLs this way.',
    })
    return
  }
  const sigs = MAGIC[ext]
  if (sigs && !sigs.some(sig => startsWith(buf, sig))) {
    findings.add({
      id: 'FILETYPE-MISMATCH', severity: 'medium', file: rel,
      title: `File named .${ext} doesn't look like a .${ext} file`,
      detail: 'Its first bytes don\'t match the format its name claims. It may just be corrupt, but files that lie about their type are a common hiding place.',
    })
  }
}

/**
 * Walk the repo and run every content check.
 * @returns {{files:number, bytes:number, skippedLarge:number, truncated:boolean, packageJsons:string[]}}
 */
export async function contentChecks(root, findings) {
  const stats = { files: 0, bytes: 0, scanned: 0, skippedLarge: 0, truncated: false }
  const ioc = iocIndex()
  const queue = ['']
  while (queue.length) {
    const relDir = queue.pop()
    let entries
    try { entries = await readdir(path.join(root, relDir), { withFileTypes: true }) } catch { continue }
    for (const ent of entries) {
      const rel = relDir ? `${relDir}/${ent.name}` : ent.name
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) {
          if (ent.name === 'node_modules' && relDir === '') {
            findings.add({ id: 'REPO-COMMITTED-NODE-MODULES', severity: 'medium', file: rel, title: 'node_modules is committed to the repo',
              detail: 'Committed dependencies bypass the lockfile and registry checks entirely, so nothing verifies them. Unusual for a legitimate project.' })
          }
          continue
        }
        queue.push(rel)
        continue
      }
      const abs = path.join(root, rel)
      const st = await lstat(abs).catch(() => null)
      if (!st || !st.isFile()) continue // symlinks were checked out as files; anything else is skipped
      stats.files++
      if (stats.files > MAX_FILES || stats.bytes > MAX_TOTAL_BYTES) { stats.truncated = true; break }
      const ext = path.extname(ent.name).slice(1).toLowerCase()
      const base = ent.name.toLowerCase()
      if (ioc.files.has(base)) {
        const c = ioc.files.get(base)
        findings.add({ id: 'IOC-MATCH', severity: 'critical', file: rel, evidence: `file name: ${ent.name}`,
          title: `File name matches a known ${c.campaign} indicator`,
          detail: `Reported in public research (snapshot ${IOC_SNAPSHOT_DATE}): ${c.source}` })
      }
      const fh = await open(abs, 'r')
      let buf
      try {
        const size = Math.min(st.size, MAX_FILE_BYTES)
        buf = Buffer.alloc(size)
        await fh.read(buf, 0, size, 0)
      } finally { await fh.close() }
      stats.bytes += buf.length
      if (st.size > MAX_FILE_BYTES) stats.skippedLarge++
      stats.scanned++

      const head = buf.subarray(0, 8000)
      const binary = head.includes(0)
      if (binary) {
        binaryChecks(rel, buf, ext, findings)
        continue
      }
      const text = buf.toString('utf8')
      if (FONT_LIKE.test(ent.name) && !isLfsPointer(text)) {
        findings.add({
          id: 'FILETYPE-FAKE-FONT', severity: 'high', file: rel, evidence: excerpt(text, 0, 60),
          title: 'Font file that is actually text',
          detail: 'Real fonts are binary. PolinRider hid JavaScript in fake font files named like fa-solid-400.woff2 and fa-solid-300.llf.',
        })
      } else if (MAGIC[ext] && !isLfsPointer(text)) {
        findings.add({
          id: 'FILETYPE-MISMATCH', severity: SCRIPT_EXT.has(ext) ? 'medium' : 'high', file: rel, evidence: excerpt(text, 0, 60),
          title: `File named .${ext} contains text`,
          detail: 'A binary format (image, font, archive) that is actually text is a common place to stash a script.',
        })
      }
      for (const hit of matchIocStrings(text, ioc)) {
        findings.add({ id: 'IOC-MATCH', severity: 'critical', file: rel, line: lineOf(text, hit.index), evidence: `${hit.kind}: ${hit.needle}`,
          title: `Contains a known ${hit.campaign} indicator (${hit.kind})`,
          detail: `This exact value appears in public reporting on an active campaign (snapshot ${IOC_SNAPSHOT_DATE}): ${hit.source}` })
      }
      if (['csproj', 'vbproj', 'fsproj', 'props', 'targets'].includes(ext) || base === 'packages.config') {
        for (const m of text.matchAll(/<\s*(?:PackageReference|package)\b[^>]*?(?:Include|id)\s*=\s*"([^"]+)"/gi)) {
          const c = ioc.nuget.get(m[1].toLowerCase())
          if (c) findings.add({ id: 'IOC-MATCH', severity: 'critical', file: rel, line: lineOf(text, m.index), evidence: `NuGet package: ${m[1]}`,
            title: `References a known-malicious NuGet package (${c.campaign})`, detail: `Reported in public research (snapshot ${IOC_SNAPSHOT_DATE}): ${c.source}` })
        }
      }
      unicodeChecks(rel, text, ext, findings)
      patternChecks(rel, text, ext, base, findings)
    }
    if (stats.truncated) break
  }
  if (stats.truncated) {
    findings.add({ id: 'SCAN-TRUNCATED', severity: 'medium', title: 'Repository too large to scan completely',
      detail: `Scanning stopped after ${MAX_FILES} files or ${MAX_TOTAL_BYTES / 1024 / 1024} MiB. Unscanned files were not checked.` })
  }
  if (stats.skippedLarge) {
    findings.add({ id: 'SCAN-LARGE-FILES', severity: 'info', title: `${stats.skippedLarge} file(s) larger than 2 MiB were only partly scanned`,
      detail: 'The first 2 MiB of each was checked.' })
  }
  return stats
}
