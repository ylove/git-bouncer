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
// Nothing here executes repository code. Files are read as bytes and inspected. Every regex here
// is linear-time on hostile input (no nested quantifiers over overlapping classes).

import { readdir, lstat, open } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import path from 'node:path'
import { excerpt } from '../findings.js'
import { iocIndex, matchIocStrings, IOC_SNAPSHOT_DATE } from './iocs.js'

const MAX_FILE_BYTES = 2 * 1024 * 1024
const MAX_TOTAL_BYTES = 400 * 1024 * 1024
const MAX_FILES = 60000 // distinct, non-empty files
const MAX_ENTRIES = 400000 // directory entries we're willing to list at all

// Files that are executed as code by some tool (interpreters, shells, build systems).
const EXEC_EXT = new Set(['js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx', 'vue', 'svelte', 'astro',
  'py', 'pyw', 'rb', 'php', 'pl', 'sh', 'bash', 'zsh', 'fish', 'ps1', 'psm1', 'bat', 'cmd', 'cs', 'vb', 'fs',
  'csproj', 'vbproj', 'fsproj', 'props', 'targets', 'proj', 'java', 'kt', 'kts', 'groovy', 'gradle', 'go', 'rs',
  'lua', 'mk', 'cmake', 'swift', 'dart', 'scala', 'r', 'jl', 'ex', 'exs'])
const EXEC_NAMES = new Set(['makefile', 'gnumakefile', 'rakefile', 'gemfile', 'cmakelists.txt', 'dockerfile', 'vagrantfile', 'justfile', 'build', 'build.bazel', 'workspace'])
// Data and markup: shown to people, parsed by programs, but not executed by themselves.
const DATA_EXT = new Set(['json', 'jsonc', 'json5', 'toml', 'yml', 'yaml', 'html', 'htm', 'xml', 'md', 'mdx', 'txt', 'po', 'properties', 'csv', 'svg', 'ini', 'cfg', 'conf'])
const SCRIPT_EXT = new Set(['js', 'mjs', 'cjs', 'jsx', 'ts', 'mts', 'cts', 'tsx', 'vue', 'svelte', 'py', 'pyw', 'rb', 'php', 'pl', 'sh', 'bash', 'zsh', 'fish', 'ps1', 'psm1', 'bat', 'cmd'])
const MSBUILD_EXT = new Set(['csproj', 'vbproj', 'fsproj', 'props', 'targets', 'proj'])

// Magic bytes for formats that malware has impersonated.
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
const FONT_EXT = new Set(['woff', 'woff2', 'ttf', 'otf', 'eot', 'llf'])

const startsWith = (buf, sig, at = 0) => sig.every((b, i) => buf[at + i] === b)

/** A real font, judged by its header, not just its first four bytes (which anyone can copy). */
function isRealFont(buf, ext, size) {
  if (ext === 'llf') return false // not a real font format; PolinRider used it as a disguise
  if (ext === 'eot') return buf.length > 36 && buf[34] === 0x4c && buf[35] === 0x50 && buf.readUInt32LE(0) === size // "LP" magic + EOTSize
  if (!(MAGIC[ext] || []).some(sig => startsWith(buf, sig))) return false
  if (ext === 'woff' || ext === 'woff2') return buf.length >= 12 && buf.readUInt32BE(8) === size // header's total-length field
  // TrueType/OpenType: a sane table count, and room for the table directory.
  if (buf.length < 12) return false
  const tables = buf.readUInt16BE(4)
  return tables >= 1 && tables <= 100 && size >= 12 + 16 * tables
}

function executableKind(buf, ext) {
  if (buf.length >= 4 && startsWith(buf, [0x7f, 0x45, 0x4c, 0x46])) return 'ELF (Linux executable)'
  if (buf.length >= 8) {
    const be = buf.readUInt32BE(0)
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(be)) return 'Mach-O (macOS executable)'
    // Universal ("fat") Mach-O shares 0xCAFEBABE with Java .class files; the arch count tells them apart
    // (Java's version field there is always 45 or more).
    if (be === 0xcafebabe && ext !== 'class') {
      const n = buf.readUInt32BE(4)
      if (n >= 1 && n <= 20) return 'Mach-O universal (macOS executable)'
    }
  }
  if (buf.length >= 0x40 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const peOffset = buf.readUInt32LE(0x3c)
    if (peOffset + 4 <= buf.length && buf.readUInt32BE(peOffset) === 0x50450000) return 'PE (Windows .exe/.dll)'
  }
  return null
}

const isLfsPointer = text => text.startsWith('version https://git-lfs.github.com/spec/v1')

/** Decode bytes as text: UTF-16 when there's a BOM (MSBuild and PowerShell files often are), else UTF-8. */
function decode(buf) {
  if (buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder('utf-16le').decode(buf.subarray(2))
  if (buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder('utf-16be').decode(buf.subarray(2))
  return buf.toString('utf8')
}

// --- text patterns -----------------------------------------------------------------------

const CODEISH = /[;(){}=]|\b(require|import|eval|exec|Function|fetch|http|atob|Buffer|subprocess|base64)\b/

/**
 * Longest run of "nothing visible" between two visible characters on one line: whitespace of any kind
 * (including non-breaking and other Unicode spaces) and empty comments used to break up runs.
 * A single pass over the line, so it stays fast on a 2 MiB one-line file.
 * @returns {{len: number, after: string}}
 */
export function longestHiddenGap(line) {
  let best = 0
  let bestEnd = -1
  let run = 0
  let seenVisible = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '/' && line[i + 1] === '*') { // an empty or whitespace-only comment counts as gap
      let j = i + 2
      while (j < line.length && j < i + 12 && /\s/.test(line[j])) j++
      if (line[j] === '*' && line[j + 1] === '/') { run += j + 2 - i; i = j + 1; continue }
    }
    if (/\s/.test(ch)) { run++; continue }
    if (seenVisible && run > best) { best = run; bestEnd = i }
    seenVisible = true
    run = 0
  }
  return { len: best, after: bestEnd >= 0 ? line.slice(bestEnd, bestEnd + 120) : '' }
}

// Decode-then-execute: the core move of most JS/Python droppers.
const JS_EXEC = /(?<![.\w$])(eval|Function|execSync|exec|spawn|runInNewContext|runInThisContext)\s*\(|\(\s*0\s*,\s*eval\s*\)|\b(globalThis|window|self|global)\s*(\.\s*eval|\[\s*['"`]eval['"`]\s*\])/
const JS_DECODE = /\batob\s*\(|Buffer\.from\s*\([^)]{0,200}['"](base64|base64url|hex)['"]|String\.fromCharCode\s*\(\s*(\d+\s*,\s*){8,}|(\\x[0-9a-fA-F]{2}){24,}|\bunescape\s*\(/
// Patterns that are suspicious even in minified or vendored code.
const JS_NESTED = /\b(eval|Function)\s*\(\s*(atob|Buffer\.from|String\.fromCharCode|unescape|decodeURIComponent)\s*\(|\(\s*0\s*,\s*eval\s*\)\s*\(\s*(atob|Buffer\.from)|\bimport\s*\(\s*['"`]data:(text|application)\/javascript/
const PY_EXEC = /\b(exec|eval)\s*\(/
const PY_DECODE = /\b(b64decode|b32decode|b16decode|a85decode|b85decode|urlsafe_b64decode|decompress|unhexlify|fromhex|marshal\.loads|codecs\.decode)\s*\(/
// Source encodings that let a .py file hide statements from anyone reading it as UTF-8.
const PY_DANGEROUS_CODEC = /^(utf[-_]?7|u7|unicode[-_]escape|raw[-_]unicode[-_]escape|punycode|idna|utf[-_]?(16|32)(?:[-_]?[lb]e)?|rot[-_]?13|hex|base64|zlib|bz2|uu|quopri)$/i

// Ethereum/Tron transaction data used as a dead-drop for the next stage (PolinRider, EtherHiding).
// (Written with groups so this file's own source doesn't contain the literal method names it looks for.)
const CHAIN_RPC = /(eth_get(?:Transaction(?:ByHash|Receipt)|BlockByNumber)|eth_cal[l]|getTransaction\s*\(|api\.etherscan\.io|api\.trongrid\.io|bsc-datase[e]d|mainnet\.infura\.io|cloudflare-eth\.com|eth\.llamarpc\.com|rpc\.ankr\.com|ethereum\.publicnode\.com|g\.alchemy\.com)/
const CHAIN_EXEC = /\b(eval|new\s+Function|Function\s*\(|vm\.run\w*|child_[p]rocess|exec[S]ync|spawn\s*\(\s*['"`]node)/
const DETACHED_NODE_REPL = /spawn\s*\(\s*['"`](process\.execPath|node)['"`]?\s*,\s*\[\s*['"`]-i['"`]/

// Download, decode, or pipe-to-shell inside a command string (install scripts, tasks, hooks).
// Plain "node -e" or "bash -c" isn't enough: lots of legitimate install scripts use them locally.
export const DOWNLOAD_EXEC = /(\b(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|Invoke-Expression|iex|certutil|bitsadmin|mshta|nc|ncat)\b|https?:\/\/|powershell(\.exe)?\s+(-\w+\s+)*-(e|enc|encodedcommand)\b|base64\s+(-d|--decode)|\batob\s*\(|\|\s*(ba|z|da)?sh\b)/i

const BIDI = /[\u202A-\u202E\u2066-\u2069]/g
// Invisible characters by Unicode property, not a hand-made list (which always misses some).
const INVISIBLE = /[\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu
const HANDLED_ELSEWHERE = /[\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}\uFE00-\uFE0F]/u
const TAGS = /[\u{E0000}-\u{E007F}]/gu
// Subdivision flags (England, Scotland, Wales) are legitimate tag sequences: black flag + tag letters + cancel tag.
const FLAG_TAG_SEQUENCE = /\u{1F3F4}[\u{E0061}-\u{E007A}\u{E0030}-\u{E0039}]{2,6}\u{E007F}/gu
const VARIATION_SUPPLEMENT = /[\u{E0100}-\u{E01EF}]/gu
const VS_RUN = /[\uFE00-\uFE0F]{4,}/g
const PICTO = /\p{Extended_Pictographic}/u
const EMOJI_MODIFIER = /[\u{1F3FB}-\u{1F3FF}\uFE0E\uFE0F]/u
const NON_LATIN_LETTER = /[\p{L}\p{M}]/u
const IDEOGRAPH = /\p{Ideographic}/u

const codePointName = cp => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`

/** The code point just before index i (surrogate-aware). */
function prevCodePoint(text, i) {
  if (i <= 0) return null
  const lo = text.charCodeAt(i - 1)
  if (lo >= 0xdc00 && lo <= 0xdfff && i >= 2) return { cp: text.codePointAt(i - 2), at: i - 2 }
  return { cp: lo, at: i - 1 }
}

/** Is the zero-width joiner at index i part of an emoji sequence (rainbow flag, skin tones, families)? */
function zwjInEmoji(text, i) {
  let p = prevCodePoint(text, i)
  while (p && EMOJI_MODIFIER.test(String.fromCodePoint(p.cp))) p = prevCodePoint(text, p.at)
  const next = text.codePointAt(i + 1)
  return Boolean(p && PICTO.test(String.fromCodePoint(p.cp)) && next !== undefined && PICTO.test(String.fromCodePoint(next)))
}

/** Joiners and direction marks next to letters of another script (Persian, Hebrew, Hindi, ...) are ordinary text. */
function joinerInWord(text, i) {
  const p = prevCodePoint(text, i)
  const next = text.codePointAt(i + 1)
  const isScript = cp => cp !== undefined && cp > 0x7f && NON_LATIN_LETTER.test(String.fromCodePoint(cp))
  return Boolean((p && isScript(p.cp)) || isScript(next))
}

/** 1-based line number of a character index. */
function lineOf(text, index) {
  let line = 1
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++
  return line
}

function kindOf(ext, base) {
  if (EXEC_EXT.has(ext) || EXEC_NAMES.has(base) || base.endsWith('.csproj.user') || base.endsWith('.vbproj.user')) return 'exec'
  if (DATA_EXT.has(ext)) return 'data'
  return 'other'
}

function unicodeChecks(rel, text, kind, findings) {
  const isCode = kind === 'exec'
  const bidi = text.search(BIDI)
  if (bidi !== -1) {
    findings.add({
      id: 'UNICODE-BIDI', severity: isCode ? 'high' : 'low', file: rel, line: lineOf(text, bidi),
      evidence: codePointName(text.codePointAt(bidi)),
      title: 'Bidirectional control character (Trojan Source)',
      detail: isCode
        ? 'Invisible Unicode direction controls can make code display differently from how it runs (CVE-2021-42574). There is almost never a legitimate reason for them in source code.'
        : 'Direction controls are normal in right-to-left text (Hebrew, Arabic). Noted, not a problem in a data or text file by itself.',
    })
  }
  const withoutFlags = text.includes('\u{1F3F4}') ? text.replace(FLAG_TAG_SEQUENCE, '') : text
  const tag = withoutFlags.search(TAGS)
  if (tag !== -1) {
    findings.add({ id: 'UNICODE-TAG-SMUGGLING', severity: 'high', file: rel, evidence: codePointName(withoutFlags.codePointAt(tag)),
      title: 'Unicode "tag" characters (invisible text)',
      detail: 'Characters from the Unicode Tags block are invisible but readable by programs and AI models. They have been used to hide instructions and payloads. (Flag emoji like England\'s are recognized and ignored.)' })
  }
  for (const m of text.matchAll(VARIATION_SUPPLEMENT)) {
    const p = prevCodePoint(text, m.index)
    if (p && IDEOGRAPH.test(String.fromCodePoint(p.cp))) continue // ideographic variation sequences (Japanese, Chinese)
    findings.add({ id: 'UNICODE-VARIATION-SMUGGLING', severity: isCode ? 'high' : 'medium', file: rel, line: lineOf(text, m.index), evidence: codePointName(m[0].codePointAt(0)),
      title: 'Invisible variation-selector characters',
      detail: 'Variation selectors that don\'t follow an ideograph can encode hidden bytes. The GlassWorm campaign used invisible Unicode like this to hide malware in plain sight.' })
    break
  }
  const vs = VS_RUN.exec(text)
  VS_RUN.lastIndex = 0
  if (vs) findings.add({ id: 'UNICODE-VARIATION-SMUGGLING', severity: isCode ? 'high' : 'medium', file: rel, line: lineOf(text, vs.index), evidence: codePointName(vs[0].codePointAt(0)),
    title: 'Run of invisible variation selectors', detail: 'Long runs of variation selectors can encode hidden bytes.' })

  if (isCode) {
    let count = 0
    let first = null
    for (const m of text.matchAll(INVISIBLE)) {
      const cp = m[0].codePointAt(0)
      if (HANDLED_ELSEWHERE.test(m[0])) continue
      if (cp === 0xfeff && m.index === 0) continue // a byte-order mark at the start of a file is normal
      if (cp === 0x200d && zwjInEmoji(text, m.index)) continue
      if ([0x200c, 0x200d, 0x200e, 0x200f, 0x00ad].includes(cp) && joinerInWord(text, m.index)) continue
      count++
      if (!first) first = m
    }
    if (count) {
      findings.add({
        id: 'UNICODE-INVISIBLE', severity: count >= 5 ? 'high' : 'medium', file: rel, line: lineOf(text, first.index),
        evidence: `${count}\u00D7 invisible, first ${codePointName(first[0].codePointAt(0))}`,
        title: 'Invisible characters in code',
        detail: 'Zero-width and other format characters can hide identifiers or split keywords so code looks harmless when reviewed.',
      })
    }
  }
}

// child_process calls, written however they're imported (cp.execSync, execSync, require('child_process').exec).
// A bare `.exec(` is only counted on a child_process-looking object, because RegExp#exec is everywhere.
const PROC_CALL = /(?:\b(?:cp|child_process|childProcess|proc|\))\s*\.\s*exec|\b(?:execSync|execFileSync|spawnSync|execFile|spawn|fork)|(?<![.\w$])exec)\s*\(\s*['"`]?([^'"`)]{0,60})/g
const NET_USE = /\b(https?\.(get|request)\s*\(|fetch\s*\(|axios\b|XMLHttpRequest|net\.connect|dgram\b|new\s+WebSocket\s*\()/
const HOME_SECRETS = /(os\.homedir|process\.env\.(HOME|USERPROFILE)|~\/\.ssh|\.npmrc|\.gitconfig|\.aws\/credentials|id_rsa|id_ed25519|\.config\/gh)/
export const CONFIG_FILE = /^(next|vite|vitest|tailwind|postcss|webpack|rollup|babel|jest|nuxt|svelte|astro|eslint|tsup|esbuild|metro|hardhat|prettier|playwright|cypress|docusaurus|remix|quasar|gatsby-(config|node)|karma\.conf|gulpfile|gruntfile)(\.config)?\.(c|m)?(j|t)s$|^\.(eslintrc|prettierrc|babelrc|mocharc|lintstagedrc)\.(c|m)?js$/i

function patternChecks(rel, text, ext, base, kind, findings) {
  const isScript = SCRIPT_EXT.has(ext)
  const lines = text.split('\n')
  // "Minified" is judged by content, never by path: an attacker can name any folder dist/.
  const minified = lines.length > 0 && text.length / lines.length > 1000

  let prevExecLine = -10
  let prevDecodeLine = -10
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (line.length > 150 && kind === 'exec') {
      const gap = longestHiddenGap(line)
      if (gap.len >= 150 && CODEISH.test(gap.after)) {
        findings.add({
          id: 'HIDDEN-WHITESPACE-PAYLOAD', severity: 'high', file: rel, line: i + 1, evidence: gap.after.trim().slice(0, 120),
          title: 'Code hidden after a long run of spaces',
          detail: `Code pushed ${gap.len} columns to the right is invisible in most editors and in GitHub diffs. PolinRider hid its loader in build config files exactly this way.`,
        })
      }
    }
    if (!isScript) continue
    if (JS_NESTED.test(line)) {
      findings.add({ id: 'OBFUSCATION-DECODE-EXEC', severity: 'high', file: rel, line: i + 1, evidence: excerpt(line, line.search(JS_NESTED)),
        title: 'Decodes data and executes it',
        detail: 'Decoding a base64/char-code blob and passing it straight to eval or Function is how most droppers hide their real behavior.' })
      continue
    }
    if (!minified) {
      const ex = JS_EXEC.test(line)
      const de = JS_DECODE.test(line)
      if (ex) prevExecLine = i
      if (de) prevDecodeLine = i
      // Same line, or split across up to three lines (decode into a variable, run it two lines later).
      if ((ex && de) || (ex && i - prevDecodeLine <= 3) || (de && i - prevExecLine <= 3)) {
        findings.add({
          id: 'OBFUSCATION-DECODE-EXEC', severity: 'high', file: rel, line: i + 1, evidence: excerpt(line, Math.max(0, line.search(ex ? JS_EXEC : JS_DECODE))),
          title: 'Decodes data and executes it',
          detail: 'Decoding a base64/hex/char-code blob and passing it to eval, Function or a process launcher is how most droppers hide their real behavior.',
        })
        prevExecLine = prevDecodeLine = -10
      }
      if (line.length > 5000) {
        findings.add({ id: 'OBFUSCATION-LONG-LINE', severity: 'low', file: rel, line: i + 1, evidence: `${line.length} characters`,
          title: 'Extremely long line in a source file',
          detail: 'Not proof of anything (generated code does this), but obfuscated payloads are often a single enormous line.' })
      }
    }
    if ((ext === 'py' || ext === 'pyw') && PY_EXEC.test(line) && PY_DECODE.test(line)) {
      findings.add({ id: 'OBFUSCATION-DECODE-EXEC', severity: 'high', file: rel, line: i + 1, evidence: excerpt(line, line.search(PY_EXEC)),
        title: 'Python decodes data and executes it',
        detail: 'exec/eval of base64-, zlib- or marshal-decoded data hides what the code really does.' })
    }
  }

  if (isScript && CHAIN_RPC.test(text)) {
    const exec = CHAIN_EXEC.test(text)
    findings.add({
      id: 'C2-BLOCKCHAIN', severity: exec ? 'high' : 'low', file: rel, evidence: text.match(CHAIN_RPC)[0],
      title: exec ? 'Reads blockchain transaction data and executes code' : 'Reads blockchain transaction data',
      detail: exec
        ? 'Fetching data from an Ethereum/Tron transaction and running it is a "dead-drop" command-and-control channel that can\'t be taken down. PolinRider decoded the newest transaction a wallet sent to itself and ran it with Node.js.'
        : 'Normal for web3 apps. Suspicious in a project that has nothing to do with crypto.',
    })
  }
  if (isScript && DETACHED_NODE_REPL.test(text)) {
    findings.add({ id: 'C2-NODE-REPL', severity: 'high', file: rel, evidence: text.match(DETACHED_NODE_REPL)[0],
      title: 'Spawns an interactive Node.js process',
      detail: 'Starting `node -i` and feeding it input gives remote code a live interpreter. PolinRider started a detached `node -i` after decoding its payload.' })
  }

  if (ext === 'py' || ext === 'pyw') {
    // A source-encoding declaration in the first two lines changes how Python reads the whole file.
    const head = lines.slice(0, 2).join('\n')
    const codec = head.match(/^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)/m)
    if (codec && PY_DANGEROUS_CODEC.test(codec[1])) {
      findings.add({ id: 'PY-CODEC-DECLARATION', severity: 'high', file: rel, line: 1, evidence: `coding: ${codec[1]}`,
        title: `Python file declares the "${codec[1]}" source encoding`,
        detail: 'Encodings like UTF-7 make Python decode text that looks like a comment into real statements. Nobody reading the file as UTF-8 sees that code.' })
    }
    if (['conftest.py', 'setup.py', 'sitecustomize.py', 'usercustomize.py', '__init__.py', 'noxfile.py', 'manage.py'].includes(base)) {
      const net = /\b(urllib\.request|urlopen|requests\.(get|post)|http\.client|socket\.socket|httpx\.|curl|wget)\b/.test(text)
      const execy = /\b(exec|eval|compile)\s*\(|subprocess\.|os\.system|os\.popen|__import__\s*\(/.test(text)
      if (net && execy) {
        findings.add({ id: 'PY-IMPORT-TIME-LOADER', severity: 'high', file: rel,
          title: `${base} downloads and executes code`,
          detail: `${base} runs automatically (on import, test discovery or install). Network access combined with exec/subprocess here is the PolinRider loader pattern.` })
      }
    }
  }
  if (ext === 'pth' && /^\s*import\s/m.test(text)) {
    findings.add({ id: 'PY-PTH-EXEC', severity: 'medium', file: rel, title: '.pth file with an import line',
      detail: 'Lines in .pth files that start with "import" run every time Python starts, once the file is installed into site-packages.' })
  }

  // MSBuild runs targets on every build (the fake .NET take-home tests).
  const isMsbuild = MSBUILD_EXT.has(ext) || base.endsWith('.csproj.user') || base.endsWith('.vbproj.user') || (ext === 'xml' && /<Project[\s>]/.test(text))
  if (isMsbuild && /<\s*(Exec|UsingTask)\b/i.test(text)) {
    const dl = /(DownloadFile|Invoke-WebRequest|curl|wget|https?:\/\/[^"<\s]+\.(exe|dll|ps1|zip))/i.test(text)
    const localBinary = /<\s*Exec\b[^>]{0,400}?Command\s*=\s*"[^"]{0,400}?\.(dll|exe)\b/i.test(text)
    findings.add({
      id: 'MSBUILD-EXEC', severity: dl || localBinary ? 'high' : 'medium', file: rel,
      evidence: (text.match(/<\s*(Exec|UsingTask)\b[^>]{0,160}/i) || [''])[0],
      title: localBinary ? 'Build file runs a committed program on every build' : 'Build file runs commands or loads custom tasks',
      detail: 'MSBuild <Exec> and <UsingTask> run during `dotnet build`. The fake .NET take-home repos ran a DLL after every build this way.',
    })
  }
  if (base === 'directory.build.rsp' || ext === 'rsp') {
    findings.add({ id: 'MSBUILD-RESPONSE-FILE', severity: 'medium', file: rel, evidence: text.trim().split('\n')[0].slice(0, 160),
      title: 'MSBuild response file adds options to every build',
      detail: 'Directory.Build.rsp is read automatically by `dotnet build`. It can load loggers (DLLs) and set properties that run code.' })
  }

  // Build/dev config files execute when you run the dev server, build, lint or test.
  if (CONFIG_FILE.test(base)) {
    // A config that only shells out to git (e.g. to stamp the commit SHA) is common and harmless.
    const calls = [...text.matchAll(PROC_CALL)]
    const proc = calls.some(m => !/^git\s/.test(m[1]))
    const net = NET_USE.test(text)
    const home = HOME_SECRETS.test(text)
    const n = [proc, net, home].filter(Boolean).length
    if (n >= 1) {
      findings.add({
        id: 'CONFIG-EXEC', severity: n >= 2 ? 'high' : 'medium', file: rel,
        title: `${base} ${[proc && 'launches processes', net && 'uses the network', home && 'reads home-directory files'].filter(Boolean).join(', ')}`,
        detail: `Config files like ${base} run as code whenever you start the dev server, build, lint or test. Malicious repos hide loaders in them because nobody reviews config.`,
      })
    }
  }
}

function binaryChecks(rel, buf, ext, findings) {
  const kind = executableKind(buf, ext)
  if (!kind) return false
  const disguised = !['exe', 'dll', 'so', 'dylib', 'bin', 'node', 'o', 'a', 'out', ''].includes(ext)
  findings.add({
    id: 'BIN-EXECUTABLE', severity: disguised ? 'high' : 'medium', file: rel, evidence: kind,
    title: disguised ? `Executable disguised as .${ext}` : 'Compiled executable committed to the repo',
    detail: disguised
      ? 'A program with a non-program file extension is a strong sign something is being hidden.'
      : 'Source repos rarely need committed binaries; you can\'t review what they do. The fake .NET take-home repos sideloaded DLLs this way.',
  })
  return true
}

/** List files, highest-risk first: auto-run and config locations, then code, then everything else. */
async function listFiles(root, findings) {
  const out = []
  const queue = ['']
  let entries = 0
  let nmReported = 0
  while (queue.length) {
    const relDir = queue.pop()
    let list
    try { list = await readdir(path.join(root, relDir), { withFileTypes: true }) } catch { continue }
    for (const ent of list) {
      if (++entries > MAX_ENTRIES) return { files: out, overflow: true }
      const rel = relDir ? `${relDir}/${ent.name}` : ent.name
      if (ent.isDirectory()) {
        if (ent.name === '.git' && relDir === '') continue
        // These checks run before anything is installed, so any node_modules here was committed.
        if (ent.name === 'node_modules' && nmReported++ < 5) {
          findings.add({ id: 'REPO-COMMITTED-NODE-MODULES', severity: 'medium', file: rel, title: 'node_modules is committed to the repo',
            detail: 'Committed dependencies bypass the lockfile and registry checks, and Node will load them from here. It\'s scanned like the rest of the repo, but nothing verifies where it came from.' })
        }
        queue.push(rel)
      } else if (ent.isFile()) {
        out.push(rel)
      }
    }
  }
  const rank = rel => {
    const base = path.posix.basename(rel).toLowerCase()
    if (/^\.(vscode|devcontainer|claude|cursor|husky|github|idea)\//.test(rel) || CONFIG_FILE.test(base) || ['package.json', '.npmrc', 'conftest.py', 'setup.py'].includes(base)) return 0
    const ext = path.posix.extname(base).slice(1)
    if (EXEC_EXT.has(ext) || EXEC_NAMES.has(base) || FONT_EXT.has(ext)) return 1
    return 2
  }
  out.sort((a, b) => rank(a) - rank(b))
  return { files: out, overflow: false }
}

/**
 * Walk the repo and run every content check.
 * @returns {{files:number, bytes:number, scanned:number, skippedLarge:number, duplicates:number, truncated:boolean}}
 */
export async function contentChecks(root, findings) {
  const stats = { files: 0, bytes: 0, scanned: 0, skippedLarge: 0, duplicates: 0, truncated: false }
  const ioc = iocIndex()
  const seen = new Set()
  let lfs = 0
  const { files, overflow } = await listFiles(root, findings)
  if (overflow) stats.truncated = true

  for (const rel of files) {
    const abs = path.join(root, rel)
    const st = await lstat(abs).catch(() => null)
    if (!st || !st.isFile()) continue
    stats.files++
    const name = path.posix.basename(rel)
    const base = name.toLowerCase()
    const ext = path.posix.extname(base).slice(1)
    if (ioc.files.has(base)) {
      const c = ioc.files.get(base)
      findings.add({ id: 'IOC-MATCH', severity: 'critical', file: rel, evidence: `file name: ${name}`,
        title: `File name matches a known ${c.campaign} indicator`,
        detail: `Reported in public research (snapshot ${IOC_SNAPSHOT_DATE}): ${c.source}` })
    }
    if (st.size === 0) continue
    if (stats.scanned >= MAX_FILES || stats.bytes > MAX_TOTAL_BYTES) { stats.truncated = true; break }

    const fh = await open(abs, 'r')
    let buf
    try {
      const size = Math.min(st.size, MAX_FILE_BYTES)
      buf = Buffer.alloc(size)
      await fh.read(buf, 0, size, 0)
    } finally { await fh.close() }
    if (st.size > MAX_FILE_BYTES) stats.skippedLarge++

    const kind = kindOf(ext, base)
    // Identical bytes are checked once, unless the name changes what they mean (code, config, fonts).
    const digest = createHash('sha1').update(buf).digest('hex')
    if (seen.has(digest) && kind === 'other' && !FONT_EXT.has(ext) && !MAGIC[ext]) { stats.duplicates++; continue }
    seen.add(digest)
    stats.bytes += buf.length
    stats.scanned++

    const utf16 = (buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff)
    const binary = !utf16 && buf.subarray(0, 8000).includes(0)
    if (binary && binaryChecks(rel, buf, ext, findings)) continue
    const head = buf.toString('latin1', 0, 80)

    if (FONT_EXT.has(ext)) {
      if (isRealFont(buf, ext, st.size)) continue // a real font: nothing else to check
      if (!isLfsPointer(head)) {
        findings.add({ id: 'FILETYPE-FAKE-FONT', severity: 'high', file: rel, evidence: excerpt(head, 0, 60),
          title: ext === 'llf' ? 'File with the fake font extension .llf' : `.${ext} file that isn't a real font`,
          detail: 'Its first bytes don\'t match any font format. PolinRider hid JavaScript in fake font files named like fa-solid-400.woff2 and fa-solid-300.llf.' })
      }
    } else if (MAGIC[ext]) {
      if (MAGIC[ext].some(sig => startsWith(buf, sig))) continue // a real image/archive: nothing else to check
      if (!isLfsPointer(head)) {
        findings.add({ id: 'FILETYPE-MISMATCH', severity: binary ? 'medium' : 'high', file: rel, evidence: binary ? null : excerpt(head, 0, 60),
          title: binary ? `File named .${ext} doesn't look like a .${ext} file` : `File named .${ext} contains text`,
          detail: 'Its first bytes don\'t match the format its name claims. Files that lie about their type are a common hiding place.' })
      }
    }

    // Text rules run on anything that could be executed or parsed as code, even if it contains a NUL
    // byte. (A single NUL used to be enough to make a file look "binary" and skip every rule.)
    if (binary && kind === 'other' && !FONT_EXT.has(ext) && !MAGIC[ext]) continue
    const text = decode(buf)
    if (isLfsPointer(text)) {
      lfs++
      if (kind === 'exec' || CONFIG_FILE.test(base)) {
        findings.add({ id: 'LFS-CODE', severity: 'high', file: rel, title: 'Code stored in Git LFS',
          detail: 'The real contents of this code file live on an LFS server, not in the commit, so they weren\'t scanned and the commit hash doesn\'t vouch for them. git-bouncer clones with LFS downloads switched off; don\'t run `git lfs pull` on code you haven\'t checked.' })
      }
      continue
    }
    for (const hit of matchIocStrings(text, ioc)) {
      findings.add({ id: 'IOC-MATCH', severity: 'critical', file: rel, line: lineOf(text, hit.index), evidence: `${hit.kind}: ${hit.needle}`,
        title: `Contains a known ${hit.campaign} indicator (${hit.kind})`,
        detail: `This exact value appears in public reporting on an active campaign (snapshot ${IOC_SNAPSHOT_DATE}): ${hit.source}` })
    }
    if (MSBUILD_EXT.has(ext) || base === 'packages.config' || base.endsWith('.csproj.user')) {
      for (const m of text.matchAll(/<\s*(?:PackageReference|package)\b[^>]{0,400}?(?:Include|id)\s*=\s*"([^"]{1,200})"/gi)) {
        const c = ioc.nuget.get(m[1].toLowerCase())
        if (c) findings.add({ id: 'IOC-MATCH', severity: 'critical', file: rel, line: lineOf(text, m.index), evidence: `NuGet package: ${m[1]}`,
          title: `References a known-malicious NuGet package (${c.campaign})`, detail: `Reported in public research (snapshot ${IOC_SNAPSHOT_DATE}): ${c.source}` })
      }
    }
    unicodeChecks(rel, text, kind, findings)
    patternChecks(rel, text, ext, base, kind, findings)
  }
  if (lfs) {
    findings.add({ id: 'LFS-POINTERS', severity: 'info', title: `${lfs} file(s) are stored in Git LFS`,
      detail: 'Their real contents weren\'t downloaded or scanned. git-bouncer clones with LFS downloads switched off.' })
  }
  if (stats.truncated) {
    findings.add({ id: 'SCAN-TRUNCATED', severity: 'medium', title: 'Repository too large to scan completely',
      detail: `Scanning stopped after ${MAX_FILES} distinct files or ${MAX_TOTAL_BYTES / 1024 / 1024} MiB. Auto-run locations, config files and code were scanned first; the rest may not have been.` })
  }
  if (stats.skippedLarge) {
    findings.add({ id: 'SCAN-LARGE-FILES', severity: 'info', title: `${stats.skippedLarge} file(s) larger than 2 MiB were only partly scanned`,
      detail: 'The first 2 MiB of each was checked.' })
  }
  return stats
}
