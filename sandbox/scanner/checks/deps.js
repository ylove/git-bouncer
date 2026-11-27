// Dependency checks, run inside the sandbox after the content checks.
//
// Order matters:
//   1. read and neutralize project config that could change how npm behaves (.npmrc)
//   2. review package.json scripts (root and workspaces) and lockfiles statically
//   3. install with --ignore-scripts so npm verifies every tarball's sha512 against the lockfile
//   4. check registry signatures; read every install script npm WOULD run, straight from each
//      package's own package.json (the lockfile's hasInstallScript flag is the source of truth)
//   5. ask OSV about known-malicious packages and known vulnerabilities, one lockfile at a time
//
// Nothing in this file executes code from the repo or its dependencies.

import { open, rename, readdir, stat } from 'node:fs/promises'
import path from 'node:path'
import { run, cleanEnv } from '../proc.js'
import { DOWNLOAD_EXEC } from './content.js'
import { iocIndex, IOC_SNAPSHOT_DATE } from './iocs.js'
import { POPULAR_NPM } from './popular.js'

const REGISTRY = 'https://registry.npmjs.org/'
const REGISTRY_HOSTS = new Set(['registry.npmjs.org', 'registry.yarnpkg.com'])

// npm settings in a project .npmrc that can make npm run a program or fetch from somewhere else,
// even with --ignore-scripts.
const DANGEROUS_NPMRC = new Map([
  ['registry', 'sends every package download to a different server'],
  ['git', 'chooses which program npm runs as "git"'],
  ['node-gyp', 'chooses which program npm runs to build native modules'],
  ['script-shell', 'chooses the shell npm runs scripts with'],
  ['shell', 'chooses the shell used by npm exec/npx'],
  ['node-options', 'passes options (like --require ./payload.js) to every Node process npm starts'],
  ['onload-script', 'runs a script whenever npm loads'],
  ['init-module', 'runs a script on npm init'],
  ['editor', 'chooses a program npm launches'],
  ['browser', 'chooses a program npm launches'],
  ['viewer', 'chooses a program npm launches'],
  ['strict-ssl', 'can turn off TLS certificate checking'],
  ['cafile', 'can make npm trust a different certificate authority'],
  ['ca', 'can make npm trust a different certificate authority'],
  ['proxy', 'routes npm traffic through a different server'],
  ['https-proxy', 'routes npm traffic through a different server'],
])

// Packages whose install scripts are well known and expected (native binaries, prebuilt downloads).
// Only trusted when the package really came from the npm registry. Additions need a reason.
const KNOWN_INSTALL_SCRIPTS = new Set([
  'esbuild', 'sharp', '@swc/core', 'puppeteer', 'bcrypt', 'sqlite3', 'better-sqlite3', 'canvas', 'node-sass',
  'protobufjs', 'core-js', 'core-js-pure', 'es5-ext', 'vue-demi', 'husky', 'nodemon', 'electron', '@prisma/client', 'prisma',
  '@prisma/engines', '@parcel/watcher', 'cypress', 'lefthook', 'msw', 'unrs-resolver', '@biomejs/biome', 'fsevents',
  'node-gyp', 'grpc', '@grpc/grpc-js', 'deasync', 'utf-8-validate', 'bufferutil', 'cpu-features', 'ssh2', 'leveldown',
  'workerd', '@sentry/cli', 'nx', 'playwright', 'playwright-core', 'spawn-sync', 'iltorb', 'nice-napi', 'argon2',
])

// npm runs these on install: the root project's own lifecycle scripts, plus "dependencies" (npm 7+).
const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare', 'prepublish', 'dependencies']
const DEP_LIFECYCLE = ['preinstall', 'install', 'postinstall']
const RUN_SCRIPTS = ['dev', 'start', 'test', 'build', 'serve', 'predev', 'prestart', 'pretest', 'prebuild']
const BENIGN_ROOT_SCRIPT = /^(husky( install)?|is-ci \|\| husky( install)?|npx husky( install)?|lefthook install|simple-git-hooks|patch-package|node-gyp rebuild|ngcc|tsc( -b)?|npm run build|prisma generate|svelte-kit sync|nuxt prepare|nuxi prepare|astro sync|panda codegen)$/

const LOCKFILE_NAMES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock',
  'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'uv.lock', 'pdm.lock', 'packages.lock.json', 'Cargo.lock',
  'go.mod', 'Gemfile.lock', 'composer.lock', 'pubspec.lock', 'mix.lock', 'gradle.lockfile', 'pom.xml'])
/** Compare hosts after parsing; a regex on the raw string would accept https://evil.example/registry.npmjs.org. */
const isRegistryUrl = u => { try { const x = new URL(u); return x.protocol === 'https:' && REGISTRY_HOSTS.has(x.hostname) } catch { return false } }
const KNOWN_PY_INDEXES = /^https:\/\/(download\.pytorch\.org|pypi\.nvidia\.com|data\.pyg\.org)\//

/** Read a whole file (size-capped) through one open handle, so the size check and the read can't diverge. */
async function readText(file, max = 8 * 1024 * 1024) {
  let fh
  try {
    fh = await open(file, 'r')
    const st = await fh.stat()
    if (!st.isFile() || st.size > max) return null
    return await fh.readFile('utf8')
  } catch { return null } finally { await fh?.close() }
}
async function readJson(file) { const t = await readText(file); if (t === null) return null; try { return JSON.parse(t.replace(/^\uFEFF/, '')) } catch { return undefined } }

/** Damerau-Levenshtein (optimal string alignment) distance, capped for speed. */
export function editDistance(a, b, cap = 3) {
  if (Math.abs(a.length - b.length) > cap) return cap + 1
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)])
  for (let j = 1; j <= b.length; j++) d[0][j] = j
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1)
    }
  }
  return Math.min(d[a.length][b.length], cap + 1)
}

const squash = s => s.replace(/[-_.]/g, '')
const scopeOf = s => (s.startsWith('@') ? s.slice(0, s.indexOf('/') + 1) : '')

/** If `name` looks like a misspelling of a popular package, return that package's name. */
export function typosquatOf(name, popular = POPULAR_NPM) {
  if (popular.has(name) || name.length < 4) return null
  const sq = squash(name)
  for (const p of popular) {
    if (squash(p) === sq) return p // crossenv vs cross-env
  }
  for (const p of popular) {
    if (p.length < 5) continue
    // Siblings in the same scope (@aws-sdk/client-sts vs client-sqs) are a family, not a squat.
    if (scopeOf(name) && scopeOf(name) === scopeOf(p)) continue
    const limit = p.length >= 10 ? 2 : 1
    if (editDistance(name, p, limit) <= limit) return p
  }
  return null
}

/** Parse an ini-style .npmrc into [key, value] pairs (keys lowercased, quotes removed like npm does). */
export function parseNpmrc(text) {
  const unquote = s => s.trim().replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1')
  return text.replace(/^\uFEFF/, '').split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#') && !l.startsWith(';') && l.includes('='))
    .map(l => { const i = l.indexOf('='); return [unquote(l.slice(0, i)).toLowerCase(), unquote(l.slice(i + 1))] })
}

function classifyResolved(resolved) {
  if (!resolved || typeof resolved !== 'string') return null
  if (/^(file|link|workspace|portal|patch):/.test(resolved)) return null
  if (/^git(\+ssh|\+https|\+http|\+file)?:|^github:|^gitlab:|^bitbucket:/.test(resolved)) return 'git'
  let u
  try { u = new URL(resolved) } catch { return 'odd' }
  if (u.protocol === 'http:') return 'insecure'
  if (u.protocol !== 'https:') return 'odd'
  if (REGISTRY_HOSTS.has(u.hostname)) return null
  if (u.hostname === 'codeload.github.com') return 'git'
  return 'nonregistry'
}

const newTally = () => ({ insecure: [], nonregistry: [], git: [], odd: [], noIntegrity: 0, sha1Only: 0 })
const note = (t, kind, label) => { t[kind].push(t[kind].length < 5 ? label : null) }

/** Static review of npm/yarn/pnpm lockfiles. Returns every package name seen, and npm's per-package info. */
export async function lockfileChecks(root, findings) {
  const names = new Set()
  const npmEntries = [] // [key, entry] from package-lock v2/v3

  for (const lockName of ['package-lock.json', 'npm-shrinkwrap.json']) {
    const lock = await readJson(path.join(root, lockName))
    if (lock === undefined) {
      findings.add({ id: 'LOCK-UNPARSABLE', severity: 'medium', file: lockName, title: `${lockName} is not valid JSON`,
        detail: 'npm can\'t use a broken lockfile, so the dependency tree couldn\'t be verified.' })
      continue
    }
    if (!lock) continue
    const t = newTally()
    const entries = []
    if (lock.packages && typeof lock.packages === 'object') {
      for (const [key, p] of Object.entries(lock.packages)) {
        if (!key || !p || typeof p !== 'object') continue
        entries.push([p.name || key.split('node_modules/').pop(), p, key])
        npmEntries.push([key, p])
      }
    } else if (lock.dependencies) {
      const walk = deps => { for (const [n, p] of Object.entries(deps || {})) { if (p && typeof p === 'object') { entries.push([n, p, null]); if (p.dependencies) walk(p.dependencies) } } }
      walk(lock.dependencies)
    }
    for (const [name, p] of entries) {
      names.add(name)
      if (p.link || p.bundled || p.inBundle) continue
      // npm v1 lockfiles put tarball/git URLs in "version".
      const where = typeof p.resolved === 'string' ? p.resolved : (typeof p.version === 'string' && /^[a-z+]+:/.test(p.version) ? p.version : null)
      const kind = classifyResolved(where)
      if (kind) note(t, kind, `${name}@${p.version ?? '?'} → ${where.slice(0, 120)}`)
      if (kind === 'git') continue // git dependencies are pinned by commit, not by an integrity hash
      if (where && !p.integrity) t.noIntegrity++
      else if (p.integrity && !/sha(256|384|512)-/.test(p.integrity)) t.sha1Only++
    }
    reportTally(findings, lockName, t)
  }

  const yarn = await readText(path.join(root, 'yarn.lock'))
  if (yarn) {
    const t = newTally()
    for (const m of yarn.matchAll(/^"?(@?[^@\s"]+)@[^\n]*\n((?:[ \t]+[^\n]*\n?)*)/gm)) {
      const name = m[1]
      names.add(name)
      const block = m[2]
      // Yarn classic: resolved "https://...#sha1". Yarn Berry: resolution: "name@npm:1.2.3" or "name@https://...".
      const classic = (block.match(/^\s+resolved\s+"?([^"\n]+)"?/m) || [])[1]
      const berry = (block.match(/^\s+resolution:\s+"?([^"\n]+)"?/m) || [])[1]
      let url = classic ? classic.replace(/#.*$/, '') : null
      if (!url && berry) {
        const at = berry.indexOf('@', 1)
        const spec = at > 0 ? berry.slice(at + 1) : ''
        url = /^(npm|workspace|patch|portal|link|file):/.test(spec) ? null : spec.replace(/^(https?:)/, '$1')
      }
      const kind = classifyResolved(url)
      if (kind) note(t, kind, `${name} → ${url.slice(0, 120)}`)
      if (kind === 'git') continue
      if (url && /:\/\//.test(url) && !/^\s+(integrity|checksum)\s|^\s+checksum:/m.test(block)) t.noIntegrity++
    }
    reportTally(findings, 'yarn.lock', t)
  }

  const pnpm = await readText(path.join(root, 'pnpm-lock.yaml'))
  if (pnpm) {
    const t = newTally()
    for (const m of pnpm.matchAll(/^\s{2,4}'?\/?(@?[^@\s':]+)@([^:\n']*)'?:\n((?:\s{4,}[^\n]*\n?)*)/gm)) {
      names.add(m[1])
      // pnpm v9 keys URL-installed packages by URL ("pkg@https://..."); older versions use tarball: lines.
      const tarball = (m[3].match(/tarball:\s*'?([^'\s},]+)/) || [])[1] || (/^(https?|git)/.test(m[2]) ? m[2] : null)
      const kind = classifyResolved(tarball)
      if (kind) note(t, kind, `${m[1]} → ${tarball.slice(0, 120)}`)
    }
    reportTally(findings, 'pnpm-lock.yaml', t)
  }
  return { names, npmEntries }
}

function reportTally(findings, file, t) {
  const show = list => list.filter(Boolean).join('; ') + (list.length > 5 ? ` (+${list.length - 5} more)` : '')
  if (t.insecure.length) findings.add({ id: 'LOCK-RESOLVED-INSECURE', severity: 'high', file, evidence: show(t.insecure),
    title: `${t.insecure.length} package(s) download over plain http`,
    detail: 'Anyone on the network path can replace these packages in transit. Registry packages always use https.' })
  if (t.nonregistry.length) findings.add({ id: 'LOCK-RESOLVED-NONREGISTRY', severity: 'medium', file, evidence: show(t.nonregistry),
    title: `${t.nonregistry.length} package(s) come from outside the npm registry`,
    detail: 'Packages downloaded from arbitrary servers skip the registry\'s malware takedowns and signatures. A swapped lockfile URL is a known supply-chain trick.' })
  if (t.git.length) findings.add({ id: 'LOCK-RESOLVED-GIT', severity: 'low', file, evidence: show(t.git),
    title: `${t.git.length} package(s) installed straight from git`,
    detail: 'Git dependencies aren\'t covered by registry signatures, and npm runs their "prepare" script when installed normally.' })
  if (t.odd.length) findings.add({ id: 'LOCK-RESOLVED-ODD', severity: 'medium', file, evidence: show(t.odd),
    title: `${t.odd.length} package(s) have an unusual download location`, detail: 'The lockfile points at something that isn\'t a normal https URL.' })
  if (t.noIntegrity) findings.add({ id: 'LOCK-MISSING-INTEGRITY', severity: 'medium', file, evidence: `${t.noIntegrity} package(s)`,
    title: 'Lockfile entries without an integrity hash',
    detail: 'Without an integrity hash nothing checks that the downloaded package is the one that was locked.' })
  if (t.sha1Only) findings.add({ id: 'LOCK-WEAK-INTEGRITY', severity: 'low', file, evidence: `${t.sha1Only} package(s)`,
    title: 'Lockfile entries pinned only with SHA-1', detail: 'SHA-1 is no longer collision-resistant. Modern lockfiles use sha512.' })
}

/** Find lockfiles (not inside node_modules), shallowest first, for OSV. */
async function findLockfiles(root, depth = 4) {
  const out = []
  const queue = [['', depth]]
  while (queue.length) {
    const [rel, d] = queue.shift() // breadth-first: the root lockfile always comes first
    let entries
    try { entries = await readdir(path.join(root, rel), { withFileTypes: true }) } catch { continue }
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name
      if (e.isDirectory()) {
        if (d > 0 && !['node_modules', '.git', 'vendor', '.venv', 'venv'].includes(e.name)) queue.push([r, d - 1])
      } else if (e.isFile() && (LOCKFILE_NAMES.has(e.name) || /^requirements[\w.-]*\.txt$/.test(e.name))) out.push(r)
    }
  }
  return out
}

function cvssBucket(score) {
  const n = Number.parseFloat(score)
  if (!Number.isFinite(n)) return 'unknown'
  return n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : 'low'
}

const MAX_OSV_LOCKFILES = 25

// --no-resolve: never resolve transitive dependencies of manifest-only files (pom.xml, requirements.txt, ...).
// Resolution downloads metadata from wherever the manifest says (a pom.xml <repositories> URL, a parent
// POM), so the repo could steer the sandbox at any server it likes, including the host's own 127.0.0.1
// through host.docker.internal. Manifests are matched on the versions they declare instead.
export const OSV_ARGS = (osvConfig, lockfile) => ['scan', 'source', '--format', 'json', '--no-resolve', '--config', osvConfig, '-L', lockfile]

/** osv-scanner, one lockfile per run (one bad file can't sink the rest), always with OUR config file. */
async function osvChecks(root, lockfiles, findings, { osvBin, osvConfig }) {
  if (!lockfiles.length) return { ran: false, reason: 'no lockfiles or manifests found' }
  const malware = []
  const vulnPkgs = new Map()
  const buckets = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  let ok = 0
  const failed = []
  for (const l of lockfiles.slice(0, MAX_OSV_LOCKFILES)) {
    const r = await run(osvBin, OSV_ARGS(osvConfig, l), { cwd: root, timeoutMs: 5 * 60 * 1000 })
    let data = null
    if (r.code === 0 || r.code === 1) { try { data = JSON.parse(r.stdout) } catch { data = null } }
    if (r.code === 128) { ok++; continue } // "no packages found" in this file
    if (!data) { failed.push(l); continue }
    ok++
    for (const res of data.results || []) {
      for (const p of res.packages || []) {
        const label = `${p.package?.name}@${p.package?.version} (${p.package?.ecosystem})`
        const vulns = p.vulnerabilities || []
        const mal = vulns.filter(v => String(v.id).startsWith('MAL-') || (v.aliases || []).some(a => String(a).startsWith('MAL-')))
        if (mal.length) malware.push(`${label}: ${mal.map(v => v.id).join(', ')}`)
        const groups = (p.groups || []).filter(g => !(g.ids || []).some(id => String(id).startsWith('MAL-')))
        if (groups.length) {
          vulnPkgs.set(label, groups.map(g => g.ids?.[0]).filter(Boolean))
          for (const g of groups) buckets[cvssBucket(g.max_severity)]++
        }
      }
    }
  }
  if (lockfiles.length > MAX_OSV_LOCKFILES) {
    findings.add({ id: 'DEP-OSV-PARTIAL', severity: 'medium', title: `Only ${MAX_OSV_LOCKFILES} of ${lockfiles.length} lockfiles were checked against OSV`,
      detail: 'The root lockfile and the shallowest ones were checked first. Deeper ones were not checked for known malware.' })
  }
  if (failed.length) {
    findings.add({ id: 'DEP-OSV-UNAVAILABLE', severity: 'medium', evidence: failed.slice(0, 5).join(', '),
      title: ok ? `Known-malware check failed for ${failed.length} lockfile(s)` : 'Known-malware check could not run',
      detail: 'osv-scanner (the known-malicious and known-vulnerable package lookup) failed for these files, so that part of the check is missing. Treat the result as incomplete.' })
  }
  for (const m of malware.slice(0, 25)) {
    findings.add({ id: 'DEP-MALWARE', severity: 'critical', evidence: m, title: 'Known-malicious package in the dependency tree',
      detail: 'This exact package version is in the OSV malicious-packages database (OpenSSF). Installing it runs malware.' })
  }
  if (vulnPkgs.size) {
    const total = Object.values(buckets).reduce((a, b) => a + b, 0)
    const top = [...vulnPkgs.entries()].slice(0, 4).map(([k, ids]) => `${k}: ${ids.slice(0, 2).join(', ')}`).join('; ')
    // Low on purpose: the verdict answers "will this repo attack me?", and an ordinary CVE answers "is this
    // app vulnerable?". The counts stay in the title so a critical CVE is still visible at a glance.
    findings.add({ id: 'DEP-VULN', severity: 'low', evidence: top,
      title: `${total} known vulnerabilit${total === 1 ? 'y' : 'ies'} in ${vulnPkgs.size} package(s) (${buckets.critical} critical, ${buckets.high} high)`,
      detail: 'These are ordinary security bugs (CVEs), not malware: they make the app vulnerable, not your machine at install time. Worth knowing before you build on it or deploy it.' })
  }
  return { ran: ok > 0, lockfiles: Math.min(lockfiles.length, MAX_OSV_LOCKFILES) }
}

/** Follow "npm run x" / "yarn x" / "pnpm x" one level, so `prepare: npm run build` shows what build does. */
function expandScript(cmd, scripts) {
  const m = cmd.match(/^(?:npm run(?:-script)?|yarn(?: run)?|pnpm(?: run)?|bun run)\s+([\w:.-]+)/)
  const target = m && typeof scripts[m[1]] === 'string' ? scripts[m[1]] : null
  return target ? `${cmd}  →  ${m[1]}: ${target}` : cmd
}

/** Lifecycle scripts of one package.json (the root, or a workspace that npm installs with it). */
async function lifecycleFindings(dir, rel, pkg, findings) {
  const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts : {}
  const file = rel ? `${rel}/package.json` : 'package.json'
  for (const name of LIFECYCLE) {
    const raw = scripts[name]
    if (typeof raw !== 'string') continue
    const cmd = expandScript(raw, scripts)
    const dangerous = DOWNLOAD_EXEC.test(cmd)
    const hooks = /core\.hooksPath/.test(cmd)
    findings.add({
      id: dangerous ? 'SCRIPT-ROOT-DANGEROUS' : 'SCRIPT-ROOT-LIFECYCLE',
      severity: dangerous ? 'high' : hooks ? 'medium' : BENIGN_ROOT_SCRIPT.test(raw.trim()) ? 'low' : 'medium',
      file, evidence: `${name}: ${cmd.slice(0, 220)}`,
      title: `"${name}" script runs automatically on install${rel ? ` (workspace ${rel})` : ''}`,
      detail: dangerous
        ? 'This script downloads or decodes something and runs it the moment you run npm install. That is the most common way malicious repos attack.'
        : hooks ? 'It points git at a hooks folder inside the repo, so its scripts run on every commit from then on.'
          : 'npm runs this automatically during install. It may be fine; read it before installing on your machine.',
    })
  }
  // A binding.gyp means npm runs `node-gyp rebuild` on install, even with no install script listed.
  const gyp = await readText(path.join(dir, 'binding.gyp'), 1024 * 1024)
  if (gyp !== null && typeof scripts.install !== 'string' && typeof scripts.preinstall !== 'string') {
    const expand = /<!@?\(/.test(gyp) // gyp command expansion: runs a shell command while configuring
    findings.add({ id: expand ? 'SCRIPT-ROOT-DANGEROUS' : 'SCRIPT-ROOT-LIFECYCLE', severity: expand ? 'high' : 'medium', file: rel ? `${rel}/binding.gyp` : 'binding.gyp',
      evidence: expand ? (gyp.match(/<!@?\([^)]{0,160}/) || [''])[0] : 'binding.gyp',
      title: expand ? 'binding.gyp runs shell commands during install' : 'npm compiles native code (node-gyp) on install',
      detail: 'A binding.gyp file makes npm run `node-gyp rebuild` during install. Its <!(...) syntax runs arbitrary shell commands.' })
  }
}

/** Workspace folders listed in package.json ("packages/*" style globs, one level). */
async function workspaceDirs(root, pkg) {
  const globs = Array.isArray(pkg.workspaces) ? pkg.workspaces : Array.isArray(pkg.workspaces?.packages) ? pkg.workspaces.packages : []
  const out = []
  for (const g of globs.slice(0, 50)) {
    if (typeof g !== 'string' || g.includes('..') || g.startsWith('/')) continue
    if (g.endsWith('/*')) {
      const base = g.slice(0, -2)
      try { for (const e of await readdir(path.join(root, base), { withFileTypes: true })) if (e.isDirectory()) out.push(`${base}/${e.name}`) } catch { /* missing */ }
    } else if (!g.includes('*')) out.push(g.replace(/\/$/, ''))
  }
  return out.slice(0, 200)
}

/**
 * All dependency checks. Mutates nothing outside `root`.
 * @returns {Promise<{kind: string, lockfile: string|null, generatedLockfile: boolean, installed: boolean, osv: object}>}
 */
export async function dependencyChecks(root, findings, { osvBin = 'osv-scanner', osvConfig = '/opt/bouncer/osv-scanner.toml', skipInstall = false, dryRun = false } = {}) {
  const ioc = iocIndex()
  const pm = { kind: 'none', lockfile: null, generatedLockfile: false, analysisLockfile: false, installed: false, osv: null }

  // 1. Project config that changes how package managers behave. Read it, report it, then move it out of
  //    the way. Names are matched case-insensitively (".NPMRC" is ".npmrc" on macOS and Windows).
  const rootNames = new Map((await readdir(root).catch(() => [])).map(n => [n.toLowerCase(), n]))
  for (const lower of ['.npmrc', '.yarnrc', '.yarnrc.yml']) {
    const rc = rootNames.get(lower)
    if (!rc) continue
    const text = await readText(path.join(root, rc))
    if (text === null) continue
    if (lower === '.yarnrc') {
      // Yarn classic: `yarn-path "./x.js"` makes every yarn command run that file.
      const yp = text.match(/^\s*yarn-path\s+["']?([^"'\n]+)/m)
      if (yp) findings.add({ id: 'YARN-PATH', severity: 'high', file: rc, evidence: yp[1].trim().slice(0, 120),
        title: 'Running yarn here executes a JavaScript file from the repo',
        detail: '`yarn-path` in .yarnrc makes every yarn command (even `yarn --version`) run this file instead of Yarn.' })
    }
    if (lower === '.yarnrc.yml') {
      const yp = text.match(/^\s*yarnPath:\s*["']?([^"'\n]+)/m)
      if (yp) {
        // Medium even for the standard .yarn/releases/yarn-x.y.z.cjs path: the file at that path is whatever
        // the repo committed, and nothing checks it against a real Yarn release.
        findings.add({ id: 'YARN-PATH', severity: 'medium', file: rc, evidence: yp[1].trim().slice(0, 120),
          title: 'Running yarn here executes a JavaScript file from the repo',
          detail: '`yarnPath` makes every yarn command (even `yarn --version`) run this file from the repo instead of the Yarn you installed. Yarn Berry projects commonly ship one at .yarn/releases/yarn-x.y.z.cjs, but the path proves nothing: the file is repo-controlled code, it was not compared with a real Yarn release, and it runs with your permissions the moment you type `yarn`.' })
      }
      const reg = text.match(/^\s*npmRegistryServer:\s*["']?([^"'\s]+)/m)
      if (reg && !isRegistryUrl(reg[1])) findings.add({ id: 'NPMRC-OVERRIDE', severity: 'high', file: rc, evidence: `npmRegistryServer: ${reg[1].slice(0, 100)}`,
        title: 'Yarn is pointed at a different package registry', detail: 'Every package would be downloaded from this server instead of the npm registry.' })
      continue
    }
    const risky = []
    const scoped = []
    for (const [key, value] of parseNpmrc(text)) {
      const bare = key.replace(/^@[^:]+:/, '')
      // npm expands ${VAR} from YOUR environment. Aimed at a server other than the npm registry, that
      // sends your token (GITHUB_TOKEN, NPM_TOKEN, ...) to whoever runs that server.
      const envRef = value.match(/\$\{([A-Za-z0-9_]+)\}/)
      const host = (key.match(/^\/\/([^/:]+)/) || [])[1]
      if (envRef && !(host && REGISTRY_HOSTS.has(host))) {
        findings.add({ id: 'NPMRC-ENV-EXFIL', severity: 'high', file: rc, evidence: `${key}=... ${envRef[1]}`,
          title: `.npmrc would send your ${envRef[1]} ${host ? `to ${host}` : 'with npm requests'}`,
          detail: 'npm fills in ${VARIABLES} from your own environment. A repo that points one at its own server can collect tokens from anyone who runs npm install.' })
        continue
      }
      if (/(^|:)_auth(token)?$/.test(key)) {
        if (/^\$\{[A-Z0-9_]+\}$/.test(value)) continue // ${NPM_TOKEN} for the npm registry: a placeholder, not a secret
        findings.add({ id: 'NPMRC-TOKEN', severity: 'medium', file: rc, title: 'An npm auth token is committed to the repo',
          detail: 'Someone leaked a credential here. Not an attack on you, but a sign of poor hygiene, and possibly a stolen token.' })
        continue
      }
      if (bare === 'registry' && /^https:\/\/registry\.npmjs\.org\/?$/.test(value)) continue
      if (bare === 'strict-ssl' && value === 'true') continue
      if (bare === 'registry' && key.startsWith('@')) { scoped.push(`${key}=${value}`); continue }
      if (DANGEROUS_NPMRC.has(bare)) risky.push(`${key} (${DANGEROUS_NPMRC.get(bare)})`)
    }
    if (risky.length) {
      findings.add({ id: 'NPMRC-OVERRIDE', severity: 'high', file: rc, evidence: risky.slice(0, 4).join('; ').slice(0, 240),
        title: `Project ${rc} changes how npm downloads or runs programs`,
        detail: 'npm reads this file automatically in the project folder. These settings can redirect downloads or make npm run arbitrary programs even with --ignore-scripts. It was moved aside inside the sandbox; on your machine it would apply.' })
    }
    if (scoped.length) {
      findings.add({ id: 'NPMRC-SCOPED-REGISTRY', severity: 'medium', file: rc, evidence: scoped.slice(0, 3).join('; ').slice(0, 200),
        title: 'Some packages come from a third-party registry',
        detail: 'Packages in these scopes are downloaded from another server (common for paid packages like Font Awesome Pro). Make sure you recognize it.' })
    }
    if (!dryRun) await rename(path.join(root, rc), path.join(root, `${rc}.bouncer-disabled`)).catch(() => {})
  }
  // pnpm runs .pnpmfile.cjs on every install, even with --ignore-scripts; bunfig.toml can preload scripts.
  const pnpmfile = rootNames.get('.pnpmfile.cjs') || rootNames.get('.pnpmfile.mjs')
  if (pnpmfile) {
    const t = (await readText(path.join(root, pnpmfile))) ?? ''
    findings.add({ id: 'PNPMFILE', severity: DOWNLOAD_EXEC.test(t) || /child_process/.test(t) ? 'high' : 'medium', file: pnpmfile,
      title: 'pnpm runs code from this repo on every install',
      detail: '.pnpmfile.cjs hooks run whenever pnpm installs, even with --ignore-scripts. Read it before running pnpm here.' })
  }
  const bunfig = rootNames.get('bunfig.toml')
  if (bunfig && /^\s*preload\s*=/m.test((await readText(path.join(root, bunfig))) ?? '')) {
    findings.add({ id: 'BUNFIG-PRELOAD', severity: 'medium', file: bunfig, title: 'bunfig.toml preloads scripts',
      detail: '`preload` makes bun run these files before your code (and before tests).' })
  }

  // 2. package.json scripts (root + workspaces) and direct dependencies.
  const pkg = await readJson(path.join(root, 'package.json'))
  const directDeps = new Set()
  if (pkg && typeof pkg === 'object') {
    pm.kind = 'npm'
    await lifecycleFindings(root, '', pkg, findings)
    for (const ws of await workspaceDirs(root, pkg)) {
      const wpkg = await readJson(path.join(root, ws, 'package.json'))
      if (wpkg && typeof wpkg === 'object') await lifecycleFindings(path.join(root, ws), ws, wpkg, findings)
    }
    const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts : {}
    for (const name of RUN_SCRIPTS) {
      const cmd = typeof scripts[name] === 'string' ? expandScript(scripts[name], scripts) : null
      if (cmd && DOWNLOAD_EXEC.test(cmd)) {
        findings.add({ id: 'SCRIPT-RUN-DANGEROUS', severity: 'medium', file: 'package.json', evidence: `${name}: ${cmd.slice(0, 200)}`,
          title: `"npm run ${name}" downloads or decodes something and runs it`,
          detail: 'Take-home tests tell you to run "npm run dev" or "npm test". Read what that actually does first.' })
      }
    }
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [name, spec] of Object.entries(pkg[field] || {})) {
        if (typeof spec !== 'string') continue
        // "alias": "npm:real-name@1.2.3" installs real-name under another name; check the real one.
        const alias = spec.match(/^npm:((?:@[^/@]+\/)?[^@]+)/)
        directDeps.add(alias ? alias[1] : name)
        if (/^(https?:|git|github:|gitlab:|bitbucket:|file:\/)/.test(spec) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec)) {
          findings.add({ id: 'DEP-SPEC-URL', severity: spec.startsWith('http:') ? 'high' : 'low', file: 'package.json', evidence: `${name}: ${spec.slice(0, 160)}`,
            title: `"${name}" is installed from a URL or git, not the registry`, detail: 'URL and git dependencies skip registry signatures and malware takedowns.' })
        }
      }
    }
  }

  // 3. Static lockfile review.
  const { names, npmEntries } = await lockfileChecks(root, findings)
  for (const n of directDeps) names.add(n)
  const exists = async f => Boolean(await stat(path.join(root, f)).catch(() => null))
  for (const f of ['yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb']) {
    if (await exists(f)) { pm.kind = f.startsWith('yarn') ? 'yarn' : f.startsWith('pnpm') ? 'pnpm' : 'bun'; pm.lockfile = f; break }
  }
  const npmLock = (await exists('npm-shrinkwrap.json')) ? 'npm-shrinkwrap.json' : (await exists('package-lock.json')) ? 'package-lock.json' : null
  if (npmLock) { pm.kind = 'npm'; pm.lockfile = npmLock }

  // 4. Known-bad package names (IOC snapshot) and typosquats.
  for (const n of names) {
    const c = ioc.npm.get(n)
    if (c) findings.add({ id: 'IOC-MATCH', severity: 'critical', evidence: `npm package: ${n}`, title: `Depends on a package named in ${c.campaign} reporting`,
      detail: `Reported in public research (snapshot ${IOC_SNAPSHOT_DATE}): ${c.source}` })
  }
  for (const n of directDeps) {
    const like = typosquatOf(n)
    if (like) findings.add({ id: 'DEP-TYPOSQUAT', severity: 'medium', file: 'package.json', evidence: `${n} ≈ ${like}`,
      title: `"${n}" looks like a misspelling of "${like}"`,
      detail: 'Typosquatting packages copy a popular name with one letter changed and add malware. Check that this is really the package the author meant.' })
  }

  // 5. Install with scripts disabled, so npm verifies checksums without running anything. Every
  //    project with a package.json gets an npm-resolved tree to analyze; for npm projects without a
  //    lockfile it's also the exact tree the host will install.
  let lockEntries = npmEntries
  // Don't let the repo choose which servers the sandbox talks to: if anything would be downloaded from
  // outside the registry (or GitHub, for git dependencies), npm isn't run at all. The lockfile findings
  // above already say why.
  const offRegistryUrl = u => {
    const k = classifyResolved(u)
    if (k === null) return false
    if (k !== 'git') return true
    return !/^(git\+)?(https:\/\/|ssh:\/\/git@|git@)?(github\.com|codeload\.github\.com)[/:]|^github:/.test(u)
  }
  const offRegistry = npmEntries.some(([, e]) => e && !e.link && offRegistryUrl(e.resolved)) ||
    findings.items.some(f => ['LOCK-RESOLVED-INSECURE', 'LOCK-RESOLVED-NONREGISTRY', 'LOCK-RESOLVED-ODD'].includes(f.id)) ||
    findings.items.some(f => f.id === 'DEP-SPEC-URL' && !/(github\.com|github:|^[^:]+: [\w.-]+\/[\w.-]+)/.test(f.evidence || ''))
  if (offRegistry && pkg && !skipInstall) {
    findings.add({ id: 'DEP-INSTALL-SKIPPED', severity: 'medium', title: 'Dependencies were not installed in the sandbox',
      detail: 'Some packages would be downloaded from servers outside the npm registry, so the sandbox did not contact them. Checksum and signature checks were skipped; install scripts were read from the lockfile where possible.' })
  }
  if (pkg && typeof pkg === 'object' && !skipInstall && !offRegistry) {
    const npmEnv = cleanEnv({ npm_config_ignore_scripts: 'true', npm_config_registry: REGISTRY, npm_config_audit: 'false', npm_config_fund: 'false' })
    const common = ['--ignore-scripts', '--no-audit', '--no-fund', `--registry=${REGISTRY}`, '--loglevel=error']
    const args = npmLock ? ['ci', ...common] : ['install', ...common, '--package-lock=true']
    let r = await run('npm', args, { cwd: root, env: npmEnv, timeoutMs: 15 * 60 * 1000 })
    if (r.code !== 0 && /EBADPLATFORM|EBADDEVENGINES|EBADENGINE|notsup/i.test(r.stderr)) {
      // The repo says it only installs on another OS or toolchain; check the tree anyway.
      findings.add({ id: 'DEP-PLATFORM-RESTRICTED', severity: 'low', title: 'The project refuses to install on Linux',
        detail: 'Its package.json restricts the operating system or toolchain. The sandbox installed it anyway (with --force) to check the dependencies.' })
      r = await run('npm', [...args, '--force'], { cwd: root, env: npmEnv, timeoutMs: 15 * 60 * 1000 })
    }
    const err = r.stderr
    if (r.code === 0) {
      pm.installed = true
      if (!npmLock) {
        if (pm.kind === 'npm') { pm.lockfile = 'package-lock.json'; pm.generatedLockfile = true } else pm.analysisLockfile = true
        const gen = await readJson(path.join(root, 'package-lock.json'))
        if (gen && gen.packages) lockEntries = Object.entries(gen.packages)
      }
    } else if (/EINTEGRITY|integrity checksum failed|sha512-.* integrity/i.test(err)) {
      findings.add({ id: 'DEP-INTEGRITY-MISMATCH', severity: 'critical', file: pm.lockfile, evidence: (err.match(/[^\n]*(EINTEGRITY|integrity)[^\n]*/i) || [''])[0].slice(0, 240),
        title: 'A downloaded package does not match its checksum in the lockfile',
        detail: 'The lockfile says a package should have one hash and the registry served a different one. Either the lockfile was tampered with or the package was swapped. Do not install this.' })
    } else if (/can only install packages when your package\.json and package-lock\.json|are in sync/i.test(err)) {
      findings.add({ id: 'LOCK-OUT-OF-SYNC', severity: 'medium', file: pm.lockfile, title: 'package.json and package-lock.json disagree',
        detail: 'npm ci refuses to install when the lockfile doesn\'t match package.json, so the exact tree couldn\'t be verified. A lockfile edited by hand can hide a swapped dependency.' })
    } else {
      findings.add({ id: 'DEP-INSTALL-FAILED', severity: 'medium', evidence: err.trim().split('\n').slice(-2).join(' ').slice(0, 240),
        title: r.timedOut ? 'Dependency install timed out in the sandbox' : 'Dependencies could not be installed in the sandbox',
        detail: 'Checksum and signature checks need the dependency tree, so those checks are incomplete. Install scripts were still read from the lockfile where possible.' })
    }
  }

  if (pm.installed) {
    // 6a. Registry signatures and provenance attestations.
    const sig = await run('npm', ['audit', 'signatures', '--json', `--registry=${REGISTRY}`], { cwd: root, env: cleanEnv({ npm_config_registry: REGISTRY }), timeoutMs: 5 * 60 * 1000 })
    let sigData = null
    try { sigData = JSON.parse(sig.stdout) } catch { /* handled below */ }
    if (sigData && Array.isArray(sigData.invalid) && sigData.invalid.length) {
      findings.add({ id: 'DEP-SIGNATURE-INVALID', severity: 'critical', evidence: sigData.invalid.slice(0, 5).map(p => `${p.name}@${p.version}`).join(', '),
        title: `${sigData.invalid.length} package(s) have an invalid registry signature`,
        detail: 'The npm registry signs every package. An invalid signature means what you downloaded is not what the registry published.' })
    } else if (!sigData && sig.code !== 0 && !/no dependencies to audit/i.test(sig.stderr)) {
      findings.add({ id: 'DEP-SIGNATURES-UNCHECKED', severity: 'low', title: 'Registry signatures could not be checked', evidence: sig.stderr.trim().split('\n').pop()?.slice(0, 200) })
    }
  }

  // 6b. Every dependency install script npm would run. npm only runs scripts for lockfile entries marked
  //     hasInstallScript (including implicit node-gyp builds), so that flag is the source of truth, and
  //     the script text comes from the package's own package.json. Platform-specific packages that weren't
  //     installed in the sandbox are still listed.
  const known = []
  for (const [key, entry] of lockEntries) {
    if (!key || !entry || entry.hasInstallScript !== true || entry.link) continue
    const name = entry.name || key.split('node_modules/').pop()
    const fromRegistry = typeof entry.resolved === 'string' && /^https:\/\/registry\.npmjs\.org\//.test(entry.resolved)
    const dpkg = /^[\w@./-]+$/.test(key) && !key.includes('..') ? await readJson(path.join(root, key, 'package.json')) : null
    const s = dpkg && typeof dpkg.scripts === 'object' && dpkg.scripts ? dpkg.scripts : null
    const cmd = s ? DEP_LIFECYCLE.filter(k => typeof s[k] === 'string').map(k => `${k}: ${s[k]}`).join(' ; ') : ''
    const gyp = !cmd && dpkg ? await readText(path.join(root, key, 'binding.gyp'), 1024 * 1024) : null
    const shown = cmd || (gyp !== null ? 'node-gyp rebuild (implicit, from binding.gyp)' : '')
    const dangerous = DOWNLOAD_EXEC.test(cmd) || (gyp !== null && /<!@?\(/.test(gyp))
    if (KNOWN_INSTALL_SCRIPTS.has(name) && fromRegistry && !dangerous) { known.push(`${name}@${entry.version}`); continue }
    findings.add({
      id: dangerous ? 'DEP-INSTALL-SCRIPT-DANGEROUS' : 'DEP-INSTALL-SCRIPT',
      severity: dangerous ? 'high' : 'medium',
      evidence: `${name}@${entry.version ?? '?'} ${shown || '(script not readable: package not installed in the sandbox)'}`.slice(0, 240),
      title: `Dependency "${name}" runs a script on install`,
      detail: dangerous
        ? 'This dependency downloads or decodes something and runs it during install. Malicious packages almost always work this way.'
        : 'Install scripts run with your user\'s full permissions. This one isn\'t on the list of well-known native packages from the npm registry; read it before installing with scripts enabled.',
    })
  }
  if (known.length) findings.add({ id: 'DEP-INSTALL-SCRIPT-KNOWN', severity: 'info', evidence: known.slice(0, 8).join(', '),
    title: `${known.length} well-known package(s) with install scripts`, detail: 'Packages like esbuild and sharp download prebuilt binaries on install. Expected.' })

  // 7. OSV: known-malicious packages and known vulnerabilities, for every ecosystem's lockfile.
  let lockfiles = await findLockfiles(root)
  // The npm-resolved analysis tree is only useful to OSV when the project's own lockfile can't be read.
  if (pm.analysisLockfile && pm.kind !== 'bun') lockfiles = lockfiles.filter(l => l !== 'package-lock.json')
  for (const l of lockfiles.filter(f => /requirements[\w.-]*\.txt$/.test(f))) {
    const text = await readText(path.join(root, l))
    const m = text && text.match(/^\s*(-i|--index-url|--extra-index-url|--trusted-host|-f|--find-links)\b\s*=?\s*(\S*)/m)
    if (m) {
      const knownIndex = KNOWN_PY_INDEXES.test(m[2] || '')
      findings.add({ id: 'PY-INDEX-OVERRIDE', severity: knownIndex ? 'low' : 'medium', file: l, evidence: m[0].trim().slice(0, 160),
        title: 'requirements file adds or replaces the Python package index',
        detail: knownIndex
          ? 'A well-known vendor index (for example PyTorch\'s). Still, pip may take a same-named package from whichever index offers the higher version.'
          : '--extra-index-url is the classic "dependency confusion" setup: pip may pick a same-named package from whichever index offers the higher version.' })
    }
  }
  pm.osv = await osvChecks(root, lockfiles, findings, { osvBin, osvConfig })
  if (!pm.osv.ran && pkg && !skipInstall && lockfiles.length === 0) {
    findings.add({ id: 'DEP-OSV-UNAVAILABLE', severity: 'medium', title: 'Known-malware check had nothing to check',
      detail: 'No lockfile could be read or generated, so dependencies were not checked against the known-malware database.' })
  }
  return pm
}
