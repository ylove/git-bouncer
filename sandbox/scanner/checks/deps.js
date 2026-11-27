// Dependency checks, run inside the sandbox after the content checks.
//
// Order matters:
//   1. read and neutralize project config that could change how npm behaves (.npmrc)
//   2. review lockfiles statically (where packages come from, whether they're pinned by hash)
//   3. install with --ignore-scripts so npm verifies every tarball's sha512 against the lockfile
//   4. check registry signatures, list every install script in the tree
//   5. ask OSV about known-malicious packages and known vulnerabilities, for every lockfile found
//
// Nothing in this file executes code from the repo or its dependencies.

import { readFile, rename, readdir, stat } from 'node:fs/promises'
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
])

// Packages whose install scripts are well known and expected (native binaries, prebuilt downloads).
// Listing them as "info" instead of "warning" keeps real surprises visible. Additions need a reason.
const KNOWN_INSTALL_SCRIPTS = new Set([
  'esbuild', 'sharp', '@swc/core', 'puppeteer', 'bcrypt', 'sqlite3', 'better-sqlite3', 'canvas', 'node-sass',
  'protobufjs', 'core-js', 'core-js-pure', 'es5-ext', 'husky', 'nodemon', 'electron', '@prisma/client', 'prisma',
  '@prisma/engines', '@parcel/watcher', 'cypress', 'lefthook', 'msw', 'unrs-resolver', '@biomejs/biome', 'fsevents',
  'node-gyp', 'grpc', '@grpc/grpc-js', 'deasync', 'utf-8-validate', 'bufferutil', 'cpu-features', 'ssh2', 'leveldown',
  'workerd', '@sentry/cli', 'nx', '@nx/nx-darwin-arm64', 'playwright', 'playwright-core', 'spawn-sync', 'iltorb',
])

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare', 'prepublish']
const RUN_SCRIPTS = ['dev', 'start', 'test', 'build', 'serve', 'predev', 'prestart', 'pretest', 'prebuild']

const LOCKFILE_NAMES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock',
  'requirements.txt', 'poetry.lock', 'Pipfile.lock', 'uv.lock', 'pdm.lock', 'packages.lock.json', 'Cargo.lock',
  'go.mod', 'Gemfile.lock', 'composer.lock', 'pubspec.lock', 'mix.lock', 'gradle.lockfile', 'pom.xml'])

async function readText(file) { try { return await readFile(file, 'utf8') } catch { return null } }
async function readJson(file) { const t = await readText(file); if (t === null) return null; try { return JSON.parse(t) } catch { return undefined } }

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

/** If `name` looks like a misspelling of a popular package, return that package's name. */
export function typosquatOf(name, popular = POPULAR_NPM) {
  if (popular.has(name) || name.length < 4) return null
  const sq = squash(name)
  for (const p of popular) {
    if (squash(p) === sq) return p // crossenv vs cross-env
  }
  for (const p of popular) {
    if (p.length < 5) continue
    const limit = p.length >= 10 ? 2 : 1
    if (editDistance(name, p, limit) <= limit) return p
  }
  return null
}

/** Parse an ini-style .npmrc into [key, value] pairs (keys lowercased, scopes kept). */
export function parseNpmrc(text) {
  return text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#') && !l.startsWith(';') && l.includes('='))
    .map(l => { const i = l.indexOf('='); return [l.slice(0, i).trim().toLowerCase(), l.slice(i + 1).trim()] })
}

function classifyResolved(resolved) {
  if (!resolved || typeof resolved !== 'string') return null
  if (/^(file|link|workspace|portal|patch):/.test(resolved)) return null
  if (/^git(\+ssh|\+https|\+http)?:|^github:|^gitlab:|^bitbucket:/.test(resolved)) return 'git'
  let u
  try { u = new URL(resolved) } catch { return 'odd' }
  if (u.protocol === 'http:') return 'insecure'
  if (u.protocol !== 'https:') return 'odd'
  if (REGISTRY_HOSTS.has(u.hostname)) return null
  if (u.hostname === 'codeload.github.com') return 'git'
  return 'nonregistry'
}

/** Static review of npm/yarn/pnpm lockfiles. Returns every package name seen (for IOC + typosquat checks). */
export async function lockfileChecks(root, findings) {
  const names = new Set()
  const tally = { insecure: [], nonregistry: [], git: [], odd: [], noIntegrity: 0, sha1Only: 0 }
  const note = (kind, label, where) => { if (tally[kind] && tally[kind].length < 5) tally[kind].push(`${label} → ${where}`); else if (tally[kind]) tally[kind].push(null) }

  for (const lockName of ['package-lock.json', 'npm-shrinkwrap.json']) {
    const lock = await readJson(path.join(root, lockName))
    if (lock === undefined) {
      findings.add({ id: 'LOCK-UNPARSABLE', severity: 'medium', file: lockName, title: `${lockName} is not valid JSON`,
        detail: 'npm can\'t use a broken lockfile, so the dependency tree couldn\'t be verified.' })
      continue
    }
    if (!lock) continue
    const entries = []
    if (lock.packages && typeof lock.packages === 'object') {
      for (const [key, p] of Object.entries(lock.packages)) {
        if (!key || !p || typeof p !== 'object') continue
        entries.push([p.name || key.split('node_modules/').pop(), p])
      }
    } else if (lock.dependencies) {
      const walk = deps => { for (const [n, p] of Object.entries(deps || {})) { entries.push([n, p]); if (p && p.dependencies) walk(p.dependencies) } }
      walk(lock.dependencies)
    }
    for (const [name, p] of entries) {
      names.add(name)
      if (p.link || p.bundled || p.inBundle) continue
      const kind = classifyResolved(p.resolved)
      if (kind) note(kind, `${name}@${p.version ?? '?'}`, p.resolved.slice(0, 120))
      if (p.resolved && !p.integrity) tally.noIntegrity++
      else if (p.integrity && !/sha(256|384|512)-/.test(p.integrity)) tally.sha1Only++
    }
    reportTally(findings, lockName, tally)
  }

  const yarn = await readText(path.join(root, 'yarn.lock'))
  if (yarn) {
    const t = { insecure: [], nonregistry: [], git: [], odd: [], noIntegrity: 0, sha1Only: 0 }
    for (const m of yarn.matchAll(/^"?(@?[^@\s"]+)@[^\n]*\n((?:[ \t]+[^\n]*\n?)*)/gm)) {
      const name = m[1]
      names.add(name)
      const block = m[2]
      const resolved = (block.match(/^\s+(?:resolved|resolution)\s+"?([^"\n]+)"?/m) || [])[1]
      const url = resolved && resolved.includes('@') && !resolved.includes('://') ? null : resolved && resolved.replace(/#.*$/, '')
      const kind = classifyResolved(url)
      if (kind && t[kind].length < 5) t[kind].push(`${name} → ${url.slice(0, 120)}`)
      else if (kind) t[kind].push(null)
      if (resolved && /:\/\//.test(resolved) && !/^\s+(integrity|checksum)\s/m.test(block) && !/#[0-9a-f]{40}/.test(resolved)) t.noIntegrity++
    }
    reportTally(findings, 'yarn.lock', t)
  }

  const pnpm = await readText(path.join(root, 'pnpm-lock.yaml'))
  if (pnpm) {
    const t = { insecure: [], nonregistry: [], git: [], odd: [], noIntegrity: 0, sha1Only: 0 }
    for (const m of pnpm.matchAll(/^\s{2,4}'?\/?(@?[^@\s':]+)@[^:\n]*'?:\n((?:\s{4,}[^\n]*\n?)*)/gm)) {
      names.add(m[1])
      const tarball = (m[2].match(/tarball:\s*'?([^'\s},]+)/) || [])[1]
      const kind = classifyResolved(tarball)
      if (kind && t[kind].length < 5) t[kind].push(`${m[1]} → ${tarball.slice(0, 120)}`)
      else if (kind) t[kind].push(null)
    }
    reportTally(findings, 'pnpm-lock.yaml', t)
  }
  return names
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

/** Find lockfiles (not inside node_modules), up to a small depth, for OSV. */
async function findLockfiles(root, depth = 4, rel = '') {
  const out = []
  let entries
  try { entries = await readdir(path.join(root, rel), { withFileTypes: true }) } catch { return out }
  for (const e of entries) {
    const r = rel ? `${rel}/${e.name}` : e.name
    if (e.isDirectory()) {
      if (depth > 0 && !['node_modules', '.git', 'vendor', '.venv', 'venv'].includes(e.name)) out.push(...await findLockfiles(root, depth - 1, r))
    } else if (e.isFile() && (LOCKFILE_NAMES.has(e.name) || /^requirements[\w.-]*\.txt$/.test(e.name))) out.push(r)
  }
  return out
}

function cvssBucket(score) {
  const n = Number.parseFloat(score)
  if (!Number.isFinite(n)) return 'unknown'
  return n >= 9 ? 'critical' : n >= 7 ? 'high' : n >= 4 ? 'medium' : 'low'
}

/** Run osv-scanner against explicit lockfiles with OUR config, so the repo can't suppress results. */
async function osvChecks(root, lockfiles, findings, { osvBin, osvConfig }) {
  if (!lockfiles.length) return { ran: false, reason: 'no lockfiles or manifests found' }
  const args = ['scan', 'source', '--format', 'json', '--config', osvConfig]
  for (const l of lockfiles.slice(0, 50)) args.push('-L', l)
  const r = await run(osvBin, args, { cwd: root, timeoutMs: 5 * 60 * 1000 })
  if (r.code !== 0 && r.code !== 1) {
    findings.add({ id: 'DEP-OSV-UNAVAILABLE', severity: 'medium', title: 'Known-malware check could not run',
      detail: 'osv-scanner (the known-malicious and known-vulnerable package lookup) failed, so this part of the check is missing. Treat the result as incomplete.',
      evidence: r.stderr.trim().split('\n').slice(-1)[0]?.slice(0, 200) })
    return { ran: false, reason: `osv-scanner exited ${r.code}` }
  }
  let data
  try { data = JSON.parse(r.stdout) } catch { data = null }
  if (!data) {
    findings.add({ id: 'DEP-OSV-UNAVAILABLE', severity: 'medium', title: 'Known-malware check returned unreadable output', detail: 'Treat the result as incomplete.' })
    return { ran: false, reason: 'unparsable output' }
  }
  const malware = []
  const vulnPkgs = new Map()
  const buckets = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
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
  for (const m of malware.slice(0, 25)) {
    findings.add({ id: 'DEP-MALWARE', severity: 'critical', evidence: m, title: 'Known-malicious package in the dependency tree',
      detail: 'This exact package version is in the OSV malicious-packages database (OpenSSF). Installing it runs malware.' })
  }
  if (vulnPkgs.size) {
    const total = Object.values(buckets).reduce((a, b) => a + b, 0)
    const top = [...vulnPkgs.entries()].slice(0, 4).map(([k, ids]) => `${k}: ${ids.slice(0, 2).join(', ')}`).join('; ')
    findings.add({ id: 'DEP-VULN', severity: 'medium', evidence: top,
      title: `${total} known vulnerabilit${total === 1 ? 'y' : 'ies'} in ${vulnPkgs.size} package(s) (${buckets.critical} critical, ${buckets.high} high)`,
      detail: 'These are ordinary security bugs (CVEs), not malware: they make the app vulnerable, not your machine at install time. Worth knowing before you build on it.' })
  }
  return { ran: true, lockfiles: lockfiles.length }
}

/**
 * All dependency checks. Mutates nothing outside `root`.
 * @returns {Promise<{kind: string, lockfile: string|null, generatedLockfile: boolean, installed: boolean, osv: object}>}
 */
export async function dependencyChecks(root, findings, { osvBin = 'osv-scanner', osvConfig = '/opt/bouncer/osv-scanner.toml', skipInstall = false, dryRun = false } = {}) {
  const ioc = iocIndex()
  const pm = { kind: 'none', lockfile: null, generatedLockfile: false, installed: false, osv: null }

  // 1. Project config that changes npm's behavior. Read it, report it, then move it out of the way.
  for (const rc of ['.npmrc', '.yarnrc', '.yarnrc.yml']) {
    const text = await readText(path.join(root, rc))
    if (text === null) continue
    if (rc === '.yarnrc.yml') {
      const yp = text.match(/^\s*yarnPath:\s*(.+)$/m)
      if (yp) findings.add({ id: 'YARN-PATH', severity: 'medium', file: rc, evidence: yp[1].trim().slice(0, 120),
        title: 'Running yarn here executes a JavaScript file from the repo',
        detail: '`yarnPath` makes every yarn command run the repo\'s own copy of Yarn. That\'s common with Yarn Berry, but it means the repo controls the program that installs your dependencies. Compare it with an official Yarn release before running yarn.' })
      const reg = text.match(/^\s*npmRegistryServer:\s*["']?([^"'\s]+)/m)
      if (reg && !/registry\.(npmjs\.org|yarnpkg\.com)/.test(reg[1])) findings.add({ id: 'NPMRC-OVERRIDE', severity: 'high', file: rc, evidence: `npmRegistryServer: ${reg[1].slice(0, 100)}`,
        title: 'Yarn is pointed at a different package registry', detail: 'Every package would be downloaded from this server instead of the npm registry.' })
      continue
    }
    const risky = []
    for (const [key, value] of parseNpmrc(text)) {
      const bare = key.replace(/^@[^:]+:/, '')
      if (key.endsWith(':_authtoken') || key.endsWith(':_auth') || key === '_authtoken' || key === '_auth') {
        findings.add({ id: 'NPMRC-TOKEN', severity: 'medium', file: rc, title: 'An npm auth token is committed to the repo',
          detail: 'Someone leaked a credential here. Not an attack on you, but a sign of poor hygiene, and possibly a stolen token.' })
        continue
      }
      if (bare === 'registry' && /^https:\/\/registry\.npmjs\.org\/?$/.test(value)) continue
      if (bare === 'strict-ssl' && value === 'true') continue
      if (DANGEROUS_NPMRC.has(bare)) risky.push(`${key} (${DANGEROUS_NPMRC.get(bare)})`)
    }
    if (risky.length) {
      findings.add({ id: 'NPMRC-OVERRIDE', severity: 'high', file: rc, evidence: risky.slice(0, 4).join('; ').slice(0, 240),
        title: `Project ${rc} changes how npm downloads or runs programs`,
        detail: `npm reads this file automatically in the project folder. These settings can redirect downloads or make npm run arbitrary programs even with --ignore-scripts. It was moved aside inside the sandbox; on your machine it would apply.` })
    }
    if (!dryRun) await rename(path.join(root, rc), path.join(root, `${rc}.bouncer-disabled`)).catch(() => {})
  }

  // 2. Root package.json: lifecycle scripts, run scripts, direct dependencies.
  const pkg = await readJson(path.join(root, 'package.json'))
  const directDeps = new Set()
  if (pkg && typeof pkg === 'object') {
    pm.kind = 'npm'
    const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts : {}
    for (const name of LIFECYCLE) {
      const cmd = scripts[name]
      if (typeof cmd !== 'string') continue
      const benign = /^(husky( install)?|is-ci \|\| husky( install)?|npx husky( install)?|lefthook install|simple-git-hooks|patch-package|node-gyp rebuild|ngcc|tsc|npm run build|prisma generate)$/.test(cmd.trim())
      findings.add({
        id: DOWNLOAD_EXEC.test(cmd) ? 'SCRIPT-ROOT-DANGEROUS' : 'SCRIPT-ROOT-LIFECYCLE',
        severity: DOWNLOAD_EXEC.test(cmd) ? 'high' : benign ? 'low' : 'medium',
        file: 'package.json', evidence: `${name}: ${cmd.slice(0, 200)}`,
        title: `"${name}" script runs automatically on install`,
        detail: DOWNLOAD_EXEC.test(cmd)
          ? 'This script downloads or decodes something and runs it the moment you run npm install. That is the most common way malicious repos attack.'
          : 'npm runs this automatically during install. It may be fine; read it before installing on your machine.',
      })
    }
    for (const name of RUN_SCRIPTS) {
      const cmd = scripts[name]
      if (typeof cmd === 'string' && DOWNLOAD_EXEC.test(cmd)) {
        findings.add({ id: 'SCRIPT-RUN-DANGEROUS', severity: 'medium', file: 'package.json', evidence: `${name}: ${cmd.slice(0, 200)}`,
          title: `"npm run ${name}" downloads or decodes something and runs it`,
          detail: 'Take-home tests tell you to run "npm run dev" or "npm test". Read what that actually does first.' })
      }
    }
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [name, spec] of Object.entries(pkg[field] || {})) {
        directDeps.add(name)
        if (typeof spec === 'string' && /^(https?:|git|github:|file:\/)/.test(spec) && !spec.startsWith('https://registry.npmjs.org/')) {
          findings.add({ id: 'DEP-SPEC-URL', severity: spec.startsWith('http:') ? 'high' : 'low', file: 'package.json', evidence: `${name}: ${spec.slice(0, 160)}`,
            title: `"${name}" is installed from a URL, not the registry`, detail: 'URL and git dependencies skip registry signatures and malware takedowns.' })
        }
      }
    }
  }

  // 3. Static lockfile review.
  const names = await lockfileChecks(root, findings)
  for (const n of directDeps) names.add(n)
  const hasNpmLock = (await stat(path.join(root, 'package-lock.json')).catch(() => null)) || (await stat(path.join(root, 'npm-shrinkwrap.json')).catch(() => null))
  const otherLock = ['yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb']
  for (const f of otherLock) {
    if (await stat(path.join(root, f)).catch(() => null)) { pm.kind = f.startsWith('yarn') ? 'yarn' : f.startsWith('pnpm') ? 'pnpm' : 'bun'; pm.lockfile = f; break }
  }
  if (hasNpmLock) { pm.kind = 'npm'; pm.lockfile = (await stat(path.join(root, 'npm-shrinkwrap.json')).catch(() => null)) ? 'npm-shrinkwrap.json' : 'package-lock.json' }

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

  // 5. Install with scripts disabled, so npm verifies checksums without running anything.
  if (pm.kind === 'npm' && !skipInstall) {
    const npmEnv = cleanEnv({ npm_config_ignore_scripts: 'true', npm_config_registry: REGISTRY, npm_config_audit: 'false', npm_config_fund: 'false' })
    const common = ['--ignore-scripts', '--no-audit', '--no-fund', `--registry=${REGISTRY}`, '--loglevel=error']
    const args = pm.lockfile ? ['ci', ...common] : ['install', ...common, '--package-lock=true']
    const r = await run('npm', args, { cwd: root, env: npmEnv, timeoutMs: 15 * 60 * 1000 })
    const err = r.stderr
    if (r.code === 0) {
      pm.installed = true
      if (!pm.lockfile) { pm.lockfile = 'package-lock.json'; pm.generatedLockfile = true }
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
        detail: 'Checksum, signature and install-script checks need the dependency tree, so those checks are incomplete.' })
    }
  }

  if (pm.installed) {
    const npmEnv = cleanEnv({ npm_config_registry: REGISTRY })
    // 6a. Registry signatures and provenance attestations.
    const sig = await run('npm', ['audit', 'signatures', '--json', `--registry=${REGISTRY}`], { cwd: root, env: npmEnv, timeoutMs: 5 * 60 * 1000 })
    let sigData = null
    try { sigData = JSON.parse(sig.stdout) } catch { /* handled below */ }
    if (sigData && Array.isArray(sigData.invalid) && sigData.invalid.length) {
      findings.add({ id: 'DEP-SIGNATURE-INVALID', severity: 'critical', evidence: sigData.invalid.slice(0, 5).map(p => `${p.name}@${p.version}`).join(', '),
        title: `${sigData.invalid.length} package(s) have an invalid registry signature`,
        detail: 'The npm registry signs every package. An invalid signature means what you downloaded is not what the registry published.' })
    } else if (!sigData && sig.code !== 0 && !/no dependencies to audit/i.test(sig.stderr)) {
      findings.add({ id: 'DEP-SIGNATURES-UNCHECKED', severity: 'low', title: 'Registry signatures could not be checked', evidence: sig.stderr.trim().split('\n').pop()?.slice(0, 200) })
    }

    // 6b. Every install script anywhere in the installed tree.
    const q = await run('npm', ['query', ':attr(scripts, [preinstall]), :attr(scripts, [install]), :attr(scripts, [postinstall])'], { cwd: root, env: npmEnv, timeoutMs: 2 * 60 * 1000 })
    let pkgs = []
    try { pkgs = JSON.parse(q.stdout) } catch { pkgs = [] }
    const known = []
    for (const p of pkgs) {
      if (!p || p.location === '' || p.location === undefined) continue // the root is covered above
      const s = p.scripts || {}
      const cmd = ['preinstall', 'install', 'postinstall'].filter(k => s[k]).map(k => `${k}: ${s[k]}`).join(' ; ')
      if (KNOWN_INSTALL_SCRIPTS.has(p.name) && !DOWNLOAD_EXEC.test(cmd)) { known.push(`${p.name}@${p.version}`); continue }
      findings.add({
        id: DOWNLOAD_EXEC.test(cmd) ? 'DEP-INSTALL-SCRIPT-DANGEROUS' : 'DEP-INSTALL-SCRIPT',
        severity: DOWNLOAD_EXEC.test(cmd) ? 'high' : 'medium',
        evidence: `${p.name}@${p.version} ${cmd}`.slice(0, 240),
        title: `Dependency "${p.name}" runs a script on install`,
        detail: DOWNLOAD_EXEC.test(cmd)
          ? 'This dependency downloads or decodes something and runs it during install. Malicious packages almost always work this way.'
          : 'Install scripts run with your user\'s full permissions. This one isn\'t on the list of well-known native packages; read it before installing with scripts enabled.',
      })
    }
    if (known.length) findings.add({ id: 'DEP-INSTALL-SCRIPT-KNOWN', severity: 'info', evidence: known.slice(0, 8).join(', '),
      title: `${known.length} well-known package(s) with install scripts`, detail: 'Packages like esbuild and sharp download prebuilt binaries on install. Expected.' })
  }

  // 7. OSV: known-malicious packages and known vulnerabilities, for every ecosystem's lockfile.
  const lockfiles = await findLockfiles(root)
  for (const l of lockfiles.filter(f => /requirements[\w.-]*\.txt$/.test(f))) {
    const text = await readText(path.join(root, l))
    const m = text && text.match(/^\s*(-i|--index-url|--extra-index-url|--trusted-host|-f|--find-links)\b[^\n]*/m)
    if (m) findings.add({ id: 'PY-INDEX-OVERRIDE', severity: 'medium', file: l, evidence: m[0].trim().slice(0, 160),
      title: 'requirements file adds or replaces the Python package index',
      detail: '--extra-index-url is the classic "dependency confusion" setup: pip may pick a same-named package from whichever index offers the higher version.' })
  }
  pm.osv = await osvChecks(root, lockfiles, findings, { osvBin, osvConfig })
  return pm
}
