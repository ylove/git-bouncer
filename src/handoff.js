// Bring a repo that passed the pat-down onto this machine: the commit that was scanned, written by a
// git that can't be steered by the repo or by your own global settings, and dependencies installed
// only when the sandbox actually exercised the same install.
//
// Time-of-check vs time-of-use: between the scan and this clone, the repo's owner could push something
// new, so we check out the commit SHA the sandbox scanned and verify the commit and tree IDs. Git object
// IDs are hashes of content. With filters, hooks and LFS switched off (below), what git writes to disk is
// exactly what it stores, so matching IDs mean matching files.
//
// Nothing here runs inside the new folder until it's verified, and nothing ever resolves a program from
// inside it: a repo can ship its own `npm.cmd` or `node_modules/.bin/git`, and on Windows the current
// folder is searched before PATH.

import { lstat, rm, writeFile, readdir } from 'node:fs/promises'
import { devNull } from 'node:os'
import path from 'node:path'
import { run, which } from './proc.js'

// Host git runs with none of the system's or your global configuration (no LFS smudge filter, no hooks
// path, no fsmonitor, no aliases), plus explicit hardening on every command.
const HOST_GIT = [
  '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'protocol.file.allow=never',
  '-c', 'init.templateDir=', '-c', `core.hooksPath=${devNull}`, '-c', 'core.fsmonitor=false',
  '-c', 'transfer.fsckObjects=true', '-c', 'fetch.fsckObjects=true',
  '-c', 'submodule.recurse=false', '-c', 'credential.helper=',
  '-c', 'filter.lfs.smudge=', '-c', 'filter.lfs.process=', '-c', 'filter.lfs.required=false',
  '-c', 'core.protectNTFS=true', '-c', 'core.protectHFS=true',
]
const gitEnv = () => ({
  ...process.env,
  GIT_TERMINAL_PROMPT: '0', GIT_ALLOW_PROTOCOL: 'https',
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: devNull, GIT_ATTR_NOSYSTEM: '1', GIT_LFS_SKIP_SMUDGE: '1',
  GIT_CONFIG_COUNT: '0',
})

export class HandoffError extends Error {}

/** A lockfile generated in the sandbox must look exactly like an npm registry lockfile before it touches disk. */
export function validateGeneratedLockfile(text) {
  let lock
  try { lock = JSON.parse(text) } catch { throw new HandoffError('the lockfile generated in the sandbox is not valid JSON') }
  if (!lock || typeof lock !== 'object' || ![2, 3].includes(lock.lockfileVersion) || !lock.packages || typeof lock.packages !== 'object') {
    throw new HandoffError('the lockfile generated in the sandbox has an unexpected format')
  }
  const KEY = /^(node_modules\/(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*\/?)+$/i
  for (const [key, p] of Object.entries(lock.packages)) {
    if (key === '') continue
    if (!KEY.test(key.replace(/\/$/, '')) || key.includes('..')) throw new HandoffError(`the generated lockfile has an unexpected entry (${key.slice(0, 80)})`)
    if (!p || typeof p !== 'object' || p.link || p.bundled || p.inBundle) throw new HandoffError(`the generated lockfile has a linked or bundled entry (${key.slice(0, 80)})`)
    if (typeof p.resolved !== 'string' || !/^https:\/\/registry\.npmjs\.org\/[^?#]+\.tgz$/.test(p.resolved) ||
        typeof p.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/=]+$/.test(p.integrity)) {
      throw new HandoffError(`the generated lockfile has an entry outside the npm registry or without a sha512 hash (${key.slice(0, 80)})`)
    }
  }
  return text
}

const SCRIPT_FINDINGS = new Set(['SCRIPT-ROOT-LIFECYCLE', 'SCRIPT-ROOT-DANGEROUS', 'DEP-INSTALL-SCRIPT', 'DEP-INSTALL-SCRIPT-DANGEROUS', 'DEP-INSTALL-SCRIPT-KNOWN'])
// Files that make a package manager run repo code or talk to other servers, whatever flags you pass.
const STEERING_FILES = ['.npmrc', '.yarnrc', '.yarnrc.yml', '.pnpmfile.cjs', '.pnpmfile.mjs', 'bunfig.toml', '.yarn']

/** The install command for npm, the one package manager the sandbox actually runs. Constant arguments only. */
export function installCommand(kind, { ignoreScripts }) {
  if (kind !== 'npm') return null
  return ['npm', ['ci', ...(ignoreScripts ? ['--ignore-scripts'] : [])]]
}

/** What we'd tell someone to run themselves when git-bouncer won't install for them. */
export function manualInstallHint(kind) {
  return { npm: 'npm ci --ignore-scripts', yarn: 'yarn install --immutable --mode=skip-build', pnpm: 'pnpm install --frozen-lockfile --ignore-scripts', bun: 'bun install --frozen-lockfile --ignore-scripts' }[kind] || null
}

/** Environment for the install: what package managers need, minus every token and credential we can name. */
export function installEnv(env = process.env) {
  const out = {}
  const secret = /(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE|SESSION|AUTH)/i
  for (const [k, v] of Object.entries(env)) {
    if (secret.test(k) || /^(AWS_|AZURE_|GOOGLE_|GCLOUD_|CLOUDSDK_|GH_|GITHUB_|NPM_CONFIG__AUTH|npm_config__auth)/i.test(k)) continue
    out[k] = v
  }
  return out
}

/** On Windows, npm is a .cmd shim that Node can only start through cmd.exe: started by full path, with the
 * current folder removed from the program search. Arguments here are constants. */
function platformCommand(cmdPath, args) {
  if (process.platform !== 'win32') return [cmdPath, args, {}]
  const cmdExe = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'cmd.exe')
  return [cmdExe, ['/d', '/s', '/c', cmdPath, ...args], { NoDefaultCurrentDirectoryInExePath: '1' }]
}

/**
 * @param {{target: object, report: object, findings: object[], dir: string, install: boolean,
 *          runtime: object, session: object, prompter: object, out: object, cwd?: string,
 *          onCreated?: (dest: string|null) => void}} p
 * @returns {Promise<{dest: string, installed: boolean, ignoreScripts: boolean|null, manual: string|null}>}
 */
export async function handoff({ target, report, findings, dir, install, runtime, session, prompter, out, cwd = process.cwd(), onCreated = () => {} }) {
  const dest = path.resolve(cwd, dir)
  const rel = path.relative(cwd, dest)
  if (rel.startsWith('..') || path.isAbsolute(rel)) throw new HandoffError('the destination must be inside the current folder')
  if (await lstat(dest).catch(() => null)) throw new HandoffError(`"${dir}" already exists. Choose a new folder name; git-bouncer never writes into an existing folder.`)

  // Resolve the programs we'll run BEFORE the clone exists, from absolute PATH entries only.
  const gitBin = await which('git')
  if (!gitBin) throw new HandoffError('git is not installed')
  const git = (args, timeoutMs = 15 * 60_000) => run(gitBin, [...HOST_GIT, ...args], { cwd, env: gitEnv(), timeoutMs })

  const commit = report.target.commit
  const tree = report.target.tree
  if (!commit || !tree) throw new HandoffError('the report did not include the scanned commit and tree')

  let created = false
  try {
    out.step(`Cloning to ./${dir} at the scanned commit ${commit.slice(0, 12)}`)
    const isSha = /^[0-9a-f]{40}$/.test(target.ref || '')
    const ref = target.ref && !isSha ? target.ref : null
    created = true
    onCreated(dest)
    const clone = await git(['clone', '--no-checkout', '--no-recurse-submodules', ...(ref ? ['--branch', ref] : []), '--', target.url, dest])
    if (clone.code !== 0) throw new HandoffError(`git clone failed: ${clone.stderr.trim().split('\n').pop()}`)

    // The scanned commit must be exactly where we're about to check out.
    if (isSha) {
      if ((await git(['-C', dest, 'cat-file', '-e', `${commit}^{commit}`])).code !== 0) {
        if ((await git(['-C', dest, 'fetch', '--no-tags', 'origin', commit])).code !== 0) throw new HandoffError('could not fetch the scanned commit')
      }
    } else {
      const head = (await git(['-C', dest, 'rev-parse', 'HEAD'])).stdout.trim()
      if (head !== commit) {
        throw new HandoffError(`the repository changed after the scan (now at ${head.slice(0, 12)}, scanned ${commit.slice(0, 12)}). Run git-bouncer again to check the new version.`)
      }
    }
    const co = await git(['-C', dest, 'checkout', '--quiet', ...(isSha ? ['--detach', commit] : [])])
    if (co.code !== 0) throw new HandoffError(`checkout failed: ${co.stderr.trim().split('\n').pop()}`)
    const [nowCommit, nowTree] = (await git(['-C', dest, 'rev-parse', 'HEAD', 'HEAD^{tree}'])).stdout.trim().split('\n')
    if (nowCommit !== commit || nowTree !== tree) throw new HandoffError('the checked-out files do not match what was scanned')
    out.note(`verified: commit ${commit.slice(0, 12)} and tree ${tree.slice(0, 12)} match the scan (written with filters, hooks and LFS off)`)
    created = false // from here on, the folder is the user's
    onCreated(null)

    // Dependencies: only npm, only when the sandbox installed the same tree, and only when nothing in the
    // repo could steer the package manager. Everything else gets clear instructions instead.
    const pm = report.packageManager
    if (!install || !pm || pm.kind === 'none') return { dest, installed: false, ignoreScripts: null, manual: null }
    const present = new Set((await readdir(dest)).map(n => n.toLowerCase()))
    const steering = STEERING_FILES.filter(f => present.has(f))
    const reason =
      pm.kind !== 'npm' ? `${pm.kind} projects aren't installed automatically (the sandbox only exercises npm)` :
      !pm.installed ? 'the sandbox could not install this project, so its install was never checked' :
      steering.length ? `the repo ships ${steering.join(', ')}, which can change what the package manager runs` : null
    if (reason) {
      const hint = manualInstallHint(pm.kind)
      out.note(`Dependencies were not installed: ${reason}. Review it, then run: cd ${dir} && ${hint}`)
      return { dest, installed: false, ignoreScripts: null, manual: hint }
    }
    if (pm.generatedLockfile) {
      const text = await runtime.readFile(session, 'package-lock.json')
      if (!text) throw new HandoffError('could not copy the verified lockfile out of the sandbox')
      await writeFile(path.join(dest, 'package-lock.json'), validateGeneratedLockfile(text), { flag: 'wx' })
      out.note('the repo had no lockfile; copied in the one generated and checked in the sandbox, so you get the exact same packages')
    }

    const scriptFindings = findings.filter(f => SCRIPT_FINDINGS.has(f.id))
    let ignoreScripts = false
    if (scriptFindings.length) {
      const onlyKnown = scriptFindings.every(f => f.id === 'DEP-INSTALL-SCRIPT-KNOWN')
      out.line()
      out.note(onlyKnown
        ? 'Some well-known packages run install scripts (usually to download a prebuilt binary).'
        : 'This project or its dependencies run scripts during install (listed above). They run with your full permissions.')
      ignoreScripts = !(await prompter.confirm('Run install scripts?', { defaultYes: onlyKnown, safeAnswer: false }))
    }
    const npmBin = await which('npm')
    if (!npmBin) {
      out.note(`npm is not installed; the code is cloned. Install dependencies with: cd ${dir} && npm ci --ignore-scripts`)
      return { dest, installed: false, ignoreScripts, manual: 'npm ci --ignore-scripts' }
    }
    const [, args] = installCommand('npm', { ignoreScripts })
    out.step(`Installing dependencies: npm ${args.join(' ')}`)
    const [cmd, cmdArgs, extraEnv] = platformCommand(npmBin, args)
    const r = await run(cmd, cmdArgs, { cwd: dest, env: { ...installEnv(), ...extraEnv }, inherit: true, timeoutMs: 60 * 60_000 })
    if (r.code !== 0) {
      out.note(`npm exited with code ${r.code}; the code is cloned, dependencies may be incomplete.`)
      return { dest, installed: false, ignoreScripts, manual: null }
    }
    return { dest, installed: true, ignoreScripts, manual: null }
  } catch (e) {
    if (created) await rm(dest, { recursive: true, force: true }) // only ever a folder we created in this run
    onCreated(null)
    throw e
  }
}
