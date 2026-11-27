// Bring a repo that passed the pat-down onto this machine: exactly the commit that was scanned,
// and exactly the dependency tree that was checked.
//
// Time-of-check vs time-of-use: between the scan and this clone, the repo's owner could push something
// new. So we don't trust "whatever is on the branch now". We check out the commit SHA the sandbox scanned
// and verify both the commit and its tree hash. Git object IDs are cryptographic hashes of content, so
// matching IDs mean byte-for-byte the same files. Any mismatch: stop, and delete what we created.

import { lstat, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { run } from './proc.js'

const HOST_GIT = [
  '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
  '-c', 'init.templateDir=', '-c', 'core.fsmonitor=false',
  '-c', 'transfer.fsckObjects=true', '-c', 'fetch.fsckObjects=true',
  '-c', 'submodule.recurse=false', '-c', 'credential.helper=',
]
const gitEnv = () => ({ ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ALLOW_PROTOCOL: 'https' })
const git = (args, cwd, timeoutMs = 15 * 60_000) => run('git', [...HOST_GIT, ...args], { cwd, env: gitEnv(), timeoutMs })

export class HandoffError extends Error {}

/** A lockfile generated in the sandbox must look exactly like an npm registry lockfile before it touches disk. */
export function validateGeneratedLockfile(text) {
  let lock
  try { lock = JSON.parse(text) } catch { throw new HandoffError('the lockfile generated in the sandbox is not valid JSON') }
  if (!lock || typeof lock !== 'object' || ![2, 3].includes(lock.lockfileVersion) || typeof lock.packages !== 'object') {
    throw new HandoffError('the lockfile generated in the sandbox has an unexpected format')
  }
  for (const [key, p] of Object.entries(lock.packages)) {
    if (!key || !p || p.link || p.bundled || p.inBundle) continue
    if (typeof p.resolved !== 'string' || !/^https:\/\/registry\.npmjs\.org\//.test(p.resolved) ||
        typeof p.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/=]+$/.test(p.integrity)) {
      throw new HandoffError(`the generated lockfile has an entry outside the npm registry or without a sha512 hash (${key.slice(0, 80)})`)
    }
  }
  return text
}

const LIFECYCLE_FINDINGS = new Set(['SCRIPT-ROOT-LIFECYCLE', 'DEP-INSTALL-SCRIPT', 'DEP-INSTALL-SCRIPT-KNOWN'])

/** The install command for each package manager, with or without install scripts. Constant arguments only. */
export function installCommand(kind, { ignoreScripts, yarnMajor = 1 }) {
  switch (kind) {
    case 'npm': return ['npm', ['ci', ...(ignoreScripts ? ['--ignore-scripts'] : [])]]
    case 'yarn': return yarnMajor >= 2
      ? ['yarn', ['install', '--immutable', ...(ignoreScripts ? ['--mode=skip-build'] : [])]]
      : ['yarn', ['install', '--frozen-lockfile', ...(ignoreScripts ? ['--ignore-scripts'] : [])]]
    case 'pnpm': return ['pnpm', ['install', '--frozen-lockfile', ...(ignoreScripts ? ['--ignore-scripts'] : [])]]
    case 'bun': return ['bun', ['install', '--frozen-lockfile', ...(ignoreScripts ? ['--ignore-scripts'] : [])]]
    default: return null
  }
}

/** On Windows, npm/yarn/pnpm are .cmd shims that Node can only start through cmd.exe. Arguments here are constants. */
function platformCommand(cmd, args) {
  return process.platform === 'win32' ? ['cmd.exe', ['/d', '/s', '/c', cmd, ...args]] : [cmd, args]
}

/**
 * @param {{target: object, report: object, findings: object[], dir: string, install: boolean,
 *          runtime: object, session: object, prompter: object, out: object, cwd?: string}} p
 * @returns {Promise<{dest: string, installed: boolean, ignoreScripts: boolean|null}>}
 */
export async function handoff({ target, report, findings, dir, install, runtime, session, prompter, out, cwd = process.cwd() }) {
  const dest = path.resolve(cwd, dir)
  if (path.relative(cwd, dest).startsWith('..') || path.isAbsolute(path.relative(cwd, dest))) throw new HandoffError('the destination must be inside the current folder')
  if (await lstat(dest).catch(() => null)) throw new HandoffError(`"${dir}" already exists. Choose a new folder name; git-bouncer never writes into an existing folder.`)

  const commit = report.target.commit
  const tree = report.target.tree
  if (!commit || !tree) throw new HandoffError('the report did not include the scanned commit and tree')

  let created = false
  try {
    out.step(`Cloning to ./${dir} at the scanned commit ${commit.slice(0, 12)}`)
    const ref = target.ref && !/^[0-9a-f]{40}$/.test(target.ref) ? target.ref : null
    const clone = await git(['clone', '--no-checkout', '--no-recurse-submodules', ...(ref ? ['--branch', ref] : []), '--', target.url, dest], cwd)
    created = true
    if (clone.code !== 0) throw new HandoffError(`git clone failed: ${clone.stderr.trim().split('\n').pop()}`)

    // The scanned commit must be exactly where we're about to check out.
    const head = (await git(['rev-parse', 'HEAD'], dest)).stdout.trim()
    if (/^[0-9a-f]{40}$/.test(target.ref || '')) {
      const have = await git(['cat-file', '-e', `${commit}^{commit}`], dest)
      if (have.code !== 0) {
        const f = await git(['fetch', '--no-tags', 'origin', commit], dest)
        if (f.code !== 0) throw new HandoffError('could not fetch the scanned commit')
      }
    } else if (head !== commit) {
      throw new HandoffError(`the repository changed after the scan (now at ${head.slice(0, 12)}, scanned ${commit.slice(0, 12)}). Run git-bouncer again to check the new version.`)
    }
    const co = await git(['checkout', '--quiet', ...(/^[0-9a-f]{40}$/.test(target.ref || '') ? ['--detach', commit] : [])], dest)
    if (co.code !== 0) throw new HandoffError(`checkout failed: ${co.stderr.trim().split('\n').pop()}`)
    const [nowCommit, nowTree] = (await git(['rev-parse', 'HEAD', 'HEAD^{tree}'], dest)).stdout.trim().split('\n')
    if (nowCommit !== commit || nowTree !== tree) throw new HandoffError('the checked-out files do not match what was scanned')
    out.note(`verified: commit ${commit.slice(0, 12)} and tree ${tree.slice(0, 12)} match the scan`)

    // Dependencies: install exactly the tree that was checked.
    const pm = report.packageManager
    if (!install || !pm || pm.kind === 'none') return { dest, installed: false, ignoreScripts: null }
    if (pm.generatedLockfile && pm.kind === 'npm') {
      const text = await runtime.readFile(session, 'package-lock.json')
      if (!text) throw new HandoffError('could not copy the verified lockfile out of the sandbox')
      await writeFile(path.join(dest, 'package-lock.json'), validateGeneratedLockfile(text), { flag: 'wx' })
      out.note('the repo had no lockfile; copied in the one generated and checked in the sandbox, so you get the exact same packages')
    }

    const scriptFindings = findings.filter(f => LIFECYCLE_FINDINGS.has(f.id))
    let ignoreScripts = false
    if (scriptFindings.length) {
      const onlyKnown = scriptFindings.every(f => f.id === 'DEP-INSTALL-SCRIPT-KNOWN')
      out.line()
      out.note(onlyKnown
        ? 'Some well-known packages run install scripts (usually to download a prebuilt binary).'
        : 'This project or its dependencies run scripts during install (listed above). They run with your full permissions.')
      const runScripts = await prompter.confirm('Run install scripts?', { defaultYes: onlyKnown, safeAnswer: false })
      ignoreScripts = !runScripts
    }
    let yarnMajor = 1
    if (pm.kind === 'yarn') {
      const v = await run(...platformCommand('yarn', ['--version']), { cwd: dest, timeoutMs: 30_000 })
      yarnMajor = Number.parseInt(v.stdout.trim(), 10) || 1
    }
    const [cmd, args] = installCommand(pm.kind, { ignoreScripts, yarnMajor })
    out.step(`Installing dependencies: ${cmd} ${args.join(' ')}`)
    const r = await run(...platformCommand(cmd, args), { cwd: dest, inherit: true, timeoutMs: 60 * 60_000 })
    if (r.code !== 0) {
      out.note(r.error && r.error.code === 'ENOENT' ? `${cmd} is not installed; the code is cloned, install dependencies yourself.` : `${cmd} exited with code ${r.code}; the code is cloned, dependencies may be incomplete.`)
      return { dest, installed: false, ignoreScripts }
    }
    return { dest, installed: true, ignoreScripts }
  } catch (e) {
    if (created) await rm(dest, { recursive: true, force: true }) // only ever a folder we created in this run
    throw e
  }
}
