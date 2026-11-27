#!/usr/bin/env node
// git-bouncer scanner. This file runs INSIDE the throwaway sandbox, never on the user's machine.
//
// It clones one commit of the target repo with hardened git settings, runs every check, and prints
// exactly one JSON report between two marker lines that contain a nonce chosen by the host. Logs
// go to stderr. Nothing from the scanned repository is ever executed.
//
//   echo <nonce> | node main.js --url https://github.com/o/r.git [--ref <ref>] --nonce-stdin [--dir /work/repo]
//   echo <nonce> | node main.js --no-clone --dir <path> --nonce-stdin      (scan an existing folder; tests)
//
// The nonce arrives on stdin, not as an argument: arguments are readable by every process in the
// container through /proc/<pid>/cmdline, stdin isn't.

import { parseArgs } from 'node:util'
import { readFileSync } from 'node:fs'
import { Findings } from './findings.js'
import { hardenedClone, gitChecks, validateCloneInput } from './clone.js'
import { contentChecks } from './checks/content.js'
import { autorunChecks } from './checks/autorun.js'
import { dependencyChecks } from './checks/deps.js'
import { IOC_SNAPSHOT_DATE } from './checks/iocs.js'
import { run } from './proc.js'

export const SCHEMA_VERSION = 1
const VERSION = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version

const { values } = parseArgs({
  options: {
    url: { type: 'string' },
    ref: { type: 'string' },
    nonce: { type: 'string' },
    'nonce-stdin': { type: 'boolean', default: false },
    dir: { type: 'string', default: '/work/repo' },
    'no-clone': { type: 'boolean', default: false },
    'skip-install': { type: 'boolean', default: false },
    osv: { type: 'string', default: 'osv-scanner' },
    'osv-config': { type: 'string', default: '/opt/bouncer/osv-scanner.toml' },
  },
  strict: true,
})

async function readNonce() {
  let data = ''
  for await (const chunk of process.stdin) {
    data += chunk
    if (data.includes('\n') || data.length > 200) break
  }
  return data.split('\n')[0].trim()
}
if (values['nonce-stdin']) values.nonce = await readNonce()
if (!/^[0-9a-f]{32,64}$/.test(values.nonce || '')) {
  process.stderr.write('scanner: the nonce (on stdin with --nonce-stdin, or --nonce) must be 32-64 lowercase hex characters\n')
  process.exit(2)
}

const log = msg => process.stderr.write(`[scanner] ${msg}\n`)
const findings = new Findings()
const report = {
  schema: SCHEMA_VERSION,
  scanner: { version: VERSION, iocSnapshot: IOC_SNAPSHOT_DATE },
  status: 'ok',
  error: null,
  target: { url: values.url ?? null, ref: values.ref ?? null, commit: null, tree: null, defaultBranch: null },
  packageManager: null,
  stats: null,
  tools: {},
  timings: {},
  findings: [],
}

const timed = async (name, fn) => {
  const t = Date.now()
  try { return await fn() } finally { report.timings[name] = Date.now() - t }
}

async function toolVersions() {
  const v = async (cmd, args) => {
    const r = await run(cmd, args, { timeoutMs: 20000 })
    return r.code === 0 ? r.stdout.trim().split('\n')[0].slice(0, 80) : null
  }
  report.tools = {
    node: process.version,
    npm: await v('npm', ['--version']),
    git: await v('git', ['--version']),
    osvScanner: await v(values.osv, ['--version']),
  }
}

async function main() {
  await toolVersions()
  if (!values['no-clone']) {
    try {
      validateCloneInput(values.url, values.ref)
    } catch (e) {
      report.status = 'error'
      report.error = e.message
      return
    }
    log(`fetching one commit of ${values.url}`)
    try {
      const c = await timed('clone', () => hardenedClone(values.url, values.ref, values.dir))
      Object.assign(report.target, { commit: c.commit, tree: c.tree, defaultBranch: c.defaultBranch })
    } catch (e) {
      if (e.fsck) {
        findings.add({ id: 'GIT-FSCK', severity: 'critical', evidence: (e.stderr || '').trim().split('\n').pop()?.slice(0, 200),
          title: 'The repository contains corrupt or malformed git objects',
          detail: 'git\'s object verification rejected the download. Malformed objects have been used to exploit git clients.' })
        return
      }
      if (e.unsafePath) {
        findings.add({ id: 'GIT-UNSAFE-PATH', severity: 'high', evidence: (e.stderr || '').trim().split('\n').pop()?.slice(0, 200),
          title: 'git refused to check out a dangerous path',
          detail: 'The repo contains a path that git\'s own protections (core.protectNTFS/HFS) refuse, such as a .git look-alike. This is how several git clone exploits begin.' })
        return
      }
      report.status = 'error'
      report.error = e.unreachable ? e.message : `${e.message}${e.timedOut ? ' (timed out)' : ''}`
      report.errorDetail = (e.stderr || '').trim().split('\n').slice(-3).join(' ').slice(0, 400)
      return
    }
    await timed('git', () => gitChecks(values.dir, findings))
  }
  log('content checks')
  report.stats = await timed('content', () => contentChecks(values.dir, findings))
  log('auto-run checks')
  await timed('autorun', () => autorunChecks(values.dir, findings))
  log('dependency checks')
  report.packageManager = await timed('dependencies', () => dependencyChecks(values.dir, findings, {
    osvBin: values.osv, osvConfig: values['osv-config'], skipInstall: values['skip-install'],
  }))
}

try {
  await main()
} catch (e) {
  report.status = 'error'
  report.error = `scanner crashed: ${e && e.message ? e.message : String(e)}`.slice(0, 400)
}
report.findings = findings.toJSON()
// One line of JSON between unforgeable markers: JSON.stringify escapes every newline inside strings,
// so text from the repo can never produce a line equal to the end marker.
process.stdout.write(`\n-----BEGIN BOUNCER REPORT ${values.nonce}-----\n${JSON.stringify(report)}\n-----END BOUNCER REPORT ${values.nonce}-----\n`)
