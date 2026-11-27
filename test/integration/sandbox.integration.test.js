// Integration tests: real container engine, real sandbox image, real network.
// Run with: BOUNCER_INTEGRATION=1 node --test test/integration/   (BOUNCER_ENGINE=podman to use Podman)
// Skipped by plain `npm test`, which must work on any machine with no Docker and no network.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { mkdtemp, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { createContainerRuntime, runArgs, LABEL } from '../../src/runtimes/container.js'
import { extractReport } from '../../src/report.js'
import { run } from '../../src/proc.js'
import { main } from '../../src/cli.js'
import { fixture } from '../helpers/fixture.js'

const skip = process.env.BOUNCER_INTEGRATION ? false : 'set BOUNCER_INTEGRATION=1 to run (needs Docker or Podman and network)'
const engine = process.env.BOUNCER_ENGINE || 'docker'
const rt = createContainerRuntime(engine)
let image
const containers = []

async function start() {
  const name = `git-bouncer-test-${randomBytes(4).toString('hex')}`
  const r = await run(engine, runArgs({ name, image }), { timeoutMs: 60_000 })
  assert.equal(r.code, 0, r.stderr)
  containers.push(name)
  return name
}
const exec = (name, args, opts) => run(engine, ['exec', name, ...args], { timeoutMs: 15 * 60_000, ...opts })

/** Copy a fixture folder into a running sandbox by piping a tar stream (docker cp can't write to tmpfs). */
async function copyIn(name, dir) {
  await exec(name, ['mkdir', '-p', '/work/repo'])
  await new Promise((resolve, reject) => {
    const tar = spawn('tar', ['-c', '-C', dir, '.'])
    const ex = spawn(engine, ['exec', '-i', name, 'tar', '-x', '-C', '/work/repo'])
    tar.stdout.pipe(ex.stdin)
    ex.on('close', code => (code === 0 ? resolve() : reject(new Error(`tar into sandbox exited ${code}`))))
  })
}

async function scanFixture(files) {
  const fx = await fixture(files)
  const name = await start()
  try {
    await copyIn(name, fx.dir)
    const nonce = randomBytes(16).toString('hex')
    const r = await run(engine, ['exec', '--interactive', name, 'node', '/opt/bouncer/scanner/main.js', '--no-clone', '--dir', '/work/repo', '--nonce-stdin'], { timeoutMs: 15 * 60_000, input: `${nonce}\n` })
    const { report } = extractReport(r.stdout, nonce)
    assert.ok(report, `no report: ${r.stderr.slice(-500)}`)
    return report
  } finally { await fx.cleanup() }
}

const npmView = async (spec, field) => (await run('npm', ['view', spec, field], { timeoutMs: 60_000 })).stdout.trim()
const lockFor = (name, version, integrity) => JSON.stringify({
  name: 'fixture', lockfileVersion: 3, requires: true,
  packages: {
    '': { name: 'fixture', dependencies: { [name]: version } },
    [`node_modules/${name}`]: { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity },
  },
})

before(async () => {
  if (skip) return
  const a = await rt.available()
  assert.ok(a.ok, a.reason)
  image = await rt.ensureImage('test')
})

after(async () => {
  for (const name of containers) await run(engine, ['rm', '-f', '-v', name], { timeoutMs: 60_000 })
})

test('the sandbox is locked down: non-root, no capabilities, read-only root, noexec work area, no host env', { skip }, async () => {
  process.env.BOUNCER_TEST_SENTINEL = 'host-secret-must-not-leak'
  const name = await start()
  assert.equal((await exec(name, ['id', '-u'])).stdout.trim(), '10001')
  assert.match((await exec(name, ['grep', 'CapEff', '/proc/self/status'])).stdout, /CapEff:\s+0000000000000000/)
  assert.notEqual((await exec(name, ['touch', '/usr/local/x'])).code, 0, 'root filesystem must be read-only')
  const noexec = await exec(name, ['sh', '-c', 'printf "#!/bin/sh\\necho ran" > /work/x && chmod +x /work/x && /work/x'])
  assert.notEqual(noexec.code, 0, '/work must be noexec')
  assert.doesNotMatch(noexec.stdout, /ran/)
  const env = (await exec(name, ['env'])).stdout
  assert.doesNotMatch(env, /host-secret-must-not-leak|GITHUB_TOKEN|GH_TOKEN|SNYK_TOKEN|AWS_|NPM_TOKEN/)
  // No bind mounts or volumes at all, according to the engine itself. (/proc/mounts can't be used for
  // this: rootless Podman's own overlay storage lives under the runner's home directory.)
  const declared = JSON.parse((await run(engine, ['inspect', '--format', '{{json .Mounts}}', name])).stdout.trim() || '[]')
  assert.deepEqual(declared, [])
  const mounts = (await exec(name, ['cat', '/proc/mounts'])).stdout
  assert.doesNotMatch(mounts, /docker\.sock|podman\.sock/)
})

test('a lockfile whose checksum does not match the registry is turned away (EINTEGRITY)', { skip }, async () => {
  const wrong = await npmView('ms@2.1.2', 'dist.integrity') // a real hash, but for a different version
  const report = await scanFixture({ 'package.json': JSON.stringify({ name: 'fixture', dependencies: { ms: '2.1.3' } }), 'package-lock.json': lockFor('ms', '2.1.3', wrong) })
  assert.ok(report.findings.some(f => f.id === 'DEP-INTEGRITY-MISMATCH' && f.severity === 'critical'), JSON.stringify(report.findings.map(f => f.id)))
})

test('known vulnerabilities are reported, and the repo cannot hide them with its own osv-scanner.toml', { skip }, async () => {
  const integrity = await npmView('lodash@4.17.15', 'dist.integrity')
  const files = { 'package.json': JSON.stringify({ name: 'fixture', dependencies: { lodash: '4.17.15' } }), 'package-lock.json': lockFor('lodash', '4.17.15', integrity) }
  const first = await scanFixture(files)
  const vuln = first.findings.find(f => f.id === 'DEP-VULN')
  assert.ok(vuln, JSON.stringify(first.findings.map(f => f.id)))
  assert.equal(vuln.severity, 'low', 'an ordinary CVE is context, not a reason to turn the repo away')
  const ids = [...new Set((vuln.evidence.match(/GHSA-[a-z0-9-]+|CVE-\d+-\d+/g) || []))]
  assert.ok(ids.length > 0, vuln.evidence)
  const toml = ids.map(id => `[[IgnoredVulns]]\nid = "${id}"\nreason = "trust me"\n`).join('\n')
  const second = await scanFixture({ ...files, 'osv-scanner.toml': toml })
  assert.ok(second.findings.some(f => f.id === 'DEP-VULN'), 'the repo-supplied osv-scanner.toml must be ignored')
})

test('osv-scanner in the image accepts --no-resolve, so a pom.xml cannot point it at other servers', { skip }, async () => {
  // Without --no-resolve, osv-scanner fetches the parent POM from the <repositories> URL (and fails
  // here, because .invalid never resolves). With it, the declared dependency is matched as written.
  const pom = '<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>y</artifactId><version>1</version>' +
    '<parent><groupId>x.audit</groupId><artifactId>parent</artifactId><version>9.9.9</version></parent>' +
    '<repositories><repository><id>r</id><url>https://repo.example.invalid/maven/</url></repository></repositories>' +
    '<dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version></dependency></dependencies></project>'
  const report = await scanFixture({ 'pom.xml': pom })
  assert.ok(!report.findings.some(f => f.id === 'DEP-OSV-UNAVAILABLE'), JSON.stringify(report.findings))
  // junit 4.12 has a published advisory (CVE-2020-15250), so a match proves osv-scanner really ran on it.
  assert.ok(report.findings.some(f => f.id === 'DEP-VULN' && /junit/.test(f.evidence)), JSON.stringify(report.findings.map(f => [f.id, f.evidence])))
})

test('a project .npmrc that redirects the registry is flagged, and npm still uses the real registry', { skip }, async () => {
  const integrity = await npmView('ms@2.1.3', 'dist.integrity')
  const report = await scanFixture({
    '.npmrc': 'registry=https://registry.example.invalid/\n',
    'package.json': JSON.stringify({ name: 'fixture', dependencies: { ms: '2.1.3' } }),
    'package-lock.json': lockFor('ms', '2.1.3', integrity),
  })
  assert.ok(report.findings.some(f => f.id === 'NPMRC-OVERRIDE' && f.severity === 'high'))
  assert.equal(report.packageManager.installed, true, 'npm ci should have succeeded against the official registry')
})

test('end to end: `bouncer scan` lets a clean public repo in, and leaves no sandbox behind', { skip }, async () => {
  const out = { text: '', write(s) { this.text += s } }
  const code = await main(['scan', 'https://github.com/octocat/Hello-World', '--json', '--no-snyk', '--runtime', engine], { stdout: out, stderr: { write() {} } })
  const result = JSON.parse(out.text.trim().split('\n').pop())
  assert.equal(result.verdict, 'pass', JSON.stringify(result))
  assert.equal(code, 0)
  const left = await run(engine, ['ps', '-a', '--filter', `label=${LABEL}`, '--filter', 'name=git-bouncer-[0-9a-f]', '--format', '{{.Names}}'])
  assert.equal(left.stdout.split('\n').filter(n => /^git-bouncer-[0-9a-f]{12}$/.test(n)).length, 0)
})

test('end to end: `bouncer clone` brings over exactly the scanned commit', { skip }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'bouncer-clone-'))
  const cwd = process.cwd()
  try {
    process.chdir(dir)
    const yes = { interactive: true, confirm: async () => true }
    let log = ''
    const code = await main(['clone', 'https://github.com/octocat/Hello-World', 'hello', '--no-snyk', '--runtime', engine], { stdout: { write() {} }, stderr: { write(s) { log += s } }, prompter: yes })
    assert.equal(code, 0)
    const scanned = (log.match(/scanned commit ([0-9a-f]{40})/) || [])[1]
    const readme = await readFile(path.join(dir, 'hello', 'README'), 'utf8')
    assert.match(readme, /Hello World/)
    const head = (await run('git', ['-C', path.join(dir, 'hello'), 'rev-parse', 'HEAD'])).stdout.trim()
    assert.equal(head, scanned, 'the clone must be exactly the commit the sandbox scanned')
    // A second clone into the same folder is refused rather than writing into it.
    const again = await main(['clone', 'https://github.com/octocat/Hello-World', 'hello', '--no-snyk', '--runtime', engine], { stdout: { write() {} }, stderr: { write() {} }, prompter: yes })
    assert.equal(again, 2)
  } finally {
    process.chdir(cwd)
    await rm(dir, { recursive: true, force: true })
  }
})
