import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { run, trustedPathDirs, which } from '../src/proc.js'

const procModule = pathToFileURL(path.join(import.meta.dirname, '..', 'src', 'proc.js')).href

test('trustedPathDirs drops relative entries, node_modules folders and folders inside the current one', () => {
  const env = { PATH: ['', '.', 'bin', './node_modules/.bin', '/srv/proj/node_modules/.bin', '/srv/proj/bin', '/srv/proj', '/srv/other/node_modules/.bin', '/srv/projX/bin', '/opt/tools/bin', '/usr/bin'].join(':') }
  assert.deepEqual(trustedPathDirs(env, { cwd: '/srv/proj', home: '/srv/me', platform: 'linux' }), ['/srv/projX/bin', '/opt/tools/bin', '/usr/bin'])
  // Case-insensitive filesystems: /SRV/PROJ/bin is inside /srv/proj on macOS.
  assert.deepEqual(trustedPathDirs({ PATH: '/SRV/PROJ/bin:/usr/bin' }, { cwd: '/srv/proj', home: '/srv/me', platform: 'darwin' }), ['/usr/bin'])
})

test('trustedPathDirs: from your home folder (or above it), your own tool folders still count', () => {
  const env = { PATH: '/srv/me/.local/bin:/srv/me/.nvm/versions/node/v24/bin:/srv/me/proj/node_modules/.bin:/usr/bin' }
  const want = ['/srv/me/.local/bin', '/srv/me/.nvm/versions/node/v24/bin', '/usr/bin']
  assert.deepEqual(trustedPathDirs(env, { cwd: '/srv/me', home: '/srv/me', platform: 'linux' }), want)
  assert.deepEqual(trustedPathDirs(env, { cwd: '/', home: '/srv/me', platform: 'linux' }), want)
  // ...but not from inside a project folder.
  assert.deepEqual(trustedPathDirs({ PATH: '/srv/me/proj/.venv/bin:/usr/bin' }, { cwd: '/srv/me/proj', home: '/srv/me', platform: 'linux' }), ['/usr/bin'])
})

test('trustedPathDirs on Windows: only drive paths and network paths, never "\\Tools" or "C:Tools"', () => {
  const PATH = [
    'C:\\Tools', 'c:/Tools2', '"C:\\Program Files\\Git\\cmd"', '\\\\server\\share\\bin',
    '\\Tools', '/Tools', 'C:Tools', '.', '', 'bin',
    'D:\\proj\\bin', 'd:\\PROJ\\scripts', 'C:\\x\\node_modules\\.bin', 'C:\\x\\Node_Modules\\.bin',
  ].join(';')
  assert.deepEqual(trustedPathDirs({ PATH }, { cwd: 'D:\\proj', home: 'C:\\me', platform: 'win32' }), [
    'C:\\Tools', 'c:/Tools2', 'C:\\Program Files\\Git\\cmd', '\\\\server\\share\\bin',
  ])
  assert.deepEqual(trustedPathDirs({ Path: 'C:\\Tools' }, { cwd: 'D:\\proj', home: 'C:\\me', platform: 'win32' }), ['C:\\Tools'])
})

test('which() ignores a program planted in the project, even through an absolute PATH entry (npx, npm run, direnv)', t => {
  const root = mkdtempSync(path.join(tmpdir(), 'bouncer-which-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const win = process.platform === 'win32'
  const plant = dir => {
    mkdirSync(dir, { recursive: true })
    const file = path.join(dir, win ? 'brew.exe' : 'brew')
    writeFileSync(file, '')
    chmodSync(file, 0o755)
    return file
  }
  const project = path.join(root, 'take-home')
  plant(path.join(project, 'node_modules', '.bin'))
  plant(path.join(project, 'bin'))
  const trusted = plant(path.join(root, 'tools'))
  const PATH = [path.join(project, 'node_modules', '.bin'), path.join(project, 'bin'), path.join(root, 'tools')].join(path.delimiter)

  // Run from inside the project, the way `npx bouncer ...` would.
  const lookup = `import { which } from ${JSON.stringify(procModule)}
console.log(await which('brew', { PATH: process.env.LOOKUP_PATH, PATHEXT: '.EXE' }))`
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', lookup], { cwd: project, encoding: 'utf8', env: { ...process.env, LOOKUP_PATH: PATH } })
  assert.equal(child.status, 0, child.stderr)
  const found = child.stdout.trim()
  assert.equal(win ? found.toLowerCase() : found, win ? trusted.toLowerCase() : trusted)
  assert.ok(!found.includes('take-home'))
})

test('which() can be limited to the extensions a program can be started from without a shell', async t => {
  if (process.platform !== 'win32') return t.skip('Windows only')
  const dir = mkdtempSync(path.join(tmpdir(), 'bouncer-ext-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  writeFileSync(path.join(dir, 'tool.cmd'), '@echo off\n')
  assert.ok(await which('tool', { PATH: dir, PATHEXT: '.CMD' }))
  assert.equal(await which('tool', { PATH: dir, PATHEXT: '.CMD' }, { exts: ['.EXE', '.COM'] }), null)
})

test('run() reports the signal that stopped a program, instead of a bare -1', async t => {
  if (process.platform === 'win32') return t.skip('Windows has no POSIX signals')
  const r = await run(process.execPath, ['-e', 'process.kill(process.pid, "SIGTERM"); setTimeout(() => {}, 5000)'])
  assert.equal(r.code, -1)
  assert.equal(r.signal, 'SIGTERM')
  const ok = await run(process.execPath, ['-e', 'process.exit(3)'])
  assert.deepEqual([ok.code, ok.signal], [3, null])
})
