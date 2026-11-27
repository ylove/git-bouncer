import { test } from 'node:test'
import assert from 'node:assert/strict'
import { clean } from '../src/ui/sanitize.js'

const ESC = '\u001B'

test('a file name cannot erase the line and print a fake PASS, and the attempt is visible', () => {
  // ESC[2K erases the line, CR returns to column 0, ESC[32m is green: a classic spoof.
  const evil = `innocent.js${ESC}[2K\r${ESC}[32mPASS: no issues found${ESC}[0m`
  const out = clean(evil)
  assert.doesNotMatch(out, /[\u0000-\u001F\u007F-\u009F]/)
  assert.equal(out, 'innocent.js<ESC><CR><ESC>PASS: no issues found<ESC>')
})

test('removes cursor movement, OSC hyperlinks/titles, and C1 control codes', () => {
  assert.equal(clean(`a${ESC}[1A${ESC}[99Db`), 'a<ESC><ESC>b')
  assert.equal(clean(`x${ESC}]8;;https://evil.example/\u0007click${ESC}]8;;\u0007y`), 'x<ESC>click<ESC>y')
  assert.equal(clean(`t${ESC}]0;new window title${ESC}\\u`), 't<ESC>u')
  assert.equal(clean('p\u009B31mq'), 'p<U+009B>31mq') // single-byte CSI
  assert.equal(clean('bell\u0007 backspace\u0008'), 'bell<U+0007> backspace<U+0008>')
})

test('an unterminated OSC or DCS cannot swallow the rest of the line', () => {
  assert.equal(clean(`evil.js${ESC}] FAIL: postinstall downloads a payload`), 'evil.js<ESC> FAIL: postinstall downloads a payload')
  assert.equal(clean(`a${ESC}P no terminator here`), 'a<ESC> no terminator here')
})

test('the 8-bit string terminator ends an OSC', () => {
  assert.equal(clean(`a${ESC}]0;t\u009CVISIBLE\u0007b`), 'a<ESC>VISIBLE<U+0007>b')
})

test('makes invisible, direction-changing and separator characters visible', () => {
  assert.equal(clean('admin\u202E\u2066'), 'admin<U+202E><U+2066>')
  assert.equal(clean('zero\u200Bwidth'), 'zero<U+200B>width')
  assert.equal(clean('tag\u{E0041}'), 'tag<U+E0041>')
  assert.equal(clean('line\u2028sep'), 'line<U+2028>sep')
  assert.equal(clean('cgj\u034F'), 'cgj<U+034F>')
})

test('every format, separator, private-use and default-ignorable code point is made visible', () => {
  const re = /[\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Default_Ignorable_Code_Point}]/u
  const missed = []
  for (let cp = 0; cp <= 0x10FFFF; cp++) {
    if (cp >= 0xD800 && cp <= 0xDFFF) continue // lone surrogates can't be in a well-formed string
    if (cp > 0xFFFF && cp < 0xE0000 && cp % 0x100 !== 0) continue // keep the loop fast; sample astral planes
    const ch = String.fromCodePoint(cp)
    if (re.test(ch) && !clean(ch).startsWith('<U+')) missed.push(cp.toString(16))
  }
  assert.deepEqual(missed, [])
})

test('collapses newlines visibly for single-line fields, keeps them when asked', () => {
  assert.equal(clean('line1\nline2\r\nline3'), 'line1<LF>line2<LF>line3')
  assert.equal(clean('line1\nline2', { multiline: true }), 'line1\nline2')
  assert.equal(clean('a\rb', { multiline: true }), 'a<CR>b')
})

test('bounds length and handles non-strings', () => {
  assert.equal(clean('x'.repeat(5000), { max: 10 }).length, 10)
  assert.equal(clean(undefined), '')
  assert.equal(clean(42), '42')
})

test('stays fast on hostile input (no catastrophic backtracking)', () => {
  const start = process.hrtime.bigint()
  clean(`${ESC}]`.repeat(200000) + `${ESC}[`.repeat(200000), { max: 2_000_000 })
  assert.ok(Number(process.hrtime.bigint() - start) / 1e6 < 1500)
})
