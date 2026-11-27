import { test } from 'node:test'
import assert from 'node:assert/strict'
import { clean } from '../src/ui/sanitize.js'

test('a file name cannot erase the line and print a fake PASS', () => {
  // ESC[2K erases the line, \r returns to column 0, ESC[32m is green: a classic spoof.
  const evil = 'innocent.js\u001b[2K\r\u001b[32m✔ PASS: no issues found\u001b[0m'
  const out = clean(evil)
  assert.doesNotMatch(out, /\u001b|\r/)
  assert.equal(out, 'innocent.js ✔ PASS: no issues found') // still visible, but now obviously part of the name
})

test('removes cursor movement, OSC hyperlinks/titles, and C1 control codes', () => {
  assert.equal(clean('a\u001b[1A\u001b[99Db'), 'ab')
  assert.equal(clean('x\u001b]8;;https://evil.example/\u0007click\u001b]8;;\u0007y'), 'xclicky')
  assert.equal(clean('t\u001b]0;new window title\u001b\\u'), 'tu')
  assert.equal(clean('p\u009b31mq'), 'p31mq') // single-byte CSI
  assert.equal(clean('bell\u0007 backspace\u0008'), 'bell backspace')
})

test('makes invisible and direction-changing characters visible', () => {
  assert.equal(clean('admin‮⁦'), 'admin<U+202E><U+2066>')
  assert.equal(clean('zero​width'), 'zero<U+200B>width')
  assert.equal(clean('tag\u{E0041}'), 'tag<U+E0041>')
})

test('collapses newlines for single-line fields, keeps them when asked', () => {
  assert.equal(clean('line1\nline2\r\nline3'), 'line1 line2 line3')
  assert.equal(clean('line1\nline2', { multiline: true }), 'line1\nline2')
})

test('bounds length and handles non-strings', () => {
  assert.equal(clean('x'.repeat(5000), { max: 10 }).length, 10)
  assert.equal(clean(undefined), '')
  assert.equal(clean(42), '42')
})
