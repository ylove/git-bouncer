// Make untrusted text safe to print in a terminal.
//
// File names, file contents, package names and error messages from a scanned repo are all
// attacker-controlled. Terminals interpret escape sequences: "\x1b[2K\r" erases the current
// line, "\x1b[1A" moves the cursor up, OSC 8 makes clickable links, and some terminals have
// had escape-sequence bugs that were worse. A malicious file name could print
// "✔ PASS" over the line that said "✖ FAIL". So every untrusted string goes through here.
//
// We don't try to remove only the "dangerous" sequences. We remove every control character,
// and we make invisible or direction-changing Unicode visible as <U+XXXX>.

// ESC-based sequences: CSI (ESC [ ... final), OSC (ESC ] ... BEL or ESC \), and two-character escapes.
// eslint-disable-next-line no-control-regex
const ANSI = /\u001b\[[0-?]*[ -/]*[@-~]|\u001b\][\s\S]*?(?:\u0007|\u001b\\|$)|\u001b[PX^_][\s\S]*?(?:\u001b\\|$)|\u001b[@-Z\\-_]?/g
// Single-byte CSI/OSC introducers from the C1 range (some terminals honor them).
// eslint-disable-next-line no-control-regex
const C0_C1 = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g
const INVISIBLE_OR_BIDI = /[­؜ᅟᅠ᠎​-‏‪-‮⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/gu

const visible = ch => `<U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}>`

/**
 * @param {unknown} value  anything; non-strings are converted with String()
 * @param {{multiline?: boolean, max?: number}} [opts]
 * @returns {string} printable text containing no control characters
 */
export function clean(value, { multiline = false, max = 2000 } = {}) {
  if (value === undefined || value === null) return ''
  let s = String(value)
  if (s.length > max * 4) s = s.slice(0, max * 4) // bound the work before regexes run
  s = s.replace(ANSI, '')
  s = s.replace(/\r\n?/g, '\n')
  s = multiline ? s.replace(/\t/g, '  ') : s.replace(/[\n\t]+/g, ' ')
  s = s.replace(C0_C1, '')
  s = s.replace(INVISIBLE_OR_BIDI, visible)
  if (s.length > max) s = `${s.slice(0, max - 1)}…`
  return s
}
