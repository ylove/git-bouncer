// Make untrusted text safe to print in a terminal.
//
// File names, file contents, package names and error messages from a scanned repo are all
// attacker-controlled. Terminals interpret escape sequences: ESC[2K erases the current line,
// ESC[1A moves the cursor up, OSC 8 makes clickable links, and some terminals have had
// escape-sequence bugs that were worse. A malicious file name could print a fake PASS over the
// line that said FAIL. So every untrusted string goes through here.
//
// Two rules:
//  1. Nothing that a terminal could interpret survives: every escape sequence and every C0/C1
//     control character is replaced.
//  2. Nothing is removed silently. What was there is shown as a visible marker (<ESC>, <CR>,
//     <U+202E>), so a spoof attempt looks like a spoof attempt instead of quietly vanishing.
//
// Invisible characters are matched by Unicode *property* (format characters, line/paragraph
// separators, private use, unassigned, default-ignorable), not by a hand-made list that would
// always be missing something.

// A complete escape sequence: CSI (ESC [ params final), or a string sequence (OSC, DCS, SOS, PM, APC)
// with its terminator (BEL, ESC \, or the 8-bit ST 0x9c) within 512 characters.
const ESC_SEQUENCE = /\x1b\[[0-?]{0,64}[ -/]{0,16}[@-~]|\x1b[\]PX^_][^\x07\x1b\x9c]{0,512}(?:\x07|\x1b\\|\x9c)|\x1b[ -~]?/g
const CONTROL = /[\x00-\x08\x0b-\x1f\x7f-\x9f]/g
const INVISIBLE = /[\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}\p{Default_Ignorable_Code_Point}]/gu

const NAMED = { '\r': '<CR>', '\n': '<LF>', '\t': '<TAB>' }
const codePoint = ch => `<U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}>`

/**
 * @param {unknown} value  anything; non-strings are converted with String()
 * @param {{multiline?: boolean, max?: number}} [opts]
 *   multiline: keep "\n" so text can span lines. Callers that print multiline untrusted text MUST
 *   prefix every line (see ui/output.js), otherwise a line inside the text could look like one of ours.
 * @returns {string} printable text containing no control characters
 */
export function clean(value, { multiline = false, max = 2000 } = {}) {
  if (value === undefined || value === null) return ''
  let s = String(value)
  if (s.length > max * 4) s = s.slice(0, max * 4) // bound the work before regexes run
  s = s.replace(ESC_SEQUENCE, '<ESC>')
  s = s.replace(/\r\n/g, '\n')
  s = multiline
    ? s.replace(/\r/g, '<CR>').replace(/\t/g, '  ')
    : s.replace(/[\r\n\t]/g, ch => NAMED[ch])
  s = s.replace(CONTROL, codePoint)
  s = s.replace(INVISIBLE, codePoint)
  if (s.length > max) s = `${s.slice(0, max - 1)}…`
  return s
}
