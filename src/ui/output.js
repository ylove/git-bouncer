// Human-readable output. Every string that came from the scanned repo goes through clean(), and
// multiline untrusted text is indented under a fixed prefix so it can never look like our own lines.

import { clean } from './sanitize.js'

const useColor = stream => Boolean(stream.isTTY) && !process.env.NO_COLOR && process.env.TERM !== 'dumb'

export function createOutput(stream = process.stderr) {
  const color = useColor(stream)
  const paint = (code, s) => (color ? `\u001B[${code}m${s}\u001B[0m` : s)
  const c = {
    bold: s => paint('1', s), dim: s => paint('2', s), red: s => paint('31', s), green: s => paint('32', s),
    yellow: s => paint('33', s), cyan: s => paint('36', s),
  }
  const write = s => stream.write(`${s}\n`)
  const sev = {
    critical: s => c.red(c.bold(s)), high: s => c.red(s), medium: s => c.yellow(s), low: s => c.cyan(s), info: s => c.dim(s),
  }
  const badge = s => (sev[s] || c.red)(`[${clean(s, { max: 12 })}]`)

  return {
    c,
    line: (s = '') => write(s),
    step: s => write(`${c.bold('\u203A')} ${s}`),
    note: s => write(`  ${c.dim(s)}`),
    // Progress lines from the sandbox are untrusted (they can include repo-derived text): clean and dim them.
    progress: s => { for (const l of String(s).split('\n')) if (l.trim()) write(`  ${c.dim(`│ ${clean(l, { max: 200 })}`)}`) },

    findings(list) {
      const order = ['critical', 'high', 'medium', 'low', 'info']
      const sorted = [...list].sort((a, b) => (order.indexOf(a.severity) + 9) % 9 - (order.indexOf(b.severity) + 9) % 9)
      for (const f of sorted) {
        write(`  ${badge(f.severity)} ${c.bold(clean(f.title, { max: 200 }))} ${c.dim(clean(f.id, { max: 64 }))}`)
        const where = [f.file && clean(f.file, { max: 200 }), f.line && `line ${f.line}`].filter(Boolean).join(', ')
        if (where) write(`      ${c.dim('where:')} ${where}`)
        if (f.evidence) write(`      ${c.dim('what: ')} ${clean(f.evidence, { max: 240 })}`)
        if (f.detail) write(`      ${c.dim('why:  ')} ${clean(f.detail, { max: 600 })}`)
      }
    },

    verdict(v, counts) {
      const tally = ['critical', 'high', 'medium', 'low', 'info', 'unknown'].filter(k => counts[k]).map(k => `${counts[k]} ${k}`).join(', ') || 'no findings'
      const text = {
        pass: c.green(c.bold('✔ LET IN')) + c.green('  No red flags found.'),
        warn: c.yellow(c.bold('\u25B2 WARNING')) + c.yellow('  Nothing that clearly attacks you, but look at the warnings above first.'),
        fail: c.red(c.bold('✖ TURNED AWAY')) + c.red('  This repo shows signs it could attack your machine.'),
        incomplete: c.yellow(c.bold('? INCOMPLETE')) + c.yellow('  The pat-down did not finish, so this is not a clean result.'),
      }[v]
      write('')
      write(`${text}  ${c.dim(`(${tally})`)}`)
    },
  }
}
