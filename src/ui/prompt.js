// Yes/no prompts. Without a terminal there is nobody to ask, so every question gets its safe answer
// (which is never "install something on this machine").

import { createInterface } from 'node:readline/promises'

export function createPrompter({ input = process.stdin, output = process.stderr, interactive = Boolean(process.stdin.isTTY && output.isTTY) } = {}) {
  return {
    interactive,
    /**
     * @param {string} question  our own text (never repo-derived)
     * @param {{defaultYes?: boolean, safeAnswer?: boolean}} [opts]
     *   safeAnswer: the answer used when nobody can be asked (defaults to false)
     */
    async confirm(question, { defaultYes = false, safeAnswer = false } = {}) {
      if (!interactive) return safeAnswer
      const rl = createInterface({ input, output })
      try {
        const answer = (await rl.question(`${question} ${defaultYes ? '[Y/n]' : '[y/N]'} `)).trim().toLowerCase()
        if (answer === '') return defaultYes
        return answer === 'y' || answer === 'yes'
      } finally { rl.close() }
    },
    /**
     * Pick one option by number. Our own text only. Without a terminal, nobody chose: returns null.
     * @param {string} question
     * @param {{key: string, label: string}[]} options
     */
    async choose(question, options) {
      if (!interactive) return null
      const rl = createInterface({ input, output })
      try {
        output.write(`${question}\n${options.map((o, i) => `  ${i + 1}) ${o.label}`).join('\n')}\n`)
        const answer = (await rl.question(`Choose 1-${options.length}: `)).trim()
        const n = Number.parseInt(answer, 10)
        return Number.isInteger(n) && n >= 1 && n <= options.length && String(n) === answer ? options[n - 1].key : null
      } finally { rl.close() }
    },
  }
}
