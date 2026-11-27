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
  }
}
