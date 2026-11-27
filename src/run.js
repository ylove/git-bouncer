// Shared entry for both binaries. An unexpected crash must not look like a verdict: it exits with
// EXIT.ERROR (2), never 1 (FAIL) or 0 (PASS), and its message is sanitized like any other output.
import { main } from './cli.js'
import { EXIT } from './verdict.js'
import { clean } from './ui/sanitize.js'

export async function run(argv, opts = {}) {
  try {
    return await main(argv, opts)
  } catch (e) {
    process.stderr.write(`bouncer: internal error: ${clean(e && e.message ? e.message : e)}\n`)
    if (process.env.BOUNCER_DEBUG) process.stderr.write(`${clean(e && e.stack, { multiline: true })}\n`)
    return EXIT.ERROR
  }
}
