// A stand-in for osv-scanner in unit tests: a tiny shell script that records the arguments it was
// given and prints a canned JSON report. Generated at test time in a temp folder, never committed.
// POSIX only (it is a #!/bin/sh script); callers skip on Windows.

import { mkdtemp, writeFile, readFile, chmod, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

/**
 * @param {object} report  what osv-scanner should print (its --format json shape)
 * @param {number} [exitCode]  1 means "vulnerabilities found", like the real tool
 */
export async function fakeOsv(report = { results: [] }, exitCode = 1) {
  const dir = await mkdtemp(path.join(tmpdir(), 'bouncer-fake-osv-'))
  const bin = path.join(dir, 'osv-scanner')
  const argsFile = path.join(dir, 'args.txt')
  const jsonFile = path.join(dir, 'report.json')
  await writeFile(jsonFile, JSON.stringify(report))
  await writeFile(bin, `#!/bin/sh\nprintf '%s\\n' "$@" >> '${argsFile}'\necho '=====' >> '${argsFile}'\ncat '${jsonFile}'\nexit ${exitCode}\n`)
  await chmod(bin, 0o755)
  return {
    bin,
    /** Every invocation's argument list. */
    calls: async () => {
      const text = await readFile(argsFile, 'utf8').catch(() => '')
      return text.split('=====\n').filter(Boolean).map(c => c.split('\n').filter(Boolean))
    },
    cleanup: () => rm(dir, { recursive: true, force: true }),
  }
}
