// Build throwaway fixture folders at test time.
//
// Fixtures are generated, never committed, so cloning this repo doesn't download files that look
// malicious, and git-bouncer scanning its own repo stays clean. The "malicious" content here is inert
// text shaped like real attack techniques: nothing in it runs, and nothing points at a live host.

import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

/** @param {Record<string, string|Buffer>} files  relative path -> content */
export async function fixture(files) {
  const dir = await mkdtemp(path.join(tmpdir(), 'bouncer-fixture-'))
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel)
    await mkdir(path.dirname(abs), { recursive: true })
    await writeFile(abs, content)
  }
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) }
}

/** Assemble a string from parts so this source file never contains the literal pattern it tests. */
export const j = (...parts) => parts.join('')
