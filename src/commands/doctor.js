// `bouncer doctor`: what can git-bouncer use on this machine?

import { createContainerRuntime } from '../runtimes/container.js'
import { has } from '../proc.js'
import { snykReady } from '../snyk.js'
import { EXIT } from '../verdict.js'

export async function doctor({ out }) {
  out.line(out.c.bold('Sandbox runtimes'))
  let any = false
  for (const engine of ['docker', 'podman']) {
    const a = await createContainerRuntime(engine).available()
    any ||= a.ok
    out.line(`  ${a.ok ? out.c.green('✔') : out.c.dim('·')} ${engine.padEnd(9)} ${a.ok ? `ready (engine ${a.version})` : a.reason}`)
  }
  out.line()
  out.line(out.c.bold('Optional extras'))
  out.line(`  ${await has('gh') ? out.c.green('✔') : out.c.dim('·')} gh        ${await has('gh') ? 'installed (GitHub API look-ups use your login; Codespaces fallback coming)' : 'not installed (ID check uses the anonymous GitHub API)'}`)
  const snyk = await has('snyk')
  out.line(`  ${snyk && await snykReady() ? out.c.green('✔') : out.c.dim('·')} snyk      ${snyk ? (await snykReady() ? 'signed in (offered after the pat-down)' : 'installed but not signed in') : 'not installed (optional)'}`)
  out.line()
  out.line(any ? 'Ready. Try: bouncer scan https://github.com/octocat/Hello-World' : 'No sandbox runtime yet. Install Podman (free, open source, no account) or Docker.')
  return any ? EXIT.PASS : EXIT.ERROR
}
