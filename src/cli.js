// Command-line entry point. Parses arguments, then hands off to the command.
// Kept small on purpose: parsing and validation here, real work in the modules it calls.

import { parseArgs } from 'node:util'
import { readFileSync } from 'node:fs'
import { parseRepoUrl, validateRef, UsageError } from './url.js'
import { EXIT } from './verdict.js'
import { clean } from './ui/sanitize.js'

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
export const VERSION = pkg.version

const HELP = `bouncer ${VERSION} — a door check for repositories you didn't write

Usage:
  bouncer clone <url> [dir]     ID check, sandboxed pat-down, then asks before cloning to your machine
  git bouncer <url> [dir]       the same, as a git subcommand
  bouncer scan <url>            check only; never touches your disk (exit 0 pass, 1 fail, 3 warn)
  bouncer doctor                show which sandbox runtimes are available
  bouncer shell-init [shell]    print an opt-in function so "git clone <url> --bouncer" works

Options:
  --ref <branch|tag|sha>        check this ref instead of the default branch
  --runtime <name>              docker | podman | codespace | gcp | aws (default: first that works)
  --json                        machine-readable report on stdout (never installs anything)
  --keep                        keep the sandbox afterwards so you can inspect it
  --no-install                  clone to your machine but don't install dependencies
  --snyk / --no-snyk            also run Snyk on the dependency manifests (asks by default if Snyk is set up)
  -h, --help                    show this help
  -v, --version                 show the version

Examples:
  bouncer clone https://github.com/someone/take-home-test
  bouncer scan github.com/owner/repo --ref v1.2.3 --json

Docs: https://github.com/ylove/git-bouncer`

const OPTIONS = {
  ref: { type: 'string' },
  runtime: { type: 'string' },
  json: { type: 'boolean', default: false },
  keep: { type: 'boolean', default: false },
  'no-install': { type: 'boolean', default: false },
  snyk: { type: 'boolean' },
  'no-snyk': { type: 'boolean', default: false },
  help: { type: 'boolean', short: 'h', default: false },
  version: { type: 'boolean', short: 'v', default: false },
}
const RUNTIMES = ['docker', 'podman', 'codespace', 'gcp', 'aws']
const COMMANDS = ['clone', 'scan', 'doctor', 'shell-init', 'help', 'version']

/**
 * Parse argv into a validated command. Throws UsageError for anything malformed.
 * @param {string[]} argv  arguments after the program name
 * @param {{asGitSubcommand?: boolean}} [opts]  true when invoked as `git bouncer ...`
 */
export function parseCommand(argv, { asGitSubcommand = false } = {}) {
  let parsed
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true })
  } catch (e) {
    throw new UsageError(e.message.replace(/^TypeError \[[A-Z_]+\]: /, ''), 'Run "bouncer --help" for usage.')
  }
  const { values, positionals } = parsed
  if (values.help) return { command: 'help' }
  if (values.version) return { command: 'version' }

  let [command, ...rest] = positionals
  // `git bouncer <url>` means clone; `git bouncer scan <url>` still works.
  if (asGitSubcommand && command !== undefined && !COMMANDS.includes(command)) {
    rest = [command, ...rest]
    command = 'clone'
  }
  if (command === undefined) return { command: 'help' }
  if (!COMMANDS.includes(command)) throw new UsageError(`Unknown command "${command}".`, 'Run "bouncer --help" for usage.')

  if (values.runtime !== undefined && !RUNTIMES.includes(values.runtime)) {
    throw new UsageError(`Unknown runtime "${values.runtime}".`, `Choose one of: ${RUNTIMES.join(', ')}.`)
  }
  const options = {
    ref: validateRef(values.ref),
    runtime: values.runtime ?? null,
    json: values.json,
    keep: values.keep,
    install: !values['no-install'],
    snyk: values['no-snyk'] ? false : (values.snyk ?? null),
  }

  if (command === 'clone' || command === 'scan') {
    if (rest.length === 0) throw new UsageError(`"${command}" needs a repository URL.`, `Example: bouncer ${command} https://github.com/owner/repo`)
    const max = command === 'clone' ? 2 : 1
    if (rest.length > max) throw new UsageError(`Too many arguments for "${command}".`)
    const target = parseRepoUrl(rest[0])
    const dir = command === 'clone' ? validateDir(rest[1] ?? target.repo) : null
    return { command, target, dir, options }
  }
  if (command === 'shell-init') {
    const shell = rest[0] ?? null
    if (shell !== null && !['bash', 'zsh', 'fish', 'powershell'].includes(shell)) throw new UsageError(`Unsupported shell "${shell}".`)
    return { command, shell, options }
  }
  if (rest.length) throw new UsageError(`"${command}" takes no arguments.`)
  return { command, options }
}

/** The clone destination must be a plain relative path that can't be read as an option. */
export function validateDir(dir) {
  // eslint-disable-next-line no-control-regex
  if (typeof dir !== 'string' || dir.length === 0 || dir.length > 255 || dir.startsWith('-') || /[\u0000-\u001f\u007f]/.test(dir)) {
    throw new UsageError('That destination folder name is not allowed.')
  }
  return dir
}

/** Run the CLI. Returns the process exit code instead of exiting, so it's testable. */
export async function main(argv, { asGitSubcommand = false, stdout = process.stdout, stderr = process.stderr } = {}) {
  let cmd
  try {
    cmd = parseCommand(argv, { asGitSubcommand })
  } catch (e) {
    if (e instanceof UsageError) {
      stderr.write(`bouncer: ${clean(e.message)}\n`)
      if (e.hint) stderr.write(`  ${clean(e.hint)}\n`)
      return EXIT.ERROR
    }
    throw e
  }

  switch (cmd.command) {
    case 'help':
      stdout.write(`${HELP}\n`)
      return EXIT.PASS
    case 'version':
      stdout.write(`${VERSION}\n`)
      return EXIT.PASS
    default:
      // The commands themselves arrive in the following pull requests (see the issue tracker).
      stderr.write(`bouncer: "${cmd.command}" is not implemented yet. Follow https://github.com/ylove/git-bouncer/issues\n`)
      return EXIT.ERROR
  }
}
