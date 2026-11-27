// Command-line entry point. Parses arguments, then hands off to the command.
// Kept small on purpose: parsing and validation here, real work in the modules it calls.

import { parseArgs } from 'node:util'
import { readFileSync } from 'node:fs'
import { parseRepoUrl, validateRef, UsageError } from './url.js'
import { EXIT } from './verdict.js'
import { clean } from './ui/sanitize.js'
import { createOutput } from './ui/output.js'
import { createPrompter } from './ui/prompt.js'

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
  --allow-host <host>           also accept this git host (github.com, gitlab.com, bitbucket.org
                                and codeberg.org are always accepted)
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
  'allow-host': { type: 'string', multiple: true, default: [] },
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
    throw new UsageError(e.message, 'Run "bouncer --help" for usage.')
  }
  const { values, positionals } = parsed
  if (values.help) return { command: 'help' }
  // `--version` means "print the version" only on its own. With a command it's almost certainly a git
  // option passed through a wrapper (`git clone -v <url> --bouncer`), and exiting 0 there would look
  // like a successful check that never happened.
  if (values.version && positionals.length) throw new UsageError('-v/--version can\'t be combined with a command.', 'bouncer clone takes no -v option; run "bouncer --help" for its options.')
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
  if (values.snyk && values['no-snyk']) throw new UsageError('Pass either --snyk or --no-snyk, not both.')
  const allowHosts = values['allow-host'].map(h => h.toLowerCase())
  for (const h of allowHosts) {
    if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(h)) throw new UsageError('--allow-host takes a plain host name, like git.example.com.')
  }
  const options = {
    ref: validateRef(values.ref),
    allowHosts,
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
    const target = parseRepoUrl(rest[0], { allowHosts })
    let dir = null
    if (command === 'clone') {
      if (rest[1] === undefined && target.repo.startsWith('.')) {
        // The repo name is chosen by whoever made the repo. Defaulting the folder to ".git" or
        // ".vscode" would drop its files into YOUR project's config folders. Make the user choose.
        throw new UsageError(`The repo is named "${target.repo}", so it needs a folder name you choose.`, `Example: bouncer clone ${target.display} my-folder`)
      }
      dir = validateDir(rest[1] ?? target.repo)
    }
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

/**
 * The clone destination: a relative path inside the current folder, made of plain names.
 * Refused: absolute paths, "..", Windows drive and network paths, names starting with "-" (option
 * injection) or "." (".git", ".vscode": see CVE-style folder planting), anything that is ".git" once
 * case and trailing dots/spaces are ignored (case-insensitive filesystems), and non-ASCII.
 */
export function validateDir(dir) {
  const refuse = () => { throw new UsageError('That destination folder name is not allowed.', 'Use a plain relative folder name like "my-copy" (letters, digits, - _ . and /).') }
  if (typeof dir !== 'string' || dir.length === 0 || dir.length > 255) refuse()
  if (!/^[A-Za-z0-9._/-]+$/.test(dir)) refuse() // ASCII only; no "\\", ":", spaces or control characters
  const parts = dir.replace(/\/+$/, '').split('/')
  for (const part of parts) {
    const folded = part.toLowerCase().replace(/[. ]+$/, '')
    if (part === '' || part.startsWith('.') || part.startsWith('-') || folded === 'git' || /^git~\d+$/.test(folded)) refuse()
  }
  return parts.join('/')
}

/** Run the CLI. Returns the process exit code instead of exiting, so it's testable. */
export async function main(argv, { asGitSubcommand = false, stdout = process.stdout, stderr = process.stderr, ...deps } = {}) {
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
    case 'scan':
    case 'clone': {
      const { check } = await import('./commands/check.js')
      const out = createOutput(stderr)
      // --json is for scripts: never ask questions, never install anything.
      const prompter = cmd.options.json ? createPrompter({ interactive: false }) : (deps.prompter ?? createPrompter())
      return check(cmd, { out, prompter, stdout, version: VERSION, ...deps })
    }
    case 'doctor': {
      const { doctor } = await import('./commands/doctor.js')
      return doctor({ out: createOutput(stdout) })
    }
    default:
      // The remaining commands arrive in the following pull requests (see the issue tracker).
      stderr.write(`bouncer: "${cmd.command}" is not implemented yet. Follow https://github.com/ylove/git-bouncer/issues\n`)
      return EXIT.ERROR
  }
}
