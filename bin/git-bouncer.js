#!/usr/bin/env node
// `git bouncer <url> [dir]`: git runs any program named git-<name> found on your PATH as `git <name>`.
// Here a bare URL means "clone", so `git bouncer <url>` reads like `git clone <url>`.
import { main } from '../src/cli.js'

process.exitCode = await main(process.argv.slice(2), { asGitSubcommand: true })
