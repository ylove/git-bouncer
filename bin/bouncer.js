#!/usr/bin/env node
// `bouncer <command> ...`
import { run } from '../src/run.js'

process.exitCode = await run(process.argv.slice(2))
