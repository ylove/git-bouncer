// Auto-run checks: things that execute just because you OPENED the folder, started an AI
// agent in it, or ran the project's normal commands. No install step required.
//
// Paths are compared the way macOS and Windows compare them (see ../paths.js): there, `.VSCode/tasks.json`
// and a spelling with a Unicode look-alike letter ARE `.vscode/tasks.json` as far as the editor is
// concerned. When several spellings exist, every one is checked and the worst result is kept.

import { readFile, readdir, stat } from 'node:fs/promises'
import path from 'node:path'
import { foldPath } from '../paths.js'

// Something fetched from the network and run, or decoded and run. (A plain URL is not enough here:
// MCP configs legitimately point at remote servers.)
const FETCH_AND_RUN = /(\b(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,300}?(\||;|&&)\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(iex|Invoke-Expression)\b|powershell(\.exe)?\s+(-\w+\s+)*-(e|enc|encodedcommand)\b|base64\s+(-d|--decode)|\batob\s*\(|\b(curl|wget)\b[^\n]{0,200}?-o\s*\S+[^\n]{0,80}?(chmod|\bsh\b|bash|node|python))/i

/** Parse JSON-with-comments (VS Code, devcontainer) without evaluating anything. Tolerates a BOM. */
export function parseJsonc(text) {
  text = text.replace(/^\uFEFF/, '')
  let out = ''
  let inStr = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    const n = text[i + 1]
    if (inStr) {
      out += c
      if (c === '\\') { out += n ?? ''; i++ } else if (c === '"') inStr = false
      continue
    }
    if (c === '"') { inStr = true; out += c; continue }
    if (c === '/' && n === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; continue }
    if (c === '/' && n === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i++; continue }
    out += c
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'))
}

/** JSON string escapes decoded, so text fallbacks see "folderOpen" even if it was written folderOpen. */
const unescapeJson = t => t.replace(/^\uFEFF/, '').replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(Number.parseInt(h, 16)))

/**
 * Every file a few folders deep, with its folded path. Breadth-first, so the shallow auto-run locations
 * are always listed before the cap is reached, however big the rest of the repo is.
 * @returns {Promise<{rel: string, fold: string}[]>}
 */
async function fileIndex(root, maxDepth = 5, cap = 50000) {
  const out = []
  let level = ['']
  for (let depth = 0; level.length && depth <= maxDepth; depth++) {
    const next = []
    for (const rel of level) {
      let entries
      try { entries = await readdir(path.join(root, rel), { withFileTypes: true }) } catch { continue }
      for (const e of entries) {
        const r = rel ? `${rel}/${e.name}` : e.name
        if (e.isDirectory()) {
          if (e.name !== '.git' && foldPath(e.name) !== 'node_modules') next.push(r)
        } else if (e.isFile()) {
          out.push({ rel: r, fold: foldPath(r) })
          if (out.length >= cap) return out
        }
      }
    }
    level = next
  }
  return out
}

const cmdText = v => (Array.isArray(v) ? v.map(cmdText).join(' ') : typeof v === 'object' && v ? Object.values(v).map(cmdText).join(' ; ') : String(v ?? ''))

// Workspace settings that make VS Code run a program from the repo (Workspace Trust guards these,
// but people click "Trust" on take-home tests all the time).
const VSCODE_EXEC_SETTINGS = /^(typescript\.tsdk|eslint\.(nodePath|runtime)|python\.(defaultInterpreterPath|pythonPath)|git\.path|terminal\.integrated\.(profiles|shell|shellArgs|automationProfile|env)\.?|php\.validate\.executablePath|go\.(alternateTools|goroot)|rust-analyzer\.server\.path|.*\.(executablePath|serverPath|binaryPath))/
// Claude Code settings that run a shell command, not just hooks.
const CLAUDE_COMMAND_SETTINGS = ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper']

export async function autorunChecks(root, findings) {
  const index = await fileIndex(root)
  const byFold = new Map()
  for (const f of index) {
    if (!byFold.has(f.fold)) byFold.set(f.fold, [])
    byFold.get(f.fold).push(f.rel)
  }
  const read = async rel => {
    try { return { rel, text: await readFile(path.join(root, rel), 'utf8') } } catch { return null }
  }
  /** Every spelling of `rel` that exists in the repo (".vscode/tasks.json", ".VSCode/tasks.json", ...), read. */
  const readAll = async rel => (await Promise.all((byFold.get(foldPath(rel)) ?? []).map(read))).filter(Boolean)
  /** Real spellings of every file whose folded path matches `re` (write `re` in lowercase). */
  const matching = re => index.filter(f => re.test(f.fold)).map(f => f.rel)
  const unparsable = rel => findings.add({ id: 'AUTORUN-CONFIG-UNPARSABLE', severity: 'medium', file: rel,
    title: `${rel} could not be parsed`,
    detail: 'Editors and agents read these files leniently, so a file that breaks a strict parser may still run commands. Its contents were checked with text matching instead.' })

  // 1. VS Code tasks that run on folder open (in .vscode/tasks.json or any *.code-workspace file).
  const taskSources = [...await readAll('.vscode/tasks.json'), ...(await Promise.all(matching(/^[^/]*\.code-workspace$/).slice(0, 10).map(read))).filter(Boolean)]
  for (const { rel, text } of taskSources) {
    let flagged = false
    let parsed = true
    try {
      const conf = parseJsonc(text)
      const tasks = (foldPath(rel).endsWith('.code-workspace') ? conf.tasks?.tasks : conf.tasks) || []
      for (const t of Array.isArray(tasks) ? tasks : []) {
        if (t?.runOptions?.runOn === 'folderOpen') {
          flagged = true
          findings.add({
            id: 'AUTORUN-VSCODE-FOLDEROPEN', severity: 'high', file: rel,
            evidence: cmdText([t.command, ...(Array.isArray(t.args) ? t.args : [])]).slice(0, 200),
            title: 'VS Code task runs automatically when the folder is opened',
            detail: '`"runOn": "folderOpen"` runs this command the moment you open the repo in VS Code (or Cursor). Recent campaigns, PolinRider included, used this to run malware without any install step.',
          })
        }
      }
    } catch { parsed = false; unparsable(rel) }
    if (!flagged && /"runOn"\s*:\s*"folderOpen"/.test(unescapeJson(text))) {
      findings.add({ id: 'AUTORUN-VSCODE-FOLDEROPEN', severity: 'high', file: rel,
        title: 'VS Code task runs automatically when the folder is opened',
        detail: `The file contains \`"runOn": "folderOpen"\`${parsed ? '' : ' (and couldn\'t be parsed cleanly, which is itself unusual)'}.` })
    }
  }

  // 2. VS Code settings that point at executables.
  for (const settings of await readAll('.vscode/settings.json')) {
    try {
      const keys = Object.keys(parseJsonc(settings.text)).filter(k => VSCODE_EXEC_SETTINGS.test(k))
      if (keys.length) {
        findings.add({ id: 'AUTORUN-VSCODE-SETTINGS', severity: 'medium', file: settings.rel, evidence: keys.slice(0, 6).join(', '),
          title: 'Workspace settings choose which programs VS Code runs',
          detail: 'These settings can make the editor execute a binary or script from the repo once you trust the workspace.' })
      }
    } catch { unparsable(settings.rel) }
  }

  // 3. Dev containers (root and named configs): initializeCommand runs on YOUR HOST.
  const devcontainers = matching(/^(\.devcontainer\/devcontainer\.json|\.devcontainer\.json|\.devcontainer\/[^/]+\/devcontainer\.json)$/).slice(0, 20)
  for (const rel of devcontainers) {
    const { text } = (await read(rel)) ?? {}
    if (text === undefined) continue
    let conf = null
    try { conf = parseJsonc(text) } catch { unparsable(rel) }
    const flat = unescapeJson(text)
    const init = conf ? conf.initializeCommand : (flat.match(/"initializeCommand"\s*:\s*("([^"\\]|\\.)*"|\[[^\]]*\])/) || [])[1]
    if (init) {
      findings.add({ id: 'AUTORUN-DEVCONTAINER-HOST', severity: 'high', file: rel, evidence: cmdText(init).slice(0, 200),
        title: 'Dev container runs a command on your host machine',
        detail: '`initializeCommand` runs on your own computer (not in the container) when you "Reopen in Container" or create a Codespace from this repo.' })
    }
    if (conf) {
      const inContainer = ['onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand'].filter(k => conf[k])
      if (inContainer.length) {
        const all = inContainer.map(k => cmdText(conf[k])).join(' ; ')
        findings.add({ id: 'AUTORUN-DEVCONTAINER', severity: FETCH_AND_RUN.test(all) ? 'medium' : 'low', file: rel, evidence: all.slice(0, 200),
          title: `Dev container lifecycle commands: ${inContainer.join(', ')}`,
          detail: 'These run inside the container (or Codespace) when it is created or started, with whatever tokens that environment has.' })
      }
    }
    const mounts = conf ? JSON.stringify([conf.mounts ?? [], conf.runArgs ?? [], conf.workspaceMount ?? '']) : flat
    if (/\.ssh|\.aws|\.config|\.npmrc|\.gitconfig|\.kube|docker\.sock|--privileged|localEnv:HOME|localEnv:USERPROFILE/i.test(mounts) && /(mounts|runArgs|workspaceMount)/.test(conf ? 'mounts' : flat)) {
      findings.add({ id: 'AUTORUN-DEVCONTAINER-MOUNTS', severity: 'high', file: rel, evidence: mounts.slice(0, 200),
        title: 'Dev container mounts your credentials or gets privileged access',
        detail: 'Mounting ~/.ssh, cloud credentials or the Docker socket into the container hands them to whatever code runs inside.' })
    }
  }

  // 4. AI coding agents: hooks, helper commands and MCP servers start processes on their own.
  for (const f of [...await readAll('.claude/settings.json'), ...await readAll('.claude/settings.local.json')]) {
    let conf = null
    try { conf = parseJsonc(f.text) } catch { unparsable(f.rel) }
    const parts = []
    if (conf) {
      if (conf.hooks && Object.keys(conf.hooks).length) parts.push(`hooks: ${cmdText(conf.hooks)}`)
      if (conf.statusLine && conf.statusLine.command) parts.push(`statusLine: ${cmdText(conf.statusLine.command)}`)
      for (const k of CLAUDE_COMMAND_SETTINGS) if (conf[k]) parts.push(`${k}: ${cmdText(conf[k])}`)
    } else if (/"(hooks|statusLine|apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper)"/.test(unescapeJson(f.text))) {
      parts.push(unescapeJson(f.text).slice(0, 300))
    }
    if (parts.length) {
      const all = parts.join(' | ')
      findings.add({ id: 'AUTORUN-AGENT-HOOKS', severity: FETCH_AND_RUN.test(all) ? 'high' : 'medium', file: f.rel,
        evidence: all.slice(0, 200), title: 'Repo configures commands your AI agent runs automatically',
        detail: 'Hooks, the status line and helper settings are shell commands an AI coding agent runs on its own (on session start, on tool use, to fetch keys). A repo that ships them can run code as soon as you point an agent at it.' })
    }
  }
  for (const f of (await Promise.all(['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json', '.gemini/settings.json', '.roo/mcp.json'].map(readAll))).flat()) {
    try {
      const conf = parseJsonc(f.text)
      const servers = conf.mcpServers || conf.servers || {}
      const cmds = Object.entries(servers).filter(([, s]) => s && s.command).map(([n, s]) => `${n}: ${cmdText([s.command, ...(Array.isArray(s.args) ? s.args : [])])}`)
      if (cmds.length) {
        findings.add({ id: 'AUTORUN-AGENT-MCP', severity: FETCH_AND_RUN.test(cmds.join(' ')) ? 'high' : 'medium', file: f.rel,
          evidence: cmds.join(' | ').slice(0, 200), title: 'Repo configures MCP servers that launch local commands',
          detail: 'If you approve the project\'s MCP servers, your AI agent will start these programs on your machine.' })
      }
    } catch {
      unparsable(f.rel)
      if (/"command"\s*:/.test(unescapeJson(f.text))) findings.add({ id: 'AUTORUN-AGENT-MCP', severity: 'medium', file: f.rel,
        title: 'Repo configures MCP servers that launch local commands', detail: 'The file couldn\'t be parsed, but it contains server commands.' })
    }
  }

  // 5. Hidden instructions for AI agents in instruction files.
  for (const f of (await Promise.all(['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.cursorrules', '.github/copilot-instructions.md', '.windsurfrules'].map(readAll))).flat()) {
    if (FETCH_AND_RUN.test(f.text)) {
      findings.add({ id: 'AUTORUN-AGENT-INSTRUCTIONS', severity: 'medium', file: f.rel,
        title: 'Agent instruction file tells the agent to download and run something',
        detail: 'Instruction files are read by AI coding agents as if you wrote them. Download-and-execute commands here are a prompt-injection risk.' })
    }
  }

  // 6. Git hook managers wire commands into your commits after install: every husky hook, not just four names.
  for (const rel of matching(/^\.husky\/[^/_][^/]*$/).slice(0, 50)) {
    const st = await stat(path.join(root, rel)).catch(() => null)
    if (!st || st.size > 256 * 1024) continue
    const { text } = (await read(rel)) ?? {}
    if (text === undefined) continue
    if (FETCH_AND_RUN.test(text) || /https?:\/\//.test(text)) {
      findings.add({ id: 'AUTORUN-GIT-HOOK', severity: 'high', file: rel, evidence: text.trim().slice(0, 200),
        title: 'Git hook downloads or executes code',
        detail: 'Husky installs these hooks during `npm install` (via the prepare script); after that they run on every commit, checkout or push.' })
    }
  }
}
