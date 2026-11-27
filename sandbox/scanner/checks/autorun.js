// Auto-run checks: things that execute just because you OPENED the folder, started an AI
// agent in it, or ran the project's normal commands. No install step required.

import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { DOWNLOAD_EXEC } from './content.js'

/** Parse JSON-with-comments (VS Code, devcontainer) without evaluating anything. */
export function parseJsonc(text) {
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

async function readText(root, rel) {
  try { return await readFile(path.join(root, rel), 'utf8') } catch { return null }
}

const cmdText = v => (Array.isArray(v) ? v.map(cmdText).join(' ') : typeof v === 'object' && v ? Object.values(v).map(cmdText).join(' ; ') : String(v ?? ''))

// Workspace settings that make VS Code run a program from the repo (Workspace Trust guards these,
// but people click "Trust" on take-home tests all the time).
const VSCODE_EXEC_SETTINGS = /^(typescript\.tsdk|eslint\.(nodePath|runtime)|python\.(defaultInterpreterPath|pythonPath)|git\.path|terminal\.integrated\.(profiles|shell|shellArgs|automationProfile|env)\.?|php\.validate\.executablePath|go\.(alternateTools|goroot)|rust-analyzer\.server\.path|.*\.(executablePath|serverPath|binaryPath))/

export async function autorunChecks(root, findings) {
  // 1. VS Code tasks that run on folder open.
  const tasksText = await readText(root, '.vscode/tasks.json')
  if (tasksText) {
    let flagged = false
    try {
      const tasks = parseJsonc(tasksText).tasks || []
      for (const t of tasks) {
        if (t?.runOptions?.runOn === 'folderOpen') {
          flagged = true
          findings.add({
            id: 'AUTORUN-VSCODE-FOLDEROPEN', severity: 'high', file: '.vscode/tasks.json',
            evidence: cmdText([t.command, ...(t.args || [])]).slice(0, 200),
            title: 'VS Code task runs automatically when the folder is opened',
            detail: '`"runOn": "folderOpen"` runs this command the moment you open the repo in VS Code (or Cursor). Recent campaigns, PolinRider included, used this to run malware without any install step.',
          })
        }
      }
    } catch { /* fall through to the text match */ }
    if (!flagged && /"runOn"\s*:\s*"folderOpen"/.test(tasksText)) {
      findings.add({ id: 'AUTORUN-VSCODE-FOLDEROPEN', severity: 'high', file: '.vscode/tasks.json',
        title: 'VS Code task runs automatically when the folder is opened',
        detail: 'The file contains `"runOn": "folderOpen"` (it couldn\'t be parsed cleanly, which is itself unusual).' })
    }
  }

  // 2. VS Code settings that point at executables.
  const settingsText = await readText(root, '.vscode/settings.json')
  if (settingsText) {
    try {
      const keys = Object.keys(parseJsonc(settingsText)).filter(k => VSCODE_EXEC_SETTINGS.test(k))
      if (keys.length) {
        findings.add({ id: 'AUTORUN-VSCODE-SETTINGS', severity: 'medium', file: '.vscode/settings.json', evidence: keys.slice(0, 6).join(', '),
          title: 'Workspace settings choose which programs VS Code runs',
          detail: 'These settings can make the editor execute a binary or script from the repo once you trust the workspace.' })
      }
    } catch { /* unparsable settings aren't executable either */ }
  }

  // 3. Dev containers: initializeCommand runs on YOUR HOST, before any container exists.
  for (const rel of ['.devcontainer/devcontainer.json', '.devcontainer.json']) {
    const text = await readText(root, rel)
    if (!text) continue
    let conf
    try { conf = parseJsonc(text) } catch { continue }
    if (conf.initializeCommand) {
      findings.add({ id: 'AUTORUN-DEVCONTAINER-HOST', severity: 'high', file: rel, evidence: cmdText(conf.initializeCommand).slice(0, 200),
        title: 'Dev container runs a command on your host machine',
        detail: '`initializeCommand` runs on your own computer (not in the container) when you "Reopen in Container" or create a Codespace from this repo.' })
    }
    const inContainer = ['onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand'].filter(k => conf[k])
    if (inContainer.length) {
      const all = inContainer.map(k => cmdText(conf[k])).join(' ; ')
      findings.add({ id: 'AUTORUN-DEVCONTAINER', severity: DOWNLOAD_EXEC.test(all) ? 'medium' : 'low', file: rel, evidence: all.slice(0, 200),
        title: `Dev container lifecycle commands: ${inContainer.join(', ')}`,
        detail: 'These run inside the container (or Codespace) when it is created or started, with whatever tokens that environment has.' })
    }
    const mounts = JSON.stringify(conf.mounts || []) + JSON.stringify(conf.runArgs || [])
    if (/\.ssh|\.aws|\.config|\.npmrc|\.gitconfig|docker\.sock|--privileged|source=\$\{localEnv:HOME/i.test(mounts)) {
      findings.add({ id: 'AUTORUN-DEVCONTAINER-MOUNTS', severity: 'high', file: rel, evidence: mounts.slice(0, 200),
        title: 'Dev container mounts your credentials or gets privileged access',
        detail: 'Mounting ~/.ssh, cloud credentials or the Docker socket into the container hands them to whatever code runs inside.' })
    }
  }

  // 4. AI coding agents: hooks and MCP servers start processes when the agent starts.
  const claude = await readText(root, '.claude/settings.json')
  if (claude) {
    try {
      const hooks = parseJsonc(claude).hooks
      if (hooks && Object.keys(hooks).length) {
        const all = cmdText(hooks)
        findings.add({ id: 'AUTORUN-AGENT-HOOKS', severity: DOWNLOAD_EXEC.test(all) ? 'high' : 'medium', file: '.claude/settings.json',
          evidence: all.slice(0, 200), title: 'Repo defines AI-agent hooks',
          detail: 'Hooks are shell commands an AI coding agent runs automatically on events (session start, tool use). A repo that ships them can run code as soon as you point an agent at it.' })
      }
    } catch { /* ignore */ }
  }
  for (const rel of ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json', '.gemini/settings.json']) {
    const text = await readText(root, rel)
    if (!text) continue
    try {
      const conf = parseJsonc(text)
      const servers = conf.mcpServers || conf.servers || {}
      const cmds = Object.entries(servers).filter(([, s]) => s && s.command).map(([n, s]) => `${n}: ${cmdText([s.command, ...(s.args || [])])}`)
      if (cmds.length) {
        findings.add({ id: 'AUTORUN-AGENT-MCP', severity: DOWNLOAD_EXEC.test(cmds.join(' ')) ? 'high' : 'medium', file: rel,
          evidence: cmds.join(' | ').slice(0, 200), title: 'Repo configures MCP servers that launch local commands',
          detail: 'If you approve the project\'s MCP servers, your AI agent will start these programs on your machine.' })
      }
    } catch { /* ignore */ }
  }

  // 5. Hidden instructions for AI agents in instruction files.
  for (const rel of ['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.cursorrules', '.github/copilot-instructions.md']) {
    const text = await readText(root, rel)
    if (text && DOWNLOAD_EXEC.test(text) && /\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n]*\|\s*(ba|z)?sh|\bnode\s+-e\b|\bpowershell\b[^\n]*-e/i.test(text)) {
      findings.add({ id: 'AUTORUN-AGENT-INSTRUCTIONS', severity: 'medium', file: rel,
        title: 'Agent instruction file tells the agent to download and run something',
        detail: 'Instruction files are read by AI coding agents as if you wrote them. Download-and-execute commands here are a prompt-injection risk.' })
    }
  }

  // 6. Git hook managers wire commands into your commits after install.
  for (const rel of ['.husky/pre-commit', '.husky/post-checkout', '.husky/post-merge', '.husky/pre-push']) {
    const text = await readText(root, rel)
    if (text && DOWNLOAD_EXEC.test(text)) {
      findings.add({ id: 'AUTORUN-GIT-HOOK', severity: 'high', file: rel, evidence: text.trim().slice(0, 200),
        title: 'Git hook downloads or executes code',
        detail: 'Husky installs these hooks during `npm install` (via the prepare script); after that they run on every commit, checkout or push.' })
    }
  }
}
