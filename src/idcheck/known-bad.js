// Known-bad repositories from public malware reporting, for the ID check.
//
// The indicators live in one place: the sandbox scanner's dated IOC snapshot
// (sandbox/scanner/checks/iocs.js). The host reads the same list, so the two can never disagree. Only
// that data module is loaded on your machine. It has no side effects, and none of the scanner's checks
// run here.
//
// It's loaded when it's needed instead of imported at the top of the file. If it's missing (a broken
// install, or a checkout that predates it), the ID check still runs and reports that this list wasn't
// checked, instead of crashing or quietly skipping it. A file that exists but fails to load is a bug,
// and that error is not swallowed.

import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const IOC_MODULE = new URL('../../sandbox/scanner/checks/iocs.js', import.meta.url)

/**
 * @param {URL} [moduleUrl]
 * @returns {Promise<null | {campaigns: Array<{campaign: string, source: string, repos?: string[]}>, date: string|null}>}
 *   null when the snapshot file isn't there.
 */
export async function loadIocs(moduleUrl = IOC_MODULE) {
  if (!existsSync(fileURLToPath(moduleUrl))) return null
  const { IOCS, IOC_SNAPSHOT_DATE } = await import(moduleUrl.href)
  if (!Array.isArray(IOCS)) throw new Error('The IOC snapshot does not export an IOCS list.')
  return { campaigns: IOCS, date: typeof IOC_SNAPSHOT_DATE === 'string' ? IOC_SNAPSHOT_DATE : null }
}

/**
 * Index the campaigns' repos by lowercase "owner/repo", and by owner (the account that published them).
 * GitHub names ignore case, so "Carol-White-Super/cloud" and "carol-white-super/CLOUD" are one repo.
 */
export function indexIocRepos(campaigns) {
  const repos = new Map()
  const owners = new Map()
  for (const campaign of campaigns) {
    for (const entry of campaign.repos ?? []) {
      if (typeof entry !== 'string' || !/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(entry)) continue
      const key = entry.toLowerCase()
      repos.set(key, { campaign, repo: entry })
      const owner = key.split('/')[0]
      if (!owners.has(owner)) owners.set(owner, { campaign, repo: entry })
    }
  }
  return { repos, owners }
}
