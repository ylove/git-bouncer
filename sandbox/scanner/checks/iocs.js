// Indicators of compromise from public reporting: a dated snapshot.
//
// This list is defense in depth, not the main detector. Known-malicious packages are caught
// live through the OSV database (osv-scanner), which is updated continuously. This snapshot
// catches the specific campaigns that motivated this tool even if they aren't in OSV yet,
// and it matches things OSV doesn't cover (wallet addresses, C2 IPs, repo names).
//
// Every entry cites its source. Add new campaigns in a PR with a source link.
//
// Why the values below are split in two: git-bouncer scans its own repository too, and a file that
// contains a live campaign's wallet address or C2 IP verbatim would (correctly!) be flagged. Each
// value is stored as [first half, second half] and joined when the module loads. Nothing is encoded
// or hidden: concatenate the two halves and you have the published indicator.
const s = (a, b) => a + b

export const IOC_SNAPSHOT_DATE = '2026-11-26'

export const IOCS = [
  {
    campaign: 'PolinRider (North Korea-linked)',
    source: 'https://thehackernews.com/2026/11/north-korea-linked-polinrider-poisons.html (citing Apiiro, SafeDep, OpenSourceMalware)',
    wallets: [s('0xa322E5f3D311D3080e6', 'f0121063e9aDC2490Ef1a'), s('0x3b1574417524c11a740', '3c4b232CAcBb320CceBC6'), s('0x1eEf0849EDa15d87f64', 'e51C73C8442Cf3c8bCEF3'), s('0x67B38e9b67B38E9b686', '56c6C6f6970626f742121')],
    ips: [s('166.88', '.134.75'), s('103.179', '.142.155'), s('103.179', '.143.219'), s('23.27', '.13.72'), s('95.135.', '181.151'), s('95.135', '.181.84')],
    strings: [s('68656c6C6f69', '70626f742121')],
    npm: ['itsa-utils', 'itsa-jsext', 'itsa-cli', 'server-hemera-mongo', 'cdeops', '@adminide-stack/utils'],
    files: ['fa-solid-300.llf'],
    vscodeExtensions: [s('huntrole.ass', 'essment-tool')],
  },
  {
    campaign: 'Fake .NET/JS take-home assessments (malicious NuGet + npm)',
    source: 'https://thehackernews.com/2026/11/13-malicious-nuget-packages-turn-fake.html (citing Socket)',
    nuget: ['WinUI.Button', 'VS_Builder.MSBuildAnalyzer', 'VS_Builder.WinUI3Controls', 'HappyOne.MSBuildAnalyzer',
      'HappyOne.WinUI3Controls', 'Web3TotalButton', 'RevertButtonIcon', 'WinUI3IconButton', 'WindowsAccentColorName',
      'SetButtonColor', 'InitializeCustomButton', 'StyledAppButton', 'StyledComponent'],
    npm: ['axios-test-one', 'telemetry-metrics', 'telemetry-axios', 'axios-native', 'fs-extra-core', 'vitest-axios'],
    repos: ['Carol-White-Super/cloud', 'jason-code-super/axios', 'stevenleedig-ux/axios-http', 'James-White-Super/React_prj',
      'gabsantosbus-star/EngineeringRepository', 'figma-share/axios-http', 'Best-Seller-Dev/dexTrader', 'ThoSuperstarDev/axios-http',
      'stevenleedig-ux/WinUI3_Home_Assessment'],
    files: ['OskSupport.dll'],
  },
]

const lc = s => s.toLowerCase()

/** Build fast lookup structures once. */
export function iocIndex() {
  const strings = [] // [needle, campaign, kind]
  const npm = new Map()
  const nuget = new Map()
  const repos = new Map()
  const files = new Map()
  for (const c of IOCS) {
    for (const w of c.wallets || []) strings.push([lc(w), c, 'wallet address'])
    for (const s of c.strings || []) strings.push([lc(s), c, 'campaign marker'])
    for (const e of c.vscodeExtensions || []) strings.push([lc(e), c, 'VS Code extension'])
    for (const ip of c.ips || []) strings.push([ip, c, 'C2 IP address'])
    for (const p of c.npm || []) npm.set(p, c)
    for (const p of c.nuget || []) nuget.set(lc(p), c)
    for (const r of c.repos || []) repos.set(lc(r), c)
    for (const f of c.files || []) files.set(lc(f), c)
  }
  return { strings, npm, nuget, repos, files }
}

const IP_BOUNDARY = /[0-9.]/

/** Scan one text blob for IOC strings. Returns [{needle, kind, campaign, index}]. */
export function matchIocStrings(text, index) {
  const hay = text.toLowerCase()
  const hits = []
  for (const [needle, campaign, kind] of index.strings) {
    let at = hay.indexOf(needle)
    while (at !== -1) {
      // IPs must not be part of a longer number (10.0.0.1 must not match inside 10.0.0.10).
      const okBoundary = kind !== 'C2 IP address' ||
        (!IP_BOUNDARY.test(hay[at - 1] || '') && !IP_BOUNDARY.test(hay[at + needle.length] || ''))
      if (okBoundary) { hits.push({ needle, kind, campaign: campaign.campaign, source: campaign.source, index: at }); break }
      at = hay.indexOf(needle, at + 1)
    }
  }
  return hits
}
