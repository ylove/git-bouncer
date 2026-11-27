// Curated lists for the ID check: well-known GitHub accounts, and famous repositories with their real
// owners.
//
// These lists decide what counts as an impersonation, so a wrong entry is a security bug, not a typo.
// Listing a squatter's account here would tell people "this is the real one". Every entry was checked
// against the GitHub API (it exists, its age and followers fit, and for famous repos the API's
// full_name points back at the listed owner) on LISTS_CHECKED. See docs/id-check.md for how to add one.
//
// Names change hands, numeric account IDs don't. When these lists were checked, the organization that
// used to be "facebook" (ID 69631, created in 2009) had been renamed "meta", React's repositories had
// moved to the "react" organization, and a different, brand-new account held the name "facebook". So
// each known owner is pinned to its account ID. If GitHub says a listed name now belongs to a different
// ID, the ID check doesn't trust the name: it reports that the name changed hands.

export const LISTS_CHECKED = '2026-11-27'

/**
 * Well-known GitHub organizations and users: lowercase login -> numeric account ID. Owner names on GitHub
 * ignore case. The ID is what makes an entry trustworthy; see the note at the top of this file.
 */
export const KNOWN_OWNERS = Object.freeze({
  // Big tech and well-known companies
  microsoft: 6154722, azure: 6844498, 'azure-samples': 1844662, microsoftdocs: 22479449, dotnet: 9141961,
  github: 9919, google: 1342004, googleapis: 16785467, googlecloudplatform: 2810941, googlechrome: 1778935,
  googlemaps: 3717923, googlechromelabs: 31970254, android: 32689599, flutter: 14101776, firebase: 1335026, meta: 69631,
  facebookresearch: 16943930, facebookincubator: 19538647, react: 102812, apple: 10639145, netflix: 913567,
  spotify: 251374, airbnb: 698437, uber: 538264, twitter: 50278, linkedin: 357098, shopify: 8085, stripe: 856813,
  square: 82592, paypal: 476675, salesforce: 453694, ibm: 1459110, intel: 17888862, nvidia: 1728152, adobe: 476009,
  oracle: 4430336, sap: 2531208, alibaba: 1961952, bytedance: 4158466, samsung: 6210390, mozilla: 131524,
  atlassian: 168166, jetbrains: 878437, docker: 5429470, hashicorp: 761456, elastic: 6764390, grafana: 7195757,
  mongodb: 45120, redis: 1529926, discord: 1965106, dropbox: 559357, pinterest: 541152, twilio: 109142,
  actions: 44036562, figma: 5155369, whatsapp: 5508982, instagram: 549085, telegramdesktop: 6113871,
  makenotion: 4792552, brave: 12301619, chromium: 30044, datadog: 365230, getsentry: 1396951, posthog: 60330232,
  'n8n-io': 45487711, clerk: 49538330,
  // Cloud and hosting
  aws: 2232217, awslabs: 3299148, 'aws-samples': 8931462, cloudflare: 314135, vercel: 14985020,
  'vercel-labs': 108547162, netlify: 7892489, digitalocean: 4650108, heroku: 23211, supabase: 54469796,
  // JavaScript and TypeScript
  nodejs: 9950313, npm: 6078720, denoland: 42048915, 'oven-sh': 108928776, vuejs: 6128107, vitejs: 65625612,
  sveltejs: 23617963, angular: 139426, reactjs: 6412038, 'remix-run': 64235328, expressjs: 5658226,
  fastify: 24939410, nestjs: 28507035, webpack: 2105791, babel: 9637642, eslint: 6019716, prettier: 25822731,
  'typescript-eslint': 46634674, jestjs: 103283236, 'vitest-dev': 95747107, storybookjs: 22632046,
  tailwindlabs: 67109815, 'shadcn-ui': 139895814, mui: 33663932, axios: 32372333, lodash: 2565403, jquery: 70142,
  twbs: 2918581, mrdoob: 97088, pmndrs: 45790596, tanstack: 72518640, trpc: 78011399, prisma: 17219288,
  electron: 13409222, nuxt: 23360933, withastro: 44914786, puppeteer: 6906516, 'cypress-io': 8908513,
  seleniumhq: 983927, pnpm: 21320719, yarnpkg: 22247014, socketio: 10566080, chartjs: 10342521, evanw: 406394,
  sindresorhus: 170270, expo: 12504344, 'nvm-sh': 49963700,
  // Python
  python: 1525981, psf: 50630501, pypa: 647025, pallets: 16748505, django: 27804, tiangolo: 1326112,
  fastapi: 156354296, pydantic: 110818415, 'astral-sh': 115962839, numpy: 288276, 'pandas-dev': 21206976,
  'scikit-learn': 365630, jupyter: 7388996, pytorch: 21003710, tensorflow: 15658638, 'keras-team': 34455048,
  huggingface: 25720743, ansible: 1507452, 'home-assistant': 13844975, jupyterlab: 22800682, streamlit: 45109972, fastai: 20547620,
  // Go and cloud native
  golang: 4314092, kubernetes: 13629408, 'kubernetes-sigs': 36015203, prometheus: 3380462, helm: 15859888,
  istio: 23534644, containerd: 14037953, containers: 5874934, moby: 27259197, spf13: 173412, gohugoio: 29385237,
  traefik: 14280338, minio: 695951, 'open-telemetry': 49998002, golangci: 35628013,
  // Rust
  'rust-lang': 5430905, 'tokio-rs': 20248544, 'tauri-apps': 54536011, bevyengine: 60047606, burntsushi: 456674,
  'zed-industries': 79345384,
  // Other languages and platforms
  apache: 47359, eclipse: 56974, openjdk: 41768318, kotlin: 1446536, 'spring-projects': 317776, rails: 4223,
  ruby: 210414, php: 25158, laravel: 958072, wordpress: 276006, jenkinsci: 107424, circleci: 1231870,
  // AI labs and tools
  openai: 14957082, anthropics: 76263028, modelcontextprotocol: 182288589, 'google-deepmind': 8596759,
  'google-gemini': 161781182, 'meta-llama': 153379578, mistralai: 132372032, 'deepseek-ai': 148330874,
  qwenlm: 141221163, 'xai-org': 130314967, ollama: 151674099, 'ggml-org': 134263123, ggerganov: 1991296,
  'langchain-ai': 126733545, 'run-llama': 130722866, 'vllm-project': 136984999, unslothai: 150920049,
  'comfy-org': 166579949, comfyanonymous: 121283862, automatic1111: 20920490, 'stability-ai': 100950301,
  compvis: 30233788, 'open-webui': 158137808, 'significant-gravitas': 130738209, 'nomic-ai': 102670180,
  oobabooga: 112222186, lllyasviel: 19834515, karpathy: 241138,
  // Security
  snyk: 12959162, crowdstrike: 2446477, paloaltonetworks: 4855743, rapid7: 1013671, tenable: 2379954,
  trailofbits: 2314423, owasp: 155815, projectdiscovery: 50994705, aquasecurity: 12783832, sigstore: 71096353,
  ossf: 67707773, semgrep: 29760937, mandiant: 331209, cisagov: 18539691, socketdev: 69326764,
  'step-security': 88700172, 'chainguard-dev': 87436699, 'open-policy-agent': 16468693, '1password': 38230737,
  bitwarden: 15990069, openssl: 3279138, openssh: 2387206, letsencrypt: 9289019, tailscale: 48932923,
  signalapp: 702459, auth0: 2824157, okta: 362460,
  // Crypto and web3 (fake take-home tests often target web3 developers)
  ethereum: 6250754, bitcoin: 528860, 'solana-labs': 35608259, metamask: 11744586, openzeppelin: 20820676,
  uniswap: 36115574, coinbase: 1885080, smartcontractkit: 25111032, nomicfoundation: 38917137, wevm: 109633172,
  'ethers-io': 18492273, web3: 36739222, chainsafe: 27474093, consensys: 10818037, binance: 69836600,
  ledgerhq: 9784193, trezor: 4146447, 'foundry-rs': 99892494, aave: 47617460, base: 16627100, offchainlabs: 43838009,
  'ethereum-optimism': 58791460, 'bnb-chain': 45615063, paradigmxyz: 97369466, trufflesuite: 22205159,
  // Projects people clone and build
  torvalds: 1024025, git: 18133, curl: 16928085, ffmpeg: 729418, 'yt-dlp': 79589310, 'ytdl-org': 48381040,
  obsproject: 7725691, neovim: 6471485, vim: 11618545, tmux: 12054114, ohmyzsh: 22552083, godotengine: 6318500,
  nginxinc: 8629072, nginx: 1412239, postgres: 177543, sqlite: 48680494, homebrew: 1503512,
})

/**
 * Famous repositories, by name, with the owners that really publish them. The first owner is the
 * repo's current home; any others are old names that GitHub redirects (tiangolo/fastapi ->
 * fastapi/fastapi). An old name is only listed while its account still belongs to the same people:
 * facebook/react redirects to react/react, but "facebook" isn't listed, because a new account holds it.
 * Names are kept distinctive on purpose: very generic words ("rust", "codex", "foundry") are left out,
 * because lots of unrelated repos are named that way and a warning on all of them would be noise.
 */
export const FAMOUS_REPOS = Object.freeze({
  // JavaScript and TypeScript
  react: ['react'],
  'react-native': ['react'],
  'create-react-app': ['react'],
  docusaurus: ['meta'],
  'next.js': ['vercel'],
  turborepo: ['vercel'],
  vscode: ['microsoft'],
  TypeScript: ['microsoft'],
  playwright: ['microsoft'],
  PowerToys: ['microsoft'],
  svelte: ['sveltejs'],
  angular: ['angular'],
  deno: ['denoland'],
  express: ['expressjs'],
  axios: ['axios'],
  lodash: ['lodash'],
  jquery: ['jquery'],
  'socket.io': ['socketio'],
  'three.js': ['mrdoob'],
  'Chart.js': ['chartjs'],
  puppeteer: ['puppeteer'],
  cypress: ['cypress-io'],
  selenium: ['SeleniumHQ'],
  vite: ['vitejs'],
  webpack: ['webpack'],
  tailwindcss: ['tailwindlabs'],
  prettier: ['prettier'],
  eslint: ['eslint'],
  jest: ['jestjs'],
  vitest: ['vitest-dev'],
  storybook: ['storybookjs'],
  nuxt: ['nuxt'],
  electron: ['electron'],
  tauri: ['tauri-apps'],
  // Python
  django: ['django'],
  flask: ['pallets'],
  fastapi: ['fastapi', 'tiangolo'],
  pytorch: ['pytorch'],
  tensorflow: ['tensorflow'],
  keras: ['keras-team'],
  'scikit-learn': ['scikit-learn'],
  numpy: ['numpy'],
  pandas: ['pandas-dev'],
  // AI tools people download and run
  transformers: ['huggingface'],
  diffusers: ['huggingface'],
  langchain: ['langchain-ai'],
  llama_index: ['run-llama'],
  ollama: ['ollama'],
  'llama.cpp': ['ggml-org', 'ggerganov'],
  'whisper.cpp': ['ggml-org', 'ggerganov'],
  whisper: ['openai'],
  'openai-python': ['openai'],
  'anthropic-sdk-python': ['anthropics'],
  'claude-code': ['anthropics'],
  'gemini-cli': ['google-gemini'],
  vllm: ['vllm-project'],
  nanoGPT: ['karpathy'],
  minGPT: ['karpathy'],
  'llm.c': ['karpathy'],
  'stable-diffusion-webui': ['AUTOMATIC1111'],
  ComfyUI: ['Comfy-Org', 'comfyanonymous'],
  'stable-diffusion': ['CompVis'],
  'open-webui': ['open-webui'],
  AutoGPT: ['Significant-Gravitas'],
  gpt4all: ['nomic-ai'],
  'text-generation-webui': ['oobabooga'], // renamed oobabooga/textgen; GitHub redirects the old name
  Fooocus: ['lllyasviel'],
  // Infrastructure and tools
  kubernetes: ['kubernetes'],
  terraform: ['hashicorp'],
  ansible: ['ansible'],
  prometheus: ['prometheus'],
  grafana: ['grafana'],
  istio: ['istio'],
  linux: ['torvalds'],
  curl: ['curl'],
  openssl: ['openssl'],
  'openssh-portable': ['openssh'],
  nginx: ['nginx'],
  redis: ['redis'],
  postgres: ['postgres'],
  sqlite: ['sqlite'],
  neovim: ['neovim'],
  tmux: ['tmux'],
  ohmyzsh: ['ohmyzsh'],
  cpython: ['python'],
  godot: ['godotengine'],
  'yt-dlp': ['yt-dlp'],
  'youtube-dl': ['ytdl-org'],
  FFmpeg: ['FFmpeg'],
  'obs-studio': ['obsproject'],
  // Crypto and web3
  bitcoin: ['bitcoin'],
  'go-ethereum': ['ethereum'],
  'metamask-extension': ['MetaMask'],
  'openzeppelin-contracts': ['OpenZeppelin'],
  hardhat: ['NomicFoundation'],
  'ethers.js': ['ethers-io'],
  'web3.js': ['web3', 'ChainSafe'],
  wagmi: ['wevm'],
  viem: ['wevm'],
  solana: ['solana-labs'],
})

/**
 * Names whose look-alikes are still flagged ("faceb00k"), but whose exact name on GitHub is NOT the
 * well-known account, so it gets no trust. `formerId` is the ID the name used to belong to: if the
 * account that now holds the name has a different ID, the ID check says the name changed hands.
 */
export const NOT_THE_REAL_ONE = Object.freeze({
  facebook: { formerId: 69631, now: 'meta', why: 'The organization that was "facebook" is now "meta", and a different, new account holds the name.' },
  amazon: { formerId: null, now: 'aws', why: 'Amazon publishes as "aws", "awslabs" and "amzn". The account named "amazon" is not Amazon\'s.' },
})

/**
 * Real, long-established accounts whose names are one look-alike step from a listed name but that belong
 * to someone else, checked like the lists above. They're not look-alikes, but they get no other trust.
 * DATA-DOG (go-sqlmock, since 2014) is "datadog" with a hyphen, which would otherwise be turned away.
 */
export const KNOWN_NEIGHBOURS = Object.freeze({
  'data-dog': 6613360,
})
