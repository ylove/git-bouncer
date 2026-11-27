// Curated lists for the ID check: well-known GitHub accounts, and famous repositories with their real
// owners.
//
// These lists decide what counts as an impersonation, so a wrong entry is a security bug, not a typo.
// Listing a squatter's account here would tell people "this is the real one". Every entry was checked
// against the GitHub API (it exists, its age and followers fit, and for famous repos the API's
// full_name points back at the listed owner) on LISTS_CHECKED. See docs/id-check.md for how to add one.
//
// Names change hands. When this was checked, the organization that used to be "facebook" (created in
// 2009) had been renamed "meta", React's repositories had moved to the "react" organization, and a
// different, brand-new account held the name "facebook". GitHub still redirects facebook/react to
// react/react. That's why these lists only answer "is this name a look-alike?". Whether the account
// behind a name is old and trustworthy is a separate check against the live API.

export const LISTS_CHECKED = '2026-11-27'

/** Well-known GitHub organizations and users, lowercase. Owner names on GitHub ignore case. */
export const KNOWN_OWNERS = Object.freeze([
  // Big tech and well-known companies
  'microsoft', 'azure', 'azure-samples', 'microsoftdocs', 'dotnet', 'github',
  'google', 'googleapis', 'googlecloudplatform', 'googlechrome', 'googlemaps', 'android', 'flutter', 'firebase',
  'meta', 'facebook', 'facebookresearch', 'facebookincubator', 'react', 'apple',
  'netflix', 'spotify', 'airbnb', 'uber', 'twitter', 'linkedin', 'shopify', 'stripe', 'square', 'paypal',
  'salesforce', 'ibm', 'intel', 'nvidia', 'adobe', 'oracle', 'sap', 'alibaba', 'bytedance', 'samsung',
  'mozilla', 'atlassian', 'jetbrains', 'docker', 'hashicorp', 'elastic', 'grafana', 'mongodb', 'redis',
  'discord', 'dropbox', 'pinterest', 'twilio',
  // Cloud and hosting
  'aws', 'awslabs', 'aws-samples', 'cloudflare', 'vercel', 'vercel-labs', 'netlify', 'digitalocean', 'heroku', 'supabase',
  // JavaScript and TypeScript
  'nodejs', 'npm', 'denoland', 'oven-sh', 'vuejs', 'vitejs', 'sveltejs', 'angular', 'reactjs', 'remix-run',
  'expressjs', 'fastify', 'nestjs', 'webpack', 'babel', 'eslint', 'prettier', 'typescript-eslint', 'jestjs',
  'vitest-dev', 'storybookjs', 'tailwindlabs', 'shadcn-ui', 'mui', 'axios', 'lodash', 'jquery', 'twbs',
  'mrdoob', 'pmndrs', 'tanstack', 'trpc', 'prisma', 'electron', 'nuxt', 'withastro', 'puppeteer', 'cypress-io',
  'seleniumhq', 'pnpm', 'yarnpkg', 'socketio', 'chartjs', 'evanw', 'sindresorhus',
  // Python
  'python', 'psf', 'pypa', 'pallets', 'django', 'tiangolo', 'fastapi', 'pydantic', 'astral-sh', 'numpy',
  'pandas-dev', 'scikit-learn', 'jupyter', 'pytorch', 'tensorflow', 'keras-team', 'huggingface', 'ansible',
  'home-assistant', 'streamlit', 'fastai',
  // Go and cloud native
  'golang', 'kubernetes', 'kubernetes-sigs', 'prometheus', 'helm', 'istio', 'containerd', 'containers', 'moby', 'spf13',
  'gohugoio', 'traefik', 'minio', 'open-telemetry',
  // Rust
  'rust-lang', 'tokio-rs', 'tauri-apps', 'bevyengine', 'burntsushi', 'zed-industries',
  // AI labs and tools
  'openai', 'anthropics', 'modelcontextprotocol', 'google-deepmind', 'google-gemini', 'meta-llama',
  'mistralai', 'deepseek-ai', 'qwenlm', 'xai-org', 'ollama', 'ggml-org', 'ggerganov', 'langchain-ai',
  'run-llama', 'vllm-project', 'unslothai', 'comfy-org', 'comfyanonymous', 'automatic1111', 'stability-ai',
  'compvis', 'open-webui', 'significant-gravitas', 'nomic-ai', 'oobabooga', 'lllyasviel', 'karpathy',
  // Security
  'snyk', 'crowdstrike', 'paloaltonetworks', 'rapid7', 'tenable', 'trailofbits', 'owasp', 'projectdiscovery',
  'aquasecurity', 'sigstore', 'ossf', 'semgrep', 'mandiant', 'cisagov', 'socketdev', 'step-security',
  'chainguard-dev', 'open-policy-agent', '1password', 'bitwarden', 'openssl', 'openssh', 'letsencrypt',
  'tailscale', 'signalapp',
  // Crypto and web3 (fake take-home tests often target web3 developers)
  'ethereum', 'bitcoin', 'solana-labs', 'metamask', 'openzeppelin', 'uniswap', 'coinbase', 'smartcontractkit',
  'nomicfoundation', 'wevm', 'ethers-io', 'web3', 'chainsafe', 'consensys',
  // Projects people clone and build
  'torvalds', 'git', 'curl', 'ffmpeg', 'yt-dlp', 'ytdl-org', 'obsproject', 'neovim', 'vim', 'tmux',
  'ohmyzsh', 'godotengine', 'nginx', 'postgres', 'sqlite', 'homebrew',
])

/**
 * Famous repositories, by name, with the owners that really publish them. The first owner is the
 * repo's current home; any others are old names that GitHub redirects (facebook/react -> react/react).
 * Names are kept distinctive on purpose: very generic words ("rust", "codex", "foundry") are left out,
 * because lots of unrelated repos are named that way and a warning on all of them would be noise.
 */
export const FAMOUS_REPOS = Object.freeze({
  // JavaScript and TypeScript
  react: ['react', 'facebook'],
  'react-native': ['react', 'facebook'],
  'create-react-app': ['react', 'facebook'],
  docusaurus: ['meta', 'facebook'],
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
  jest: ['jestjs', 'facebook'],
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
