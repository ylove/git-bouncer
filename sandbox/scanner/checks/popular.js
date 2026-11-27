// Popular npm package names, used to spot typosquats ("expresss", "crossenv", "lodahs").
// Not exhaustive: a squat of a less popular package won't be caught by this list, but known-malicious
// packages are still caught by OSV. Additions welcome (keep it to widely depended-on packages).

export const POPULAR_NPM = new Set(`
react react-dom react-router react-router-dom react-native next vue vuex vue-router nuxt svelte @sveltejs/kit angular
@angular/core @angular/common @angular/cli preact solid-js astro remix @remix-run/react gatsby ember-source jquery
express koa fastify hapi @hapi/hapi nestjs @nestjs/core @nestjs/common restify connect body-parser cookie-parser cors helmet
morgan multer compression express-session passport passport-jwt jsonwebtoken bcrypt bcryptjs argon2 jose
lodash lodash-es underscore ramda immer immutable rxjs date-fns moment dayjs luxon uuid nanoid ms
axios node-fetch got superagent request undici ky cross-fetch isomorphic-fetch form-data qs query-string
chalk colors kleur picocolors ora inquirer prompts commander yargs minimist meow cac cli-progress boxen figlet
debug winston pino bunyan loglevel
dotenv dotenv-expand cross-env env-cmd config convict
typescript ts-node tsx tslib @types/node @types/react @types/express esbuild swc @swc/core babel-loader
@babel/core @babel/preset-env @babel/preset-react @babel/preset-typescript @babel/runtime core-js regenerator-runtime
webpack webpack-cli webpack-dev-server vite rollup parcel turbo nx lerna rimraf mkdirp glob fast-glob globby minimatch
chokidar nodemon concurrently npm-run-all husky lint-staged prettier eslint eslint-config-prettier eslint-plugin-react
eslint-plugin-import @typescript-eslint/parser @typescript-eslint/eslint-plugin stylelint
jest vitest mocha chai sinon ava tap supertest @testing-library/react @testing-library/jest-dom cypress playwright
@playwright/test puppeteer jsdom happy-dom nock msw
tailwindcss postcss autoprefixer sass less styled-components @emotion/react @emotion/styled classnames clsx
@mui/material @chakra-ui/react antd bootstrap framer-motion three d3 chart.js
mongoose mongodb mysql mysql2 pg sequelize typeorm prisma @prisma/client knex redis ioredis sqlite3 better-sqlite3
drizzle-orm firebase firebase-admin @supabase/supabase-js aws-sdk @aws-sdk/client-s3 @google-cloud/storage stripe twilio
socket.io socket.io-client ws graphql apollo-server @apollo/client graphql-tag
zod yup joi ajv class-validator validator
sharp jimp multer-s3 busboy formidable
fs-extra graceful-fs semver yaml js-yaml ini toml xml2js cheerio marked markdown-it highlight.js
openai @anthropic-ai/sdk langchain @langchain/core ai @modelcontextprotocol/sdk
electron electron-builder
async bluebird p-limit p-queue eventemitter3 events buffer process util path-browserify stream-browserify
crypto-js node-forge bn.js ethers web3 viem
http-proxy http-proxy-middleware serve-static express-rate-limit
open execa shelljs cross-spawn which
`.trim().split(/\s+/))
