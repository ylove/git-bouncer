# The ID check

Before git-bouncer downloads anything, it asks: **is this repository who it claims to be?** Plenty of malicious repos don't hide anything clever. They just look like someone you trust: `micr0s0ft/vscode`, a "react" repo under a stranger's account, an account created last Tuesday.

The ID check runs on your machine (never in the sandbox), in this order:

1. **Look-alike names** (offline). Is the owner or repo name a disguised or misspelled version of a well-known one?
2. **Known-bad repos** (offline). Is the repo, or its owner, named in public malware reporting?
3. **Identity and impersonation** (GitHub API). Is the account behind a well-known name still the well-known one? Does a famous project's name come from its real owner, or from a fork of it?
4. **Reputation context** (GitHub API). Does it exist, how old are the account and the repo, is it a fork or archived, does the organization have a verified domain, and what's the latest release?

Steps 1 and 2 need no network. That's why `bouncer scan github.com/micr0s0ft/vscode` is turned away even though that repo doesn't exist and even if GitHub can't be reached.

If GitHub redirects the address (the repo was renamed or transferred), steps 1 to 3 run again on the name GitHub actually serves, because that's what git will download. A redirect can't launder a known-bad or look-alike account.

### Complete or incomplete

The ID check returns `complete: false` whenever something that applies to the repo couldn't be checked: the GitHub API was unreachable, rate-limited, answered with an error or rejected your gh login, or the known-bad list is missing. The CLI passes that to the verdict, so **an incomplete ID check makes the verdict INCOMPLETE**, never a pass. (A critical or high finding still turns the repo away.) This matters because an attacker can cause the failure: anonymous API requests are limited to 60 an hour per IP address, and any web page you visit, such as the fake recruiter's page with the assignment link, can use them up. Signing in with `gh auth login` avoids that.

Findings also start at their cautious severity and are only softened by an answer from GitHub. If GitHub can't say how old an account is, a typo-style look-alike stays high.

Hosts other than GitHub are the exception: only the name checks can ever run there, and the result says so (`ID-REDUCED`). That's a permanent property of the host, not a failure someone can cause, so it counts as complete.

The code is in [`src/idcheck/`](../src/idcheck/). The threat it answers is T6 in the [threat model](../THREAT_MODEL.md).

## Findings

Severities mean the same as everywhere else in git-bouncer ([`src/verdict.js`](../src/verdict.js)): **critical/high** turn the repo away, **medium** is a warning a person should look at, **low/info** are context that never blocks.

| ID | Severity | Plain-language meaning |
|---|---|---|
| `ID-IOC-REPO` | critical | This exact repo is named in public reporting about a malware campaign. Don't clone it, open it, or run anything from it. |
| `ID-IOC-OWNER` | high | The same account published a repo that's named in malware reporting. Accounts like that usually exist only to spread malware. |
| `ID-OWNER-CHANGED-HANDS` | high | The owner's name is on the well-known list, but GitHub says a different account holds it now (its account ID doesn't match). Names can be given up and registered again by anyone. |
| `ID-LOOKALIKE-OWNER` | high or medium | The owner's name is a disguised or misspelled version of a well-known account. **High** for disguised characters (`micr0s0ft`, `rnicrosoft`, `face-book`), and for a typo (`vercell`) on an account younger than 90 days or when GitHub can't say how old it is. **Medium** for a typo on an older account (`androidx`), for the brand with a word added or left off (`microsoft-official`, `mistral` for `mistralai`), and for an account named after a famous project (`nextjs`). |
| `ID-LOOKALIKE-REPO` | high | The repo's name is a famous project's name written with look-alike characters (`vsc0de`). Nobody types it that way by accident. |
| `ID-NOT-FOUND` | high | There's no public repo at that address: it's private, deleted, or never existed. git-bouncer only checks public repos. |
| `ID-BLOCKED` | high | GitHub itself has blocked or disabled the repo, which happens for legal takedowns and for malware. |
| `ID-IMPERSONATION` | medium | The repo has a famous project's name, but it isn't that project and isn't a GitHub fork of it. Fine for a practice repo, but don't trust it because of its name. |
| `ID-MOVED` | medium or info | GitHub redirects this address to another repo, and git will follow it. **Medium** when the repo moved to a different account that git-bouncer doesn't know; **info** for a rename, or a move to a well-known account confirmed by its account ID (`facebook/react` -> `react/react`). The other checks run on where it leads. |
| `ID-FORK-OF-FAMOUS` | low or medium | Someone else's fork of a famous project. GitHub shows "forked from ..." under it, but that's not an endorsement: the fork can contain any code. **Medium** when the fork or its account is younger than 90 days. |
| `ID-NEW-OWNER` | medium | The owner's account is less than 30 days old. |
| `ID-NEW-REPO` | medium | The repo is less than 14 days old. |
| `ID-SIMILAR-REPO` | low | The repo's name is one typo from a famous project's name (`vscodee`). Often honest (`flasky`, `transformer`), so it's context only. |
| `ID-ARCHIVED` | low | The repo is read-only and no longer maintained. |
| `ID-STARS-UNUSUAL` | low | Lots of stars, almost no forks, on a young repo. A weak sign the stars were bought. |
| `ID-API-UNAVAILABLE` | low | Part of the check couldn't run (rate limit, network error, GitHub error). The finding lists exactly what wasn't checked, and the ID check is **incomplete**, so the verdict can't be a pass. |
| `ID-IOC-UNAVAILABLE` | low | The known-bad repo list is missing from this install, so the repo wasn't compared against it. The ID check is **incomplete**. |
| `ID-FORK` | info | The repo is a fork, and the finding names the original. A fork doesn't inherit the original's reputation; its owner can change anything. |
| `ID-VERIFIED-ORG` | info | The organization has proved to GitHub that it controls a domain. The finding shows its listed website and links its GitHub page, where the verified domain is shown. It says who runs the account, not whether to trust it, and it's left out when the name borrows a brand the account doesn't own (`openai-labs`). |
| `ID-LATEST-RELEASE` | info | The newest release's tag, so you can compare it with the version you were told to use. |
| `ID-REDUCED` | info | The host isn't GitHub, so only the name checks ran. |

### Why a brand-new account is a warning, not a failure

Throwaway malware repos are almost always published from new accounts. But so are lots of real take-home tests: a recruiter or a small company sets up an account for the hiring round. If git-bouncer turned away every new account, it would be wrong often enough that people would stop listening. So `ID-NEW-OWNER` and `ID-NEW-REPO` are **medium**: look at who sent you the link, and whether you'd trust them with your laptop.

## How names are compared

Three tricks, three defenses.

**Look-alike characters.** Plain edit distance underrates these. `micr0s0ft` is two edits from `microsoft` but looks identical, while `openaq` (a real, unrelated air-quality nonprofit) is only one edit from `openai`. So before comparing, both names are reduced to a *skeleton* in which characters that look alike become the same character. That's the idea behind Unicode's confusable detection ([UTS #39](https://www.unicode.org/reports/tr39/)), cut down to the ASCII tricks that work in GitHub names:

| Written as | Reads as |
|---|---|
| `0` | o |
| `1`, `i`, `l` | one vertical stroke |
| `3`, `4`, `5`, `7`, `8` | e, a, s, t, b |
| `rn`, `vv`, `cl` | m, w, d |
| `-`, `_`, `.`, capital letters | ignored |

Same skeleton, different name: a look-alike.

**Typos.** Measured as [Damerau-Levenshtein distance](https://en.wikipedia.org/wiki/Damerau%E2%80%93Levenshtein_distance) (insert, delete, change, or swap two neighbouring characters) after the single-character swaps. The letter pairs (`rn`, `vv`, `cl`) are only folded for typos when the suspect name itself is written with one (`rnicrosft`), because folding changes a name's length: folded everywhere, it made the real `golangci` organization (`ci` reads as `cl`, which reads as `d`) look one letter away from `golang`. How close counts depends on the length of the well-known name, because in a short name one changed letter is usually just a different word:

| Well-known name length | Counts as a look-alike when the name... |
|---|---|
| 1-3 | never compared (`vue`, `aws`, `npm`: too many real names are one letter away) |
| 4 | matches after look-alike characters are normalized (`ub3r`) |
| 5-7 | ...or has one extra, missing or swapped character (`vercell`, `gogle`, `goolge`) |
| 8-11 | ...or has one changed character (`micrasoft`) |
| 12+ | ...or two edits (`modelcontextptorocol`): in a long name, two slips are easy to miss |

**The brand plus a word, or minus one.** `microsoft-official`, `uniswap-labs`, `openai-labs`, or `mistral` when the real account is `mistralai`. These are compared by their *stem*: the name with words like `official-`, `real-`, `-labs`, `-dev`, `-ai`, `-hq`, `-inc`, `-team`, `-org`, `-io` and `-js` taken off, as long as five letters are left. For the well-known names, glued words count too (`mistralai` becomes `mistral`). For the name being checked, only words set off by a separator do, because real, unrelated projects glue words onto a brand: `realpython`, `jupyterlab`, `postgresapp` and `nginxinc` were all false alarms when glued words counted on both sides. A stem match is a **medium** warning.

**An owner named after a famous project** (`nextjs`, `vscode`, `typescript`) that isn't the project's real owner is a **medium** warning too.

More rules keep false alarms down:

- A typo match must keep the **first letter**. People notice a wrong first letter, and dropping it tends to produce unrelated real words (`llama` vs `ollama`, `interest` vs `pinterest`).
- A name that's **on the known list** is never a look-alike of another known name (`vuejs` and `vitejs` are both real). Real, long-established accounts that happen to be one trick away from a listed name are listed as *neighbours* (`DATA-DOG`, the go-sqlmock org, is `datadog` with a hyphen): they're not look-alikes, but they get no other trust.
- A name made only of **digits** is a number, not a disguise (`8483` isn't `babe`, a look-alike of `babel`).
- A **typo on an established account** is a warning, not a failure. `androidx` (Google's AndroidX), `nestjsx`, `pallet`, `gyoogle` and `Red5` are all old, real projects one typo from a listed name. So a typo-style match is **high** only when the account is younger than 90 days, or GitHub can't say how old it is; otherwise it's **medium**: "looks like X, check it's who you meant". Disguised characters and separator tricks are always high, however old the account: nobody writes `micr0s0ft` by accident, and old accounts can be bought.

**How often this is wrong, measured.** The owner rules (the name checks, plus the account age for typo-style matches) were run over two samples of real, popular GitHub accounts:

| Sample | Owners | High | Medium |
|---|---|---|---|
| Tuning: owners of 7,000 repos with 790+ stars (from the review of this check), 1,342 of GitHub's most-followed accounts, and owners of 1,200 of its most-starred repos | 7,027 | 0 | 4 (0.06%) |
| Held out (not used for tuning): owners of 4,000 repos with 300 to 789 stars, minus those already in the tuning sample | 3,131 | 0 | 2 (0.06%) |

The tuning sample was used to adjust the rules and lists, so it flatters the result. Its four warnings are `Red5` and `gyoogle` (old accounts one typo from `redis` and `google`), `vuejs-ai` (a 2026 org called "Vue AI") and `nextjs` (an org named after the project); the last two are arguably right to warn. The two held-out warnings were `datadog-labs` and `mongodb-js`, real sub-organizations of listed brands, which have been added to the list since. Before the tuning, the 7,000-repo sample turned away three real projects (`gyoogle`, `Red5`, `8483`), and checking names one typo from listed ones found three more (`androidx`, `nestjsx`, `pallet`). Other samples will find other cases: please report them with the false-positive issue template.

Repo names are compared against famous repo names the same way, with two differences: a version suffix isn't a disguise (`tensorflow2`, `react18`), and a plain typo is only `low`, because repos are often honestly named after the thing they build on (`flasky` is a popular Flask tutorial). And a well-known owner's own repo names are its business: `microsoft/anything` is never flagged as a look-alike repo, as long as GitHub confirms the account behind `microsoft` is still the one with Microsoft's account ID.

## What's sent where

- **Signed in to the GitHub CLI** (`gh auth status` succeeds): requests go through `gh api`. gh adds your token; git-bouncer never sees, stores or prints it. gh is run by its absolute path, found on absolute `PATH` entries only (so a `gh` planted in some folder can't stand in for it), with an argument array (never a shell), from a fresh private folder made for each call, with gh's error output discarded.
- **Otherwise**: anonymous `fetch` to `https://api.github.com` with a generic `User-Agent: git-bouncer`, no token and no cookies. GitHub allows 60 anonymous requests an hour per IP address.
- Only these paths are ever requested, checked against a strict allowlist first: `/repos/{owner}/{repo}`, `/repos/{owner}/{repo}/releases/latest`, `/users/{owner}`, `/orgs/{owner}`. One scan makes at most four requests. Every request has a 10-second timeout and a 1 MB response cap.
- Text that comes back from the API (branch names, release tags, fork parents) is controlled by the repo's owner, so it's sanitized like any other untrusted text before it reaches a finding.

## Facts

Besides findings and `complete`, the ID check returns `facts` for display. All are optional: `fullName`, `ownerId`, `ownerType`, `ownerCreatedAt`, `ownerAgeDays`, `verifiedOrg`, `orgWebsite`, `repoCreatedAt`, `repoAgeDays`, `stars`, `forks`, `defaultBranch`, `archived`, `fork`, `forkParent`, `latestRelease`, `latestReleaseAt`.

## Limitations (read these)

- **The curated lists are incomplete.** 277 well-known accounts and 100 famous repos are listed in [`known.js`](../src/idcheck/known.js). A look-alike of an account that isn't listed won't be caught by name. Additions are welcome (see below).
- **Some brand tricks still pass.** A brand of four letters or fewer has no stem check (`qwen` for `qwenlm`), a glued word isn't taken off the name being checked (`microsoftofficial`), and a product name that isn't the account name isn't compared at all (`claude-ai`, `ms-vscode-official`). If the repo has a famous name (`claude-ai/claude-code`), the impersonation check still warns.
- **Names change hands, and account IDs pin them.** When the lists were last checked, the organization that used to be `facebook` (account ID 69631) had been renamed `meta`, React had moved to the `react` organization, and the name `facebook` belonged to a different, brand-new account. So every listed name is pinned to its account ID: if GitHub says a different account holds the name now, that's `ID-OWNER-CHANGED-HANDS` (high), and the name gets no trust. `facebook` itself isn't trusted, but its look-alikes (`faceb00k`) are still caught. Offline, names can only be trusted by name, and the result is incomplete.
- **New accounts aren't proof**, and old ones aren't either. Attackers can buy or take over aged accounts.
- **Star counts can be bought.** Researchers found millions of suspected fake stars on GitHub, mostly promoting short-lived malware repos ([He et al., "Six Million (Suspected) Fake Stars in GitHub"](https://arxiv.org/abs/2412.13459)). `ID-STARS-UNUSUAL` is a weak, low-severity hint, and *no* finding doesn't mean the stars are real.
- **The known-bad list is a dated snapshot** of public reporting, shared with the sandbox scanner (`sandbox/scanner/checks/iocs.js`). It goes stale, and it only names github.com repos, so it isn't applied to other hosts.
- **Other hosts get a reduced check.** For GitLab, Bitbucket, Codeberg and `--allow-host` servers, only the name checks run, and the account names on those hosts aren't GitHub's: `microsoft` there isn't necessarily Microsoft.
- **Not checked yet:** whether the ref you're cloning matches a release, and whether its commits are signed. Both need the exact commit the sandbox scans, so they'll come with that work.
- **GitHub is trusted.** If the API is unreachable or rate-limited, the reputation part is skipped, `ID-API-UNAVAILABLE` says what was missed, and the ID check is incomplete. The name checks still run.

## Adding a name to the lists

A wrong entry tells people a squatter is the real thing, so check before you add:

```sh
gh api /users/NAME --jq '[.login, .type, .created_at, .followers]'   # exists, old, widely followed
gh api /orgs/NAME --jq '.is_verified, .blog'                          # for organizations
gh api /repos/OWNER/REPO --jq '[.full_name, .fork]'                   # a famous repo: full_name must point back at OWNER/REPO, fork false
```

Add the owner with its account ID (`gh api /users/NAME --jq .id`). Then run `npm test`. The tests check that every famous repo's owner is on the owner list, that every ID is distinct, and that no new name is one look-alike step from an existing one (if it is, that should be a conscious decision).
