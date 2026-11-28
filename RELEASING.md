# Releasing git-bouncer

Releases are published to npm **from GitHub Actions only**, with provenance, from a `v*.*.*` tag that matches `package.json`. The publish job waits for approval in the `release` environment.

## Before every release (the release gate)

1. CI is green on `main`, including the Docker and Podman sandbox jobs. CodeQL, Scorecard and zizmor have no unaddressed high/critical findings.
2. A fresh adversarial review of the whole repository found nothing critical or high that is still open.
3. `snyk code test` has been run once on the release candidate, and any findings have been fixed. (The maintainer's Snyk free tier is rationed, so this is never run in CI.)
4. `docs/`, the README and the threat model match the released behavior.
5. A version-bump PR updates `package.json` and the changelog. Merge it, then tag: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.

## How a release goes public: staged publishing

The workflow runs `npm stage publish`. That uploads the version to npm's **staging area**: it is **not public** until the maintainer approves it with 2FA, on npmjs.com (Staged Packages tab → Approve) or with `npm stage approve <stage-id>`. Even a compromised workflow or a leaked token can only *stage* a version, never publish one.

## One-time npm setup (maintainer)

npm trusted publishers are configured on a package that already exists, so the very first version is staged with a token:

1. **First version (v1.0.0):**
   - Use a granular access token that can stage publishes. A token that still requires 2FA is fine: staging never asks for a one-time code.
   - Store it as the secret `NPM_TOKEN` on the repo's `release` **environment** (not a repo-wide secret).
   - Tag `v1.0.0`, approve the workflow's `publish` job in the Actions tab, then **approve the staged version on npmjs.com with 2FA**.
   - Staging a brand-new name immediately publishes a placeholder version `0.0.0-stage`, which claims the name. The real version appears when you approve it.
2. **Switch to trusted publishing:** on npmjs.com, open the package settings and add a trusted publisher of type GitHub Actions: organization/user `ylove`, repository `git-bouncer`, workflow `release.yml`, environment `release`. The first trusted (staged) publish must happen within 2 days of adding it.
3. **Remove the token:** delete the `NPM_TOKEN` environment secret and revoke the token on npmjs.com. Then, under Settings → Publishing access, choose "Require two-factor authentication and disallow tokens".

After that, a release is: version-bump PR → tag → approve the workflow → approve the staged version with 2FA. No token exists anywhere.

The release workflow also refuses a tag that points at a commit not on `main`, and a ruleset protects `v*` tags from being moved or deleted.

## Verifying a release

```sh
npm install -g git-bouncer@X.Y.Z
npm audit signatures --global   # shows git-bouncer with a verified provenance attestation
```

The GitHub release has the exact `.tgz` that was published, plus its CycloneDX SBOM.
