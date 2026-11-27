# Releasing git-bouncer

Releases are published to npm **from GitHub Actions only**, with provenance, from a `v*.*.*` tag that matches `package.json`. The publish job waits for approval in the `release` environment.

## Before every release (the release gate)

1. CI is green on `main`, including the Docker and Podman sandbox jobs. CodeQL, Scorecard and zizmor have no unaddressed high/critical findings.
2. A fresh adversarial review of the whole repository found nothing critical or high that is still open.
3. `snyk code test` has been run once on the release candidate, and any findings have been fixed. (The maintainer's Snyk free tier is rationed, so this is never run in CI.)
4. `docs/`, the README and the threat model match the released behavior.
5. A version-bump PR updates `package.json` and the changelog. Merge it, then tag: `git tag -s vX.Y.Z && git push origin vX.Y.Z`.

## One-time npm setup (maintainer)

npm's [trusted publishing](https://docs.npmjs.com/trusted-publishers) uses GitHub's OIDC token instead of a long-lived npm token. It's configured in the settings of a package that already exists, so the very first version needs one extra step:

1. **First publish (v1.0.0) with a short-lived token, still from GitHub Actions** (so it gets provenance):
   - On npmjs.com, create a *granular access token* that can publish, expires in 1 day, and is limited to the `git-bouncer` package once it exists (or to new packages).
   - Add it as the secret `NPM_TOKEN` on the repo's `release` **environment** (not a repo-wide secret).
   - Tag `v1.0.0` and approve the publish job.
   - Then **delete the secret and revoke the token**.
2. **Switch to trusted publishing:** on npmjs.com, open the package settings, add a trusted publisher of type GitHub Actions with organization/user `ylove`, repository `git-bouncer`, workflow `release.yml`, and environment `release`. The first trusted publish must happen within 2 days of adding it.
3. **Turn tokens off:** under Settings → Publishing access, choose "Require two-factor authentication and disallow tokens". Trusted publishing keeps working.

After that, a release is: version-bump PR → tag → approve. No token exists anywhere. (1.0.0 itself is the one exception: it's published with that short-lived token, then the token is revoked.)

The release workflow also refuses a tag that points at a commit not on `main`, and a ruleset protects `v*` tags from being moved or deleted.

## Verifying a release

```sh
npm install -g git-bouncer@X.Y.Z
npm audit signatures --global   # shows git-bouncer with a verified provenance attestation
```

The GitHub release has the exact `.tgz` that was published, plus its CycloneDX SBOM.
