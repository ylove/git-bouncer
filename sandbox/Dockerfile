# git-bouncer sandbox image.
#
# Built locally on first use from the copy of this file inside the npm package, so you're not
# trusting a prebuilt image from anyone. Everything that comes from the internet is pinned:
#   - the base image by digest (Dependabot proposes updates)
#   - osv-scanner by version + the SHA256 published in its release's SHA256SUMS
# The final image has no curl/wget, and runs as an unprivileged user.

# ---- stage 1: fetch and verify osv-scanner -----------------------------------------------------
FROM node:24-trixie-slim@sha256:4d00acb4bcc42c454c4eb801526f7ad7f772ea3bd4fd168c5cc2e384abcbb9d4 AS fetch
ARG TARGETARCH
ARG OSV_VERSION=2.7.1
ARG OSV_SHA256_amd64=fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8
ARG OSV_SHA256_arm64=983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) sha="$OSV_SHA256_amd64" ;; \
      arm64) sha="$OSV_SHA256_arm64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${TARGETARCH:-amd64}"; \
    echo "${sha}  /osv-scanner" | sha256sum -c -; \
    chmod 0755 /osv-scanner

# ---- stage 2: the sandbox ----------------------------------------------------------------------
FROM node:24-trixie-slim@sha256:4d00acb4bcc42c454c4eb801526f7ad7f772ea3bd4fd168c5cc2e384abcbb9d4
LABEL org.opencontainers.image.title="git-bouncer sandbox" \
      org.opencontainers.image.source="https://github.com/ylove/git-bouncer" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.git-bouncer.sandbox="1"
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp --shell /usr/sbin/nologin scan
COPY --from=fetch /osv-scanner /usr/local/bin/osv-scanner
COPY osv-scanner.toml /opt/bouncer/osv-scanner.toml
COPY scanner/ /opt/bouncer/scanner/
ENV HOME=/tmp NPM_CONFIG_UPDATE_NOTIFIER=false NODE_ENV=production
USER 10001:10001
WORKDIR /work
HEALTHCHECK NONE
# The host starts this idle process, runs the scanner with `exec`, reads results, then removes the container.
CMD ["sleep", "infinity"]
