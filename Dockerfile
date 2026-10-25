# TransTeira container image (CLAUDE.md sections 3 and 18).
#
# Three stages:
#   web    builds the web interface (web/dist) and the integrated help generated from docs/user;
#   build  compiles the static Go binary with web/dist embedded, and prepares the minimal root
#          file system of the final image (passwd/group, CA certificates, owned directories);
#   final  `scratch`: the binary, the CA certificates and that root file system, nothing else.
#
# Build with `make docker` (same VERSION, COMMIT and DATE as `make build`); `make docker-check`
# smoke-tests the result. The base images are pinned by digest (multi-architecture index): to
# upgrade, change the tag and resolve the new digest with
#   docker pull <image:tag> && docker inspect --format '{{index .RepoDigests 0}}' <image:tag>
#
# The image runs as the unprivileged user transteira (UID/GID 10001) and works with a read-only
# root file system: everything it writes goes to the volumes below.
#   /data                     encrypted files (TT_DATA_DIR)
#   /var/lib/transteira/db    SQLite database (default TT_DB_DSN /var/lib/transteira/db/transteira.db)
#   /backups                  clean database copies (TT_BACKUP_DIR)
#   /logs                     security log (TT_LOG_DIR)
# The master key is never part of these volumes: mount it as a Docker secret
# (/run/secrets/transteira_master_key) and point TT_MASTER_KEY_FILE at it.

# --- web: Svelte applications and integrated help ---------------------------------------------
FROM node:24.22.1-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS web

WORKDIR /src/web
# Lockfile install first, so that the dependency layer is reused while only sources change.
# --ignore-scripts: no dependency install script is ever executed (web/.npmrc, web/README.md).
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --ignore-scripts --no-audit --no-fund

COPY web/ ./
# The help generator (scripts/build-help.mjs) reads ../docs/user (guides, screenshots manifest)
# and the help modules import the screenshots from there.
COPY docs/user/ /src/docs/user/
# help:gen + vite build + check-dist (strict CSP compatibility of the output).
RUN npm run --silent build

# --- build: static Go binary and minimal root file system --------------------------------------
FROM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build

ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG DATE=unknown

# Never download another toolchain: the image provides the one of go.mod (toolchain go1.27.3).
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly

WORKDIR /src
# No separate `go mod download` layer: it would also fetch the development tools declared in
# go.mod (golangci-lint, govulncheck). go build fetches only the modules of the server binary,
# and the module and build cache mounts keep them between builds.
COPY . .
COPY --from=web /src/web/dist/ ./web/dist/

# Same ldflags as the Makefile build target. timetzdata embeds the time zone database, so that a
# TZ variable works without /usr/share/zoneinfo in the scratch image.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -f web/dist/public/index.html && \
    go build -trimpath -tags timetzdata \
      -ldflags "-s -w \
        -X github.com/ed-fr/transteira/internal/version.Version=${VERSION} \
        -X github.com/ed-fr/transteira/internal/version.Commit=${COMMIT} \
        -X github.com/ed-fr/transteira/internal/version.Date=${DATE}" \
      -o /out/transteira ./cmd/transteira

# Root file system of the final image: the transteira user and group (10001, fixed so that
# host-side tools such as logrotate can rely on it), the CA bundle (SMTP over TLS) and the
# directories the server writes to, owned by that user. /tmp is world-writable with the sticky
# bit, for a container started without a tmpfs.
RUN mkdir -p /rootfs/etc/ssl/certs /rootfs/data /rootfs/var/lib/transteira/db /rootfs/backups \
      /rootfs/logs /rootfs/tmp && \
    echo 'transteira:x:10001:10001:TransTeira:/nonexistent:/sbin/nologin' > /rootfs/etc/passwd && \
    echo 'transteira:x:10001:' > /rootfs/etc/group && \
    cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt && \
    chown -R 10001:10001 /rootfs/data /rootfs/var/lib/transteira /rootfs/backups /rootfs/logs && \
    chmod 0750 /rootfs/data /rootfs/var/lib/transteira /rootfs/var/lib/transteira/db /rootfs/logs && \
    chmod 0700 /rootfs/backups && \
    chmod 1777 /rootfs/tmp

# --- final: scratch ----------------------------------------------------------------------------
FROM scratch

ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG DATE=unknown

LABEL org.opencontainers.image.title="TransTeira" \
      org.opencontainers.image.description="Self-hosted multi-tenant file transfer" \
      org.opencontainers.image.source="https://github.com/ed-fr/transteira" \
      org.opencontainers.image.url="https://github.com/ed-fr/transteira" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}"

COPY --from=build /rootfs/ /
COPY --from=build /out/transteira /transteira

# Container paths of the volumes (see the header). The database keeps its default location,
# /var/lib/transteira/db/transteira.db, so that TT_DB_DSN or TT_DB_DSN_FILE stays free for
# PostgreSQL. TT_MASTER_KEY_FILE and TT_ADMIN_HOSTS have no default and must be set.
ENV TT_LISTEN_ADDR=:8080 \
    TT_DATA_DIR=/data \
    TT_BACKUP_DIR=/backups \
    TT_LOG_DIR=/logs

USER 10001:10001

# Documentation only: the port is reached through the shared proxy network, never published.
EXPOSE 8080

# `healthcheck` probes http://127.0.0.1:<port of TT_LISTEN_ADDR>/healthz: healthy only when the
# application, the database and ClamAV answer.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/transteira", "healthcheck"]

ENTRYPOINT ["/transteira"]
CMD ["serve"]
