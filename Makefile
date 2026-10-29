# TransTeira - local quality pipeline (there is no CI: `make check` is the gate).
# On Windows, run make from Git Bash.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO          ?= go
MODULE      := github.com/ed-fr/transteira
SPECTRAL    := npx --yes @stoplight/spectral-cli@6.15.0
COVERPROFILE := coverage.out
BIN_DIR     := bin

# The race detector needs cgo and a C compiler; enable it only when one is available.
RACE := $(if $(shell command -v gcc 2>/dev/null),-race,)

GITLEAKS    := $(GO) run github.com/zricethezav/gitleaks/v8@v8.30.1

# Throwaway PostgreSQL for the tests (test/README.md). Local fake credentials.
TEST_COMPOSE      := docker compose -f test/docker-compose.test.yml
# App role (DML only) and owner role (runs migrations, owns the schema objects).
TEST_POSTGRES_DSN         ?= postgres://transteira_app:transteira_app@127.0.0.1:55432/transteira_test?sslmode=disable
TEST_POSTGRES_MIGRATE_DSN ?= postgres://transteira_owner:transteira_owner@127.0.0.1:55432/transteira_test?sslmode=disable
# Test container superuser, only used by isolation tests that need to create extra roles.
TEST_POSTGRES_SUPERUSER_DSN ?= postgres://transteira_test:transteira_test@127.0.0.1:55432/transteira_test?sslmode=disable
# Mailpit captures the mails sent by the tests (SMTP and HTTP API).
TEST_MAILPIT_SMTP ?= 127.0.0.1:51025
TEST_MAILPIT_API  ?= http://127.0.0.1:58025
# npm audit queries the npm registry: `make check NPM_AUDIT=0` skips it when offline (never before a release).
NPM_AUDIT         ?= 1
# The 10-minute default timeout of go test is too short for the slowest packages on a loaded machine.
GO_TEST           := $(GO) test $(RACE) -timeout=30m -shuffle=on -count=1 -covermode=atomic -coverprofile=$(COVERPROFILE) ./...

COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# SemVer without the leading "v": the exact tag of HEAD when there is one, a dev version otherwise.
VERSION ?= $(or $(shell git describe --tags --exact-match 2>/dev/null | sed 's/^v//'),0.0.0-dev+$(COMMIT))
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: help check check-full web-install web-gen web-check web-build fmt fmt-check vet lint vuln secrets api-lint generate generate-check \
	test test-sqlite test-pg test-clamav test-env-up test-env-down cover env-example env-example-check build hooks \
	e2e e2e-run e2e-install e2e-browser e2e-lint screenshots screenshots-run screenshots-check bigfile clean

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-18s %s\n", $$1, $$2}'

# `test` and `e2e` cover SQLite and PostgreSQL; `cover` gates the Go coverage of `test` right after it.
# The fast e2e checks (lint, screenshot manifest) run with the other static checks; the browser
# suite runs after the Go tests. The Docker gates (docker-check, proxy-configs-check,
# deploy-config-check) are appended to this list in their own sections below, so they run after
# `e2e`, in that order; bigfile (5 GB through Caddy, 20 GB in check-full) is appended last.
CHECK_GATES := web-install web-check web-build fmt-check vet lint vuln secrets api-lint generate-check \
	env-example-check e2e-lint screenshots-check test cover e2e

# --- Docker image ---
# The container image (Dockerfile, scratch, UID 10001). `docker` builds it with the same VERSION,
# COMMIT and DATE as `build`; `docker-check` builds it and smoke-tests it (scripts/docker-check.sh
# lists the checks). docker-check joins `make check`, defined here before the check rule so that
# its prerequisites see it; it is skipped with a message when Docker is unavailable, or with
# DOCKER_CHECK=0.
DOCKER       ?= docker
DOCKER_IMAGE ?= transteira
DOCKER_CHECK ?= 1
# Docker tags do not accept "+": 0.0.0-dev+abc1234 is tagged 0.0.0-dev-abc1234 (the version
# label and the binary keep the exact SemVer).
DOCKER_TAG   := $(subst +,-,$(VERSION))
CHECK_GATES  += docker-check

.PHONY: docker docker-check

docker: ## Build the container image transteira:<version> and transteira:local
	$(DOCKER) build \
		--build-arg VERSION='$(VERSION)' --build-arg COMMIT='$(COMMIT)' --build-arg DATE='$(DATE)' \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) -t $(DOCKER_IMAGE):local .
	@echo "docker: built $(DOCKER_IMAGE):$(DOCKER_TAG) ($$($(DOCKER) history --human=false --format '{{.Size}}' $(DOCKER_IMAGE):local | awk '{s+=$$1} END {printf "%.1f MiB uncompressed", s/1048576}'))"

docker-check: ## Build the image and smoke-test it (DOCKER_CHECK=0 skips; skipped without Docker)
	@if [ "$(DOCKER_CHECK)" = "0" ]; then \
		echo "docker-check: SKIPPED (DOCKER_CHECK=0)"; \
	elif ! $(DOCKER) info >/dev/null 2>&1; then \
		echo "docker-check: SKIPPED (Docker is not available: '$(DOCKER) info' failed)"; \
	else \
		$(MAKE) --no-print-directory docker VERSION='$(VERSION)' COMMIT='$(COMMIT)' DATE='$(DATE)' && \
		DOCKER='$(DOCKER)' bash scripts/docker-check.sh $(DOCKER_IMAGE):local '$(VERSION)'; \
	fi
# --- end of Docker image ---

# --- Reverse proxy configs ---
# Validates integrations/reverse-proxy with the real proxies in Docker (pinned images): caddy
# validate + fmt, nginx -t, httpd -t, Traefik started with the file provider then the labels
# (integrations/reverse-proxy/check.sh lists the checks). Joins `make check`; skipped with a
# message when Docker is unavailable.
CHECK_GATES += proxy-configs-check

.PHONY: proxy-configs-check

proxy-configs-check: ## Validate the Caddy, Nginx, Apache and Traefik configurations in Docker
	@DOCKER='$(DOCKER)' bash integrations/reverse-proxy/check.sh
# --- end of Reverse proxy configs ---

# --- Deployment ---
# Validates deploy/ without starting anything and without real secrets: docker compose config for
# the SQLite file and the PostgreSQL overlay, hardening invariants (no port, read-only, no
# capability), and clamconf on deploy/clamav/clamd.conf (scripts/deploy-config-check.sh lists the
# checks). Joins `make check`; skipped with a message when Docker is unavailable.
CHECK_GATES += deploy-config-check

.PHONY: deploy-config-check

deploy-config-check: ## Validate the production compose files and clamd.conf (skipped without Docker)
	@if ! $(DOCKER) info >/dev/null 2>&1; then \
		echo "deploy-config-check: SKIPPED (Docker is not available: '$(DOCKER) info' failed)"; \
	else \
		DOCKER='$(DOCKER)' bash scripts/deploy-config-check.sh; \
	fi

# End-to-end smoke test of the production files: builds the image, starts deploy/ (SQLite, then
# the PostgreSQL overlay) with the real ClamAV behind the reference Caddy, then deposits, scans
# (EICAR), downloads and backs up through HTTPS (scripts/deploy-smoke.sh lists the checks).
# Deliberately NOT in CHECK_GATES: it needs Internet access (ClamAV signatures) and takes several
# minutes. Run before committing a change to Dockerfile, deploy/ or integrations/reverse-proxy/.
DEPLOY_SMOKE_DB ?= both

.PHONY: deploy-smoke

deploy-smoke: docker ## End-to-end test of deploy/ behind Caddy with real ClamAV (DEPLOY_SMOKE_DB=sqlite|postgres|both; needs Internet)
	DOCKER='$(DOCKER)' TRANSTEIRA_IMAGE=$(DOCKER_IMAGE):local bash scripts/deploy-smoke.sh $(DEPLOY_SMOKE_DB)
# --- end of Deployment ---

# --- Big-file test (5 GB, 20 GB before a release) ---
# CLAUDE.md section 24.2: a 5 GiB file (20 GiB with BIGFILE=1) generated on the fly, uploaded with tus through the
# reference Caddy to the production stack (real ClamAV), the connection cut and resumed during the
# upload and the download, the SHA-256 compared, the server memory sampled and checked (peak and
# trend). Both engines, one after the other, each stack torn down with its volumes before the
# next. scripts/bigfile.sh lists the steps; test/README.md, section "Big-file test", the
# prerequisites (Docker disk of 60 to 80 GB, 7 GiB of memory) and the variables. The LAST gate of
# `make check`, through bigfile-auto (scripts/bigfile-auto.sh): with the default BIGFILE=auto it
# runs only when the big-file chain changed since its last green run; `make check-full`
# (BIGFILE=1) always runs it, before every release; BIGFILE=0 skips it. `make bigfile` alone
# always runs it unless BIGFILE=0. Size: 5 GiB by default (above the 2 GiB ClamAV limit and the
# 4 GiB ZIP64 and 32-bit offset boundaries), 20 GiB with BIGFILE=1 (`make check-full`).
BIGFILE         ?= auto
ifeq ($(BIGFILE),1)
BIGFILE_BYTES   ?= 21474836480
else
BIGFILE_BYTES   ?= 5368709120
endif
BIGFILE_DBS     ?= both
BIGFILE_KEEP    ?= 0
BIGFILE_MAX_MEM ?= 256MiB
CHECK_GATES     += bigfile-auto

.PHONY: bigfile-auto bigfile-clean

bigfile: ## 5 GB (20 GB with BIGFILE=1) upload/download test through Caddy, cut and resumed (BIGFILE=0 skips; BIGFILE_BYTES, BIGFILE_DBS, BIGFILE_KEEP)
	@if [ "$(BIGFILE)" = "0" ]; then \
		echo "bigfile: SKIPPED (BIGFILE=0): never skip the 20 GB test before a release"; \
	else \
		$(MAKE) --no-print-directory docker VERSION='$(VERSION)' COMMIT='$(COMMIT)' DATE='$(DATE)' && \
		DOCKER='$(DOCKER)' TRANSTEIRA_IMAGE=$(DOCKER_IMAGE):local BIGFILE_BYTES='$(BIGFILE_BYTES)' \
		BIGFILE_DBS='$(BIGFILE_DBS)' BIGFILE_KEEP='$(BIGFILE_KEEP)' BIGFILE_MAX_MEM='$(BIGFILE_MAX_MEM)' \
		BIGFILE_CHUNK='$(BIGFILE_CHUNK)' BIGFILE_CUT_AT='$(BIGFILE_CUT_AT)' BIGFILE_DL_CUT_AT='$(BIGFILE_DL_CUT_AT)' \
		BIGFILE_SEED='$(BIGFILE_SEED)' BIGFILE_SCAN_TIMEOUT='$(BIGFILE_SCAN_TIMEOUT)' \
		BIGFILE_CLAMAV_MAX_SCAN_BYTES='$(BIGFILE_CLAMAV_MAX_SCAN_BYTES)' BIGFILE_MIN_FREE='$(BIGFILE_MIN_FREE)' \
		BIGFILE_MAX_CLOCK_OFFSET='$(BIGFILE_MAX_CLOCK_OFFSET)' bash scripts/bigfile.sh; \
	fi

bigfile-auto: ## Run the 5 GB test when its chain changed since its last green run (BIGFILE=auto|1|0)
	@BIGFILE='$(BIGFILE)' BIGFILE_BYTES='$(BIGFILE_BYTES)' BIGFILE_DBS='$(BIGFILE_DBS)' \
		BIGFILE_MAX_MEM='$(BIGFILE_MAX_MEM)' BIGFILE_CHUNK='$(BIGFILE_CHUNK)' BIGFILE_CUT_AT='$(BIGFILE_CUT_AT)' \
		BIGFILE_DL_CUT_AT='$(BIGFILE_DL_CUT_AT)' BIGFILE_SEED='$(BIGFILE_SEED)' \
		BIGFILE_CLAMAV_MAX_SCAN_BYTES='$(BIGFILE_CLAMAV_MAX_SCAN_BYTES)' \
		bash scripts/bigfile-auto.sh '$(MAKE)' --no-print-directory bigfile \
		VERSION='$(VERSION)' COMMIT='$(COMMIT)' DATE='$(DATE)'

bigfile-clean: ## Remove what a failed BIGFILE_KEEP=1 run of the 20 GB test left (transteira-bigfile-* only)
	@DOCKER='$(DOCKER)' bash scripts/bigfile.sh clean
# --- end of big-file test ---

# The gates run in turn through scripts/check.sh, each in its own make invocation, which stops at
# the first failure (`make -k` does not apply) and prints the duration of every gate. VERSION,
# COMMIT and DATE are computed once here and passed down, so every gate builds the same version.
check: ## Run every quality gate (must be green before each commit; 20 GB test when its chain changed)
	@rm -f .cache/bigfile.last
	@MAKE='$(MAKE)' bash scripts/check.sh VERSION='$(VERSION)' COMMIT='$(COMMIT)' DATE='$(DATE)' -- $(CHECK_GATES)
	@if [ "$(BIGFILE)" = "0" ]; then \
		echo "make check: ALL GREEN (bigfile SKIPPED: BIGFILE=0, never before a release)"; \
	elif [ "$$(cat .cache/bigfile.last 2>/dev/null)" = "skipped" ]; then \
		echo "make check: ALL GREEN (bigfile skipped: chain unchanged since its last green run; make check-full forces it)"; \
	else \
		echo "make check: ALL GREEN"; \
	fi

check-full: ## make check with the 20 GB test forced at full size (before every release)
	@$(MAKE) --no-print-directory check BIGFILE=1

# Web interface (web/, Node 24 + npm 11; see web/README.md). npm runs with --ignore-scripts:
# no dependency install script is ever executed.
# The stamp lives in node_modules, so that deleting node_modules triggers a reinstall.
WEB_STAMP := web/node_modules/.install-stamp

web-install: $(WEB_STAMP) ## Install the web dependencies from the lockfile (npm ci, only when it changed)

$(WEB_STAMP): web/package-lock.json web/package.json
	cd web && npm ci --ignore-scripts --no-audit --no-fund
	touch $(WEB_STAMP)

web-gen: web-install ## Regenerate the web API types from the OpenAPI specification
	cd web && npm run --silent gen

web-check: web-install ## Web quality gates: generated types, svelte-check, eslint, prettier, vitest coverage, npm audit
	cd web && npm run --silent gen:check
	cd web && npm run --silent check
	cd web && npm run --silent lint
	cd web && npm run --silent format:check
	cd web && npm run --silent test
ifeq ($(NPM_AUDIT),0)
	@echo "web-check: npm audit SKIPPED (NPM_AUDIT=0)"
else
	cd web && npm audit --audit-level=high
endif

web-build: web-install ## Build the web interface into web/dist (checked by scripts/check-dist.mjs)
	cd web && npm run --silent build

fmt: ## Format Go code (gofumpt + goimports)
	$(GO) tool golangci-lint fmt ./...

fmt-check: ## Fail if Go code is not formatted
	$(GO) tool golangci-lint fmt --diff ./...

vet: ## go vet (and the 20 GB test client, built with the bigfile tag)
	$(GO) vet ./...
	$(GO) vet -tags bigfile ./test/bigfile/...

lint: ## golangci-lint
	$(GO) tool golangci-lint run ./...

vuln: ## govulncheck on the module
	$(GO) tool govulncheck ./...

secrets: ## Scan the working tree for secrets (gitleaks, same rules as the pre-push hook)
	$(GITLEAKS) dir --no-banner --redact --config .gitleaks.toml .

api-lint: ## Lint the OpenAPI specification (Spectral)
	$(SPECTRAL) lint --fail-severity=warn --ruleset .spectral.yaml api/openapi.yaml

generate: ## Regenerate code from the OpenAPI specification
	$(GO) generate ./...

generate-check: ## Fail if generated code is out of date
	@tmp=$$(mktemp -d .gencheck.XXXXXX); \
	cp internal/api/gen/gen.go "$$tmp/gen.go"; \
	stubs=/dev/null; \
	if [ -f internal/api/stubs/stubs_gen.go ]; then \
		cp internal/api/stubs/stubs_gen.go "$$tmp/stubs_gen.go"; stubs="$$tmp/stubs_gen.go"; \
	fi; \
	trap 'cp "$$tmp/gen.go" internal/api/gen/gen.go; \
		if [ -f "$$tmp/stubs_gen.go" ]; then cp "$$tmp/stubs_gen.go" internal/api/stubs/stubs_gen.go; \
		else rm -f internal/api/stubs/stubs_gen.go; fi; \
		rm -rf "$$tmp"' EXIT; \
	$(GO) generate ./api/; \
	stale=; \
	diff -q "$$tmp/gen.go" internal/api/gen/gen.go >/dev/null || stale="$$stale internal/api/gen"; \
	diff -q "$$stubs" internal/api/stubs/stubs_gen.go >/dev/null || stale="$$stale internal/api/stubs"; \
	if [ -n "$$stale" ]; then \
		echo "generated code is out of date:$$stale: run 'make generate'"; exit 1; \
	fi; echo "generated code is up to date"

test: test-env-up ## Unit and integration tests with coverage, on SQLite and PostgreSQL
	TT_TEST_POSTGRES_DSN='$(TEST_POSTGRES_DSN)' \
	TT_TEST_POSTGRES_MIGRATE_DSN='$(TEST_POSTGRES_MIGRATE_DSN)' \
	TT_TEST_POSTGRES_SUPERUSER_DSN='$(TEST_POSTGRES_SUPERUSER_DSN)' \
	TT_TEST_MAILPIT_SMTP='$(TEST_MAILPIT_SMTP)' \
	TT_TEST_MAILPIT_API='$(TEST_MAILPIT_API)' \
	TT_TEST_REQUIRE_POSTGRES=1 $(GO_TEST)

test-pg: test ## Alias of test (PostgreSQL is mandatory there)

test-clamav: ## Live antivirus test against a real clamd (set TT_TEST_CLAMAV_ADDR; not part of check)
	TT_TEST_CLAMAV_ADDR="$${TT_TEST_CLAMAV_ADDR:?set TT_TEST_CLAMAV_ADDR, see docs/operations/antivirus.md}" \
		$(GO) test -count=1 -run TestScanLive -v ./internal/antivirus/

test-sqlite: ## Quick loop: tests without PostgreSQL (not part of check)
	$(GO_TEST)

test-env-up: ## Start the test PostgreSQL and Mailpit and wait until healthy
	$(TEST_COMPOSE) up -d --wait postgres mailpit

test-env-down: ## Stop the test environment (PostgreSQL, Mailpit, e2e Caddy) and drop its volumes
	$(TEST_COMPOSE) --profile e2e down -v

cover: ## Enforce coverage thresholds (CLAUDE.md section 24.3)
	$(GO) run ./tools/covercheck -profile $(COVERPROFILE) -config tools/covercheck/thresholds.json

env-example: ## Regenerate .env.example from internal/config
	$(GO) run ./tools/envexample > .env.example

env-example-check: ## Fail if .env.example is out of date
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	$(GO) run ./tools/envexample > "$$tmp"; \
	if ! diff -q "$$tmp" .env.example >/dev/null; then \
		echo ".env.example is out of date: run 'make env-example'"; exit 1; \
	fi; echo ".env.example is up to date"

build: web-build ## Build the static binary into bin/ (with the web interface embedded)
	@test -f web/dist/public/index.html || { echo "web/dist/public/index.html missing: the web build failed"; exit 1; }
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/transteira ./cmd/transteira

hooks: ## Install the local git hooks (gitleaks on pre-push)
	chmod +x scripts/hooks/*
	git config core.hooksPath scripts/hooks
	@echo "git hooks installed (core.hooksPath=scripts/hooks)"

# End-to-end tests (test/e2e, Playwright + Chromium through Caddy; see test/README.md).
# Same npm policy as web/: lockfile install with --ignore-scripts, stamp in node_modules.
E2E_STAMP := test/e2e/node_modules/.install-stamp
# Set to 0 to never download the browser (offline; Chromium must already be in the cache).
E2E_BROWSER_INSTALL ?= 1
# Database engines run by `make e2e`, in order.
E2E_DBS  ?= sqlite postgres
# Extra arguments for `playwright test`, e.g. E2E_ARGS="specs/smoke.spec.ts --headed".
E2E_ARGS ?=

e2e-install: $(E2E_STAMP) ## Install the e2e dependencies from the lockfile (npm ci, only when it changed)

$(E2E_STAMP): test/e2e/package-lock.json test/e2e/package.json
	cd test/e2e && npm ci --ignore-scripts --no-audit --no-fund
	touch $(E2E_STAMP)

e2e-browser: e2e-install ## Install Playwright's Chromium unless it is already cached (E2E_BROWSER_INSTALL=0 skips)
	@cd test/e2e && if node scripts/browser-installed.mjs; then \
		echo "e2e-browser: Chromium already installed"; \
	elif [ "$(E2E_BROWSER_INSTALL)" = "0" ]; then \
		echo "e2e-browser: Chromium missing and E2E_BROWSER_INSTALL=0"; exit 1; \
	else \
		npx playwright install chromium; \
	fi

e2e-lint: e2e-install ## e2e quality gates: prettier, eslint, tsc, npm audit
	cd test/e2e && npm run --silent format:check
	cd test/e2e && npm run --silent lint
	cd test/e2e && npm run --silent typecheck
ifeq ($(NPM_AUDIT),0)
	@echo "e2e-lint: npm audit SKIPPED (NPM_AUDIT=0)"
else
	cd test/e2e && npm audit --audit-level=high
endif

# Only one e2e run at a time on the machine (shared .run/, Caddy on port 443, e2e database):
# with-lock.mjs takes the run lock (test/e2e/.run.lock) before the build and keeps it for both
# engines; a second run waits. The *-run targets do the work under that lock.
E2E_WITH_LOCK := node test/e2e/scripts/with-lock.mjs $(MAKE) --no-print-directory

e2e: e2e-browser test-env-up ## Playwright end-to-end tests, on SQLite then PostgreSQL (E2E_DBS, E2E_ARGS)
	@$(E2E_WITH_LOCK) e2e-run

e2e-run: build
	@for db in $(E2E_DBS); do \
		echo "=== e2e on $$db"; \
		start=$$(date +%s); \
		( cd test/e2e && E2E_DB=$$db npx playwright test $(E2E_ARGS) ) || exit 1; \
		echo "=== e2e on $$db passed in $$(( $$(date +%s) - start )) s"; \
	done

screenshots: e2e-browser test-env-up ## Regenerate docs/user/screenshots (fr, en) and its manifest (SQLite, under the e2e lock)
	@$(E2E_WITH_LOCK) screenshots-run

screenshots-run: build
	@start=$$(date +%s); \
	( cd test/e2e && SCREENSHOTS=1 E2E_DB=sqlite npx playwright test $(E2E_ARGS) ) || exit 1; \
	echo "=== screenshots captured in $$(( $$(date +%s) - start )) s"

screenshots-check: ## Check docs/user/screenshots against its manifest (both languages, no orphan)
	node --test test/e2e/scripts/check-screenshots.mjs

clean: ## Remove build and coverage artefacts (web/dist keeps its committed .gitkeep)
	rm -rf $(BIN_DIR) $(COVERPROFILE) web/coverage
	node -e "const fs=require('fs'),p=require('path');for(const n of fs.readdirSync('web/dist'))if(n!=='.gitkeep')fs.rmSync(p.join('web/dist',n),{recursive:true,force:true})"
