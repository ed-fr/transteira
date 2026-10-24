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

.PHONY: help check web-install web-gen web-check web-build fmt fmt-check vet lint vuln secrets api-lint generate generate-check \
	test test-sqlite test-pg test-clamav test-env-up test-env-down cover env-example env-example-check build hooks \
	e2e e2e-run e2e-install e2e-browser e2e-lint screenshots screenshots-run screenshots-check bigfile clean

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-18s %s\n", $$1, $$2}'

# `test` and `e2e` cover SQLite and PostgreSQL; `cover` gates the Go coverage of `test` right after it.
# The fast e2e checks (lint, screenshot manifest) run with the other static checks; the browser
# suite runs last. bigfile (20 GB through Caddy) joins this list when its pipeline arrives.
CHECK_GATES := web-install web-check web-build fmt-check vet lint vuln secrets api-lint generate-check \
	env-example-check e2e-lint screenshots-check test cover e2e
check: $(CHECK_GATES) ## Run every quality gate (must be green before each commit)
	@echo "make check: ALL GREEN"

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

vet: ## go vet
	$(GO) vet ./...

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

bigfile: ## 20 GB upload test through Caddy (not available yet)
	@echo "bigfile: NOT AVAILABLE YET (upload pipeline arrives in a later step)"

clean: ## Remove build and coverage artefacts (web/dist keeps its committed .gitkeep)
	rm -rf $(BIN_DIR) $(COVERPROFILE) web/coverage
	node -e "const fs=require('fs'),p=require('path');for(const n of fs.readdirSync('web/dist'))if(n!=='.gitkeep')fs.rmSync(p.join('web/dist',n),{recursive:true,force:true})"
