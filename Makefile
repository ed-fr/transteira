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

COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# SemVer without the leading "v": the exact tag of HEAD when there is one, a dev version otherwise.
VERSION ?= $(or $(shell git describe --tags --exact-match 2>/dev/null | sed 's/^v//'),0.0.0-dev+$(COMMIT))
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: help check fmt fmt-check vet lint vuln secrets api-lint generate generate-check \
	test cover env-example env-example-check build hooks test-pg e2e bigfile clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-18s %s\n", $$1, $$2}'

# test-pg, e2e and bigfile join this list when the database, web and upload layers arrive.
check: fmt-check vet lint vuln secrets api-lint generate-check env-example-check test cover ## Run every quality gate (must be green before each commit)
	@echo "make check: ALL GREEN"

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
	cp internal/api/gen/gen.go "$$tmp/current.go"; \
	trap 'cp "$$tmp/current.go" internal/api/gen/gen.go; rm -rf "$$tmp"' EXIT; \
	$(GO) generate ./api/; \
	if ! diff -q "$$tmp/current.go" internal/api/gen/gen.go >/dev/null; then \
		echo "internal/api/gen is out of date: run 'make generate'"; exit 1; \
	fi; echo "generated code is up to date"

test: ## Unit and integration tests with coverage
	$(GO) test $(RACE) -shuffle=on -count=1 -covermode=atomic -coverprofile=$(COVERPROFILE) ./...

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

build: ## Build the static binary into bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/transteira ./cmd/transteira

hooks: ## Install the local git hooks (gitleaks on pre-push)
	chmod +x scripts/hooks/*
	git config core.hooksPath scripts/hooks
	@echo "git hooks installed (core.hooksPath=scripts/hooks)"

test-pg: ## Run the test suite on PostgreSQL (not available yet)
	@echo "test-pg: NOT AVAILABLE YET (database layer arrives in a later step)"

e2e: ## Playwright end-to-end tests (not available yet)
	@echo "e2e: NOT AVAILABLE YET (web interface arrives in a later step)"

bigfile: ## 20 GB upload test through Caddy (not available yet)
	@echo "bigfile: NOT AVAILABLE YET (upload pipeline arrives in a later step)"

clean: ## Remove build and coverage artefacts
	rm -rf $(BIN_DIR) $(COVERPROFILE)
