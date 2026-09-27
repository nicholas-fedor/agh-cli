# agh-cli Makefile
# Standardized build, test, lint, and release targets

# Variables
BINARY_NAME=agh-cli
BINARY_DIR=bin
GO=go
GOLANGCI_LINT=golangci-lint
GORELEASER=goreleaser
MOCKERY ?= mockery
DOCKER=docker

# Build settings
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT  := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG := github.com/nicholas-fedor/agh-cli
# trimpath strips ldflags until https://github.com/golang/go/pull/68544 merged
# GOFLAGS=-trimpath
LDFLAGS := -s -w\
			-X '$(PKG)/internal/metadata.Version=$(VERSION)' \
            -X '$(PKG)/internal/metadata.CommitSHA=$(COMMIT)' \
            -X '$(PKG)/internal/metadata.BuildTime=$(BUILD_TIME)'

# Default target
.PHONY: help
help: ## Show this help message
	@echo "agh-cli Project Makefile"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# =============================================================================
# Development Targets
# =============================================================================

.PHONY: build mock test test-verbose bench lint vet fmt run install tidy

build: ## Build the application binary
	$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/$(BINARY_NAME) .

mock: ## Generate mocks using mockery
	@echo "Generating mocks with mockery..."
	$(MOCKERY) --config=build/mockery/mockery.yaml

test: ## Run all tests
	$(GO) test -test.fullpath=true -timeout 30s -covermode atomic -v ./...

test-coverage: ## Run all tests with coverage
	$(GO) test  -test.fullpath=true -timeout 30s -covermode=atomic -v  -coverprofile=coverage.out ./...

bench: ## Run benchmarks
	$(GO) test -bench=. -benchmem ./...

lint: ## Run linter and apply fixes
	$(GOLANGCI_LINT) run --fix --config build/golangci-lint/golangci-lint.yaml ./...

vet: ## Run Go vet
	$(GO) vet ./...

fmt: ## Format code using goimports
	$(GOLANGCI_LINT) fmt --config build/golangci-lint/golangci-lint.yaml ./...

run: ## Run the application
	$(GO) run .

install: install-tools ## Install the application (full pipeline)
	$(GO) install $(GOFLAGS) -ldflags="$(LDFLAGS)" ./...

tidy: ## Tidy Go modules and verify consistency
	$(GO) mod tidy
	$(GO) mod verify

# =============================================================================
# Dependency Management
# =============================================================================

.PHONY: deps mod-tidy mod-download

deps: mod-download ## Download all dependencies
	$(GO) get -t -d ./...

mod-tidy: tidy ## Tidy and verify Go modules (alias for tidy)

mod-download: ## Download Go module dependencies
	$(GO) mod download

.PHONY: mod-graph mod-why
mod-graph: ## Show module dependency graph
	$(GO) mod graph

mod-why: ## Explain why a module is needed
	@read -p "Enter module name: " module; \
	$(GO) mod why $$module

# =============================================================================
# Release Targets
# =============================================================================

.PHONY: release release-stable release-nightly

release: release-stable ## Create a new stable release using GoReleaser
	@echo "Release completed"

release-stable: ## Create a new stable release
	$(GORELEASER) release --config build/goreleaser/stable.yaml --clean

release-nightly: ## Create a new nightly release
	$(GORELEASER) release --config build/goreleaser/nightly.yaml --clean

.PHONY: check
check: lint vet test ## Run lint, vet, and test

# =============================================================================
# Docker Targets
# =============================================================================

.PHONY: docker-build docker-run docker-push docker-clean

docker-build: ## Build Docker image
	$(DOCKER) build -t $(BINARY_NAME) -f build/docker/Dockerfile .

docker-run: ## Run Docker container
	$(DOCKER) run $(BINARY_NAME)

docker-push: docker-build ## Push Docker images (requires DOCKER_NAMESPACE and GHCR_NAMESPACE env vars)
	$(DOCKER) push $(DOCKER_NAMESPACE)/$(BINARY_NAME)
	$(DOCKER) push ghcr.io/$(GHCR_NAMESPACE)/$(BINARY_NAME)

docker-clean: ## Remove Docker images
	$(DOCKER) rmi $(BINARY_NAME) || true

# =============================================================================
# Utility Targets
# =============================================================================

.PHONY: clean clean-all

clean: ## Clean build artifacts
	rm -rf $(BINARY_DIR)/
	rm -f coverage.out

clean-all: clean ## Clean all generated files including vendor
	rm -rf tmp/
	rm -rf vendor/

install-tools: ## Install development tools (Go-based)
	@echo "Installing development tools..."
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || (echo "Installing golangci-lint..." && $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest)
	@command -v $(GORELEASER) >/dev/null 2>&1 || (echo "Installing goreleaser..." && $(GO) install github.com/goreleaser/goreleaser/v2@latest)
	@command -v $(MOCKERY) >/dev/null 2>&1 || (echo "Installing mockery..." && $(GO) install github.com/vektra/mockery/v3@latest)
	@echo ""
	@echo "All Go tools installed!"

# =============================================================================
# CI/CD Targets
# =============================================================================

.PHONY: ci-check
ci-check: ## Run all checks as in CI
	@echo "Running CI checks..."
	@$(MAKE) tidy
	@$(MAKE) lint
	@$(MAKE) vet
	@$(MAKE) test
	@echo "CI checks passed!"

# =============================================================================
# Security Targets
# =============================================================================

.PHONY: gosec audit
gosec: ## Run security linter
	$(GOLANGCI_LINT) run --config build/golangci-lint/golangci-lint.yaml --enable-only=gosec ./...

audit: ## Check for outdated dependencies
	@echo "Checking for dependency updates..."
	@$(GO) list -m -u all

.PHONY: help-extra
help-extra: ## Show extended help with all targets
	@echo ""
	@echo "Additional targets:"
	@echo "  tidy          - Tidy and verify Go modules"
	@echo "  deps          - Download all dependencies"
	@echo "  mod-graph     - Show module dependency graph"
	@echo "  mod-why       - Explain why a module is needed"
	@echo "  ci-check      - Run all CI checks (tidy, lint, vet, test)"
	@echo "  gosec         - Run security linter"
	@echo "  audit         - Check for outdated dependencies"
	@echo "  install-tools - Install development tools"
	@echo "  clean-all     - Clean all generated files"
