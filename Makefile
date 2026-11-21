# Pomar: isolated Linux jobs and development seats on Apple silicon.
# Start with make help. Heavy targets need an admitted builder; make verify
# remains the full native gate at the committed head under review.
# Maintainers: make verify HYGIENE_DENYLIST=<path> HYGIENE_REQUIRE=1
SHELL := /bin/sh
.DEFAULT_GOAL := help
# Swift tests relink the host, so entitlement signing must follow them even -j.
# Admission across processes remains the host owner's responsibility.
.NOTPARALLEL:
export GOTOOLCHAIN := local
export GOFLAGS := -mod=readonly

HYGIENE_DENYLIST ?=
HYGIENE_REQUIRE ?= 0
HYGIENE_COPY := .hygiene/denylist.txt
BIN_DIR := .build/bin
GO_COMMANDS := pomar pomar-agent-owner pomar-ci-caller pomar-agent-host pomar-agent-login pomar-agent-export
export HYGIENE_DENYLIST HYGIENE_REQUIRE
export VERSION RELEASE_OUT POMAR_DEV_ROOT POMAR_KERNEL_SHA256

.PHONY: help help-all help-check doctor setup verify versions no-docker hygiene gofmt vet lint test
.PHONY: shim swift-build swift-test swift-sign go-build guest build prepare kernel run release-candidate release clean makefile-check hooks

help: ## First-time guide: what Pomar does and the five starting commands
	@printf '%s\n' 'Pomar runs isolated Linux jobs and retained development seats on Apple silicon.' \
	  '' 'Start here:' \
	  '  make doctor   Read-only toolchain, network, configuration and hook checks.' \
	  '  make setup    Install the main-push guard and check prerequisites; no tool downloads.' \
	  '  make verify   Full Go/Swift native gate on an admitted Apple silicon builder.' \
	  '  make build    Build local tools, static guest binaries and entitled Swift host.' \
	  '  make run      Foreground manager; explicit POMAR_DEV_ROOT and POMAR_KERNEL_SHA256.' \
	  '' 'Use make help-all for every target, including test, lint, release and clean.' \
	  'Go: the go.mod 1.27.x line. Swift: 6.2 or newer; macOS 26+, ARM64.' \
	  'No manager, data root, account, credentials or production socket is chosen for you.' \
	  'Read the source development guide in CONTRIBUTING.md before heavy work.'

help-all: ## List every documented target, directly from this Makefile
	@awk 'BEGIN {FS = ":.*## "} /^[A-Za-z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' '$(firstword $(MAKEFILE_LIST))'

help-check: ## Refuse undocumented public targets so help-all stays complete
	@awk '/^[A-Za-z0-9_-]+:/ && !/^[A-Za-z0-9_-]+:[:=]/ && !/## / {print "Missing ## description: " $$0; bad=1} END {exit bad}' '$(firstword $(MAKEFILE_LIST))'

doctor: ## Diagnose prerequisites without installing, compiling or changing configuration
	@sh tools/doctor.sh

setup: hooks doctor ## Install the lightweight branch guard, then diagnose prerequisites

verify: versions no-docker hygiene help-check makefile-check gofmt vet test shim swift-build swift-test swift-sign ## Full native merge gate; retain its exact committed-head receipt
	@echo "=== make verify GREEN ==="

versions: ## Print Go, macOS and exact source-head identity for gate evidence
	@printf 'head: '; git rev-parse HEAD
	@echo "=== versions"
	@go version
	@sw_vers 2>/dev/null | sed 's/^/  /' || true

no-docker: ## Refuse a host exposing the Docker socket
	@echo "=== no-docker"
	@test ! -e /var/run/docker.sock || { echo "a Docker socket exists at /var/run/docker.sock"; exit 1; }

# The private deny-list is copied at build time; .hygiene/ is never tracked.
hygiene: ## Check tracked-file hygiene, optionally requiring the private deny-list
	@echo "=== hygiene"
	@rm -f $(HYGIENE_COPY)
	@if [ -n "$(HYGIENE_DENYLIST)" ]; then mkdir -p .hygiene && cp "$(HYGIENE_DENYLIST)" $(HYGIENE_COPY); fi
	@go run ./cmd/pomar-hygiene -denylist "$(if $(HYGIENE_DENYLIST),$(HYGIENE_COPY))" \
		$(if $(filter 1,$(HYGIENE_REQUIRE)),-require-denylist)

gofmt: ## Check Go formatting without changing source
	@echo "=== gofmt"
	@out="$$(gofmt -l .)" || exit $$?; if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

vet: ## Run Go static analysis, including type checking
	@echo "=== go vet"
	@go vet ./...

lint: hygiene gofmt vet ## Check hygiene, formatting and Go static analysis

test: ## Run all Go tests with the race detector and no result cache
	@echo "=== go test"
	@go test -race -count=1 ./...

SHIM_BIN := .build-shim/pomar-shim-linux-arm64
shim: ## Build and verify the static Linux ARM64 in-guest module proxy
	@echo "=== shim (static linux/arm64)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags=-s -o $(SHIM_BIN) ./cmd/pomar-shim
	@file $(SHIM_BIN) | grep -q "ARM aarch64.*statically linked" \
		|| { echo "shim: not a static linux/arm64 binary"; exit 1; }
	@shasum -a 256 $(SHIM_BIN)

# Lazy evaluation: help/doctor/hooks never launch SwiftPM or Xcode probes.
# Some CLT versions need the Swift Testing macro plugin path explicitly.
TESTING_PLUGINS = $(shell xcode-select -p 2>/dev/null)/usr/lib/swift/host/plugins/testing
SWIFT_FLAGS = --package-path host --force-resolved-versions \
	$(if $(wildcard $(TESTING_PLUGINS)),-Xswiftc -plugin-path -Xswiftc $(TESTING_PLUGINS))

swift-build: ## Clean-build Swift host and tests using the locked dependency graph
	@echo "=== swift build (clean)"
	@swift --version 2>&1 | head -1
	@swift package --package-path host clean
	@swift build $(SWIFT_FLAGS) --build-tests

swift-test: ## Run the already-built Swift tests without changing dependency pins
	@echo "=== swift test"
	@swift test $(SWIFT_FLAGS) --skip-build

swift-sign: ## Apply and verify the host's ad-hoc Virtualization entitlement
	@echo "=== swift sign (ad-hoc, virtualization entitlement)"
	@set -eu; host_bin="$$(swift build --package-path host --show-bin-path)/pomar-host"; \
	  codesign --force --sign - --entitlements host/pomar-host.entitlements "$$host_bin" && \
	  entitlements="$$(codesign -d --entitlements - --xml "$$host_bin" 2>/dev/null)" && \
	  printf '%s\n' "$$entitlements" | grep -q com.apple.security.virtualization
	@set -eu; host_bin="$$(swift build --package-path host --show-bin-path)/pomar-host"; "$$host_bin" version

go-build: ## Build the Go coordinator and owner/client tools into .build/bin
	@mkdir -p "$(BIN_DIR)"
	@for command in $(GO_COMMANDS); do go build -trimpath -o "$(BIN_DIR)/$$command" "./cmd/$$command" || exit $$?; done

guest: ## Build the Linux ARM64 guest supervisor without host credentials
	@mkdir -p "$(BIN_DIR)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "$(BIN_DIR)/pomar-agent-guest-linux-arm64" ./cmd/pomar-agent-guest

build: go-build shim guest swift-build swift-sign ## Build sibling local tools and an entitled native VM host
	@set -eu; host_bin="$$(swift build --package-path host --show-bin-path)/pomar-host"; cp "$$host_bin" "$(BIN_DIR)/pomar-host"
	@cp "$(SHIM_BIN)" "$(BIN_DIR)/pomar-shim-linux-arm64"

prepare: ## Prepare the pinned base in explicit POMAR_DEV_ROOT (owner operation)
	@test -n "$$POMAR_DEV_ROOT" || { echo 'Set POMAR_DEV_ROOT to an owner-approved private absolute directory.'; exit 2; }
	@test -x "$(BIN_DIR)/pomar" || { echo 'Build the tools first with make build on an admitted host.'; exit 1; }
	@"$(BIN_DIR)/pomar" server prepare -root "$$POMAR_DEV_ROOT"

kernel: ## Fetch the pinned kernel into POMAR_DEV_ROOT and print its digest
	@test -n "$$POMAR_DEV_ROOT" || { echo 'Set POMAR_DEV_ROOT to the approved development directory.'; exit 2; }
	@test -x "$(BIN_DIR)/pomar" || { echo 'Build the tools first with make build on an admitted host.'; exit 1; }
	@"$(BIN_DIR)/pomar" server kernel -root "$$POMAR_DEV_ROOT"

run: ## Start a foreground development manager with explicit root and kernel digest
	@test -n "$$POMAR_DEV_ROOT" && test -n "$$POMAR_KERNEL_SHA256" || { echo 'Set POMAR_DEV_ROOT and POMAR_KERNEL_SHA256 from the approved prepare/kernel steps.'; exit 2; }
	@test -x "$(BIN_DIR)/pomar" || { echo 'Build the tools first with make build on an admitted host.'; exit 1; }
	@exec "$(BIN_DIR)/pomar" server start -root "$$POMAR_DEV_ROOT" -kernel-sha256 "$$POMAR_KERNEL_SHA256"

release-candidate: ## Verify and build an explicit vX.Y.Z-rc.N candidate on an admitted native builder
	@test -n "$$VERSION" && test -n "$$RELEASE_OUT" || { echo 'Set VERSION and RELEASE_OUT; see docs/releases.md.'; exit 2; }
	@printf '%s\n' "$$VERSION" | awk '/^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$$/ {ok=1} END {exit !ok}' || { echo 'Use a candidate version such as v0.1.0-rc.1.'; exit 2; }
	@case "$$RELEASE_OUT" in /*) ;; *) echo 'RELEASE_OUT must be an explicit new absolute output directory.'; exit 2;; esac
	@$(MAKE) verify
	@sh tools/build-release.sh "$$VERSION" "$$RELEASE_OUT"

release: ## Refuse final publication until the reviewed same-byte promotion route is configured
	@printf '%s\n' 'Release promotion is not configured: use the accepted candidate bytes and reviewed publisher.' \
	  'See docs/releases.md. This target does not rebuild, tag, publish or deploy.' >&2
	@exit 2

clean: ## Remove generated local binaries and shim; keep VM data and Swift dependency cache
	@test ! -L .build && test ! -L .build/bin && test ! -L .build-shim || { echo 'Refusing to clean redirected build directories.'; exit 1; }
	@rm -rf .build/bin .build-shim

makefile-check: ## Exercise help, read-only doctor and main-push refusals with lightweight fixtures
	@sh tools/makefile-check.sh

hooks: ## Install the lightweight pre-push guard that refuses updates to main
	@test -x .githooks/pre-push || { echo 'Restore the executable committed .githooks/pre-push first.'; exit 1; }
	@git config --local core.hooksPath .githooks
	@echo 'Main-push guard installed; full make verify still belongs on the admitted build host before a PR.'
