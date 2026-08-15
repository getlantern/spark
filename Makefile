# Spark — the one place that says how to build each thing.
#
# Every target here wraps a script that already existed; nothing new is implemented in this file.
# It exists because the scripts were discoverable only by reading .github/workflows/release.yml,
# and the cost of that was concrete: a build was done with `npm run tauri build`, which produces a
# Tauri shell with NO system extension and an ad-hoc signature — it launches, so it looks fine, and
# it cannot tunnel. See `make macos` below for the command that actually builds the product.
#
# Run `make` (or `make help`) for the target list.

.DEFAULT_GOAL := help
SHELL := /bin/bash

# `npm` is an nvm shell function in some interactive shells and silently no-ops; child processes get
# the real binary from PATH, which is what recipes here rely on.
NPM ?= npm

# Set by the release workflow from repo vars. Builds that embed the WASM-transport verifier refuse
# to compile without it rather than trusting the public dev key — see core/src/transport/wasm/signing.rs.
SPARK_MODULE_PUBKEY_HEX ?=

##@ Help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nSpark build targets\n"} \
		/^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@echo ""

##@ Checks (what CI runs)

.PHONY: fmt
fmt: ## Format all Rust code
	cargo fmt --all
	cd wasm-server && cargo fmt --all

.PHONY: lint
lint: ## Clippy over the workspace + the excluded crates, denying warnings (CI's exact command)
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cd wasm-server && cargo fmt --all --check && cargo clippy --all-targets --locked -- -D warnings

.PHONY: test
test: ## Full test suite, exactly as CI runs it (nextest + doctests + the excluded wasm-server crate)
	# nextest, matching CI: it enforces the per-test timeout in .config/nextest.toml, so a hung
	# test fails fast instead of stalling the job. It does NOT run doctests, hence the second line.
	cargo nextest run --workspace --all-features
	cargo test --workspace --all-features --doc
	cd wasm-server && cargo test --locked

.PHONY: check
check: lint test ## lint + test — run this before pushing

##@ Client (CLI + service)

.PHONY: build
build: ## Debug build of the workspace
	cargo build --workspace

.PHONY: release
release: ## Release build of the client binaries
	cargo build --release

.PHONY: size
size: ## Release-build and fail if any binary exceeds its stripped size budget
	bash scripts/size-budget.sh

##@ macOS product

# THE macOS product. Builds the Tauri UI, builds and embeds the org.getlantern.spark.tunnel system
# extension, signs with a Developer ID identity DERIVED FROM the installed provisioning profiles
# (no need to name one — the script intersects the keychain's Developer ID certs with the certs the
# app + tunnel profiles accept, preferring one both accept), then notarizes and staples.
#
# Notarization is NOT optional for a working build: an un-notarized system extension is refused by
# macOS at activation, so the app launches and the tunnel silently never comes up.
#
# Credentials, one of:
#   AC_USERNAME=<apple-id> AC_PASSWORD=<app-specific-password>   <-- the normal path; these are
#     already exported in the maintainer's shell, so `make macos` works with nothing extra. Check
#     with `env | grep '^AC_'` before concluding they are missing.
#   NOTARY_PROFILE=<name>                  a notarytool keychain profile, created once with:
#                                            xcrun notarytool store-credentials <name> \
#                                              --apple-id <id> --team-id ACZRKC3LQ9 --password <app-specific-password>
#
# iOS (make ios-testflight) uses a different set, also already exported:
#   ASC_KEY_ID + ASC_ISSUER_ID + ASC_KEY_PATH   App Store Connect API key
# Both AC_ vars, not just the username: build-tauri-dmg.sh requires `AC_USERNAME && AC_PASSWORD`,
# so checking only one lets a half-set environment through to fail later and less clearly.
# Reports presence only, never values: AC_USERNAME is an Apple ID and this text can end up in a CI
# log. (`$${VAR:-UNSET}` would print the value when set, which is the opposite of what is wanted.)
define require-notary-creds
	@if [ -z "$$NOTARY_PROFILE" ] && { [ -z "$$AC_USERNAME" ] || [ -z "$$AC_PASSWORD" ]; }; then \
		echo "ERROR: no notarization credentials (need NOTARY_PROFILE, or AC_USERNAME *and* AC_PASSWORD)."; \
		echo "  AC_USERNAME: $$([ -n "$$AC_USERNAME" ] && echo set || echo UNSET)   AC_PASSWORD: $$([ -n "$$AC_PASSWORD" ] && echo set || echo UNSET)"; \
		echo "  An un-notarized system extension is refused at activation, so the app would launch"; \
		echo "  and the tunnel would silently never come up."; \
		echo "  For UI-only iteration where the tunnel is not exercised: make macos-fast"; \
		exit 1; \
	fi
endef

.PHONY: macos
macos: ## Build the signed + NOTARIZED macOS DMG -> dist/Spark.dmg (needs NOTARY_PROFILE or AC_USERNAME+AC_PASSWORD)
	$(require-notary-creds)
	bash packaging/macos/build-tauri-dmg.sh

.PHONY: macos-fast
macos-fast: ## Signed but NOT notarized DMG — UI iteration only, the system extension will NOT load
	@echo "==> SKIP_NOTARIZE=1: the system extension will not activate. UI iteration only."
	SKIP_NOTARIZE=1 bash packaging/macos/build-tauri-dmg.sh

.PHONY: macos-intel
macos-intel: ## Same as `macos`, for x86_64 -> dist/Spark-x86_64.dmg
	$(require-notary-creds)
	MAC_ARCH=x86_64 bash packaging/macos/build-tauri-dmg.sh

.PHONY: gui-dev
gui-dev: ## Run the Tauri UI in dev mode (hot reload; no system extension, cannot tunnel)
	cd gui-tauri && $(NPM) run tauri dev

##@ Linux packages

.PHONY: deb
deb: release ## Build the client .deb from the release binaries
	bash packaging/debian/build-deb.sh

.PHONY: exit
exit: ## Release-build the dynamic-transport exit (requires SPARK_MODULE_PUBKEY_HEX)
	@if [ -z "$(SPARK_MODULE_PUBKEY_HEX)" ]; then \
		echo "ERROR: SPARK_MODULE_PUBKEY_HEX is unset."; \
		echo "  The exit verifies delivered modules against a pinned key; a release build refuses to"; \
		echo "  fall back to the public dev key. For a LOCAL smoke build only, the dev key is:"; \
		echo "    make exit SPARK_MODULE_PUBKEY_HEX=\$$(make -s dev-pubkey)"; \
		exit 1; \
	fi
	cd wasm-server && SPARK_MODULE_PUBKEY_HEX=$(SPARK_MODULE_PUBKEY_HEX) cargo build --release --locked

.PHONY: exit-deb
exit-deb: ## Build the exit .deb (run `make exit` first)
	bash packaging/debian/build-exit-deb.sh

##@ WASM transport modules

.PHONY: modules
modules: ## Build + dev-sign the guest modules, refreshing the committed test fixtures
	bash scripts/build-module.sh

.PHONY: modules-prod
modules-prod: ## Build + sign modules with the real key -> dist/modules (see docs/prod-module-signing-runbook.md)
	@if [ -z "$$MODULE_SIGNING_KEY" ]; then \
		echo "ERROR: set MODULE_SIGNING_KEY=/path/to/prod-module.pkcs8"; exit 1; fi
	MODULE_SIGNING_KEY=$$MODULE_SIGNING_KEY bash scripts/build-module.sh

.PHONY: dev-pubkey
dev-pubkey: ## Print the public development module-signing key (local smoke builds only)
	@cargo run --quiet -p spark-core --features module-signer,bip324 --bin sign-module -- pubkey --dev

##@ iOS

.PHONY: ios-testflight
ios-testflight: ## Build, sign and upload an iOS TestFlight build
	bash packaging/ios/build-testflight.sh

##@ Housekeeping

.PHONY: clean
clean: ## Remove build outputs (cargo target dirs are left alone; use `cargo clean` for those)
	rm -rf dist
	rm -rf gui-tauri/build gui-tauri/.svelte-kit
