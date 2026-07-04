.PHONY: setup
# Setup development environment
setup:
	bash ./scripts/setup-dev.sh

.PHONY: clean
# Cleanup compilation outputs
clean:
	cargo clean

.PHONY: fmt-check fmt format
# Check the code format
fmt-check:
	taplo fmt --check
	cargo fmt --all -- --check
# Format the code
fmt:
	taplo fmt
	cargo fmt --all
# Alias for fmt
format: fmt

.PHONY: clippy clippy-release
# Run rust clippy with debug profile
clippy:
	SKIP_WASM_BUILD=1 cargo clippy --all --all-targets --features=runtime-benchmarks,skip-proof-verification,try-runtime -- -D warnings
# Run rust clippy with release profile
clippy-release:
	SKIP_WASM_BUILD=1 cargo clippy --release --all --all-targets --features=runtime-benchmarks,skip-proof-verification,try-runtime -- -D warnings

.PHONY: check check-release
# Check code with debug profile
check:
	cargo check
# Check code with release profile
check-release:
	cargo check --release

.PHONY: build build-release
# Build all binaries with debug profile
build:
	WASM_BUILD_TYPE=debug cargo build
# Build all binaries with release profile
build-release:
	WASM_BUILD_TYPE=release cargo build --release

.PHONY: test test-release
# Run all unit tests with debug profile
test:
	cargo test --lib --all
	cargo test --lib --all --features=runtime-benchmarks,skip-proof-verification
# Run all unit tests with release profile
test-release:
	cargo test --release --lib --all
	cargo test --release --lib --all --features=runtime-benchmarks,skip-proof-verification

.PHONY: integration-test integration-test-lint
# Check code format and lint of integration tests
integration-test-lint:
	cd ts-tests && npm install && npm run fmt-check
# Run all integration tests
integration-test: build-release integration-test-lint
	cd ts-tests && npm run build && npm run test && npm run test-sql

.PHONY: benchmark benchmark-pallet
# Run all runtime benchmarks
benchmark:
	./scripts/benchmark.sh
# Run benchmark for specific pallet (usage: make benchmark-pallet PALLET=pallet-shielded-pool)
benchmark-pallet:
	@if [ -z "$(PALLET)" ]; then \
		echo "Error: PALLET variable is required. Usage: make benchmark-pallet PALLET=pallet-name"; \
		exit 1; \
	fi
	cargo build --release --features=runtime-benchmarks,skip-proof-verification
	./target/release/orbinum-node benchmark pallet --chain=dev --pallet=$(PALLET) --extrinsic='*' --steps=50 --repeat=20 --output=./frame/$(PALLET)/src/weights.rs --template=./scripts/frame-weight-template.hbs

.PHONY: run-dev
run-dev:
	./target/release/orbinum-node --dev --tmp \
		--max-runtime-instances=32 \
		--runtime-cache-size=8

.PHONY: run-dev-persistent
run-dev-persistent:
	./target/release/orbinum-node \
		--dev \
		--base-path ./data/dev \
		--max-runtime-instances=32 \
		--runtime-cache-size=8

.PHONY: audit
# Run security audit (ignoring known Polkadot SDK transitive dependencies via deny.toml)
audit:
	@cargo deny check advisories

.PHONY: deploy-runtime
# Deploy runtime upgrade on-chain (usage: make deploy-runtime WASM=<path> RPC=<ws_url> SEED=<seed>)
deploy-runtime:
	@if [ -z "$(WASM)" ]; then \
		WASM="target/release/wbuild/orbinum-runtime/orbinum_runtime.compact.compressed.wasm"; \
	else \
		WASM="$(WASM)"; \
	fi; \
	bash ./scripts/deploy-runtime.sh "$$WASM" "$(RPC)" "$(SEED)"

.PHONY: rolling-update
# Rolling update node binary on remote servers (usage: make rolling-update VALIDATORS=<ip1,ip2> RPC_NODE=<ip>)
rolling-update:
	bash ./scripts/rolling-update.sh \
		--binary target/release/orbinum-node \
		--validators "$(VALIDATORS)" \
		--rpc-node "$(RPC_NODE)"

.PHONY: healthcheck
# Check network health (usage: make healthcheck RPC=<url>)
healthcheck:
	bash ./scripts/healthcheck.sh "$(RPC)"

.PHONY: help
# Show help
help:
	@echo ''
	@echo 'Usage:'
	@echo ' make [target]'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
	helpMessage = match(lastLine, /^# (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")); \
			helpMessage = substr(lastLine, RSTART + 2, RLENGTH); \
			printf "\033[36m%-30s\033[0m %s\n", helpCommand,helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
