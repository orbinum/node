.PHONY: setup
# Setup development environment
setup:
	bash ./scripts/setup-dev.sh

.PHONY: clean
# Cleanup compilation outputs
clean:
	cargo clean

.PHONY: fmt-check fmt
# Check the code format
fmt-check:
	taplo fmt --check
	cargo fmt --all -- --check
# Format the code
fmt:
	taplo fmt
	cargo fmt --all

.PHONY: clippy clippy-release
# Run rust clippy with debug profile
clippy:
	SKIP_WASM_BUILD=1 cargo clippy --all --all-targets --features=runtime-benchmarks,try-runtime -- -D warnings
# Run rust clippy with release profile (use CI_DUMMY_VK=1 in CI to skip artifacts)
clippy-release:
	@if [ "$$CI_DUMMY_VK" = "1" ]; then \
		SKIP_WASM_BUILD=1 cargo clippy --release --all --all-targets --features=runtime-benchmarks,try-runtime,ci-dummy-vk -- -D warnings; \
	else \
		SKIP_WASM_BUILD=1 cargo clippy --release --all --all-targets --features=runtime-benchmarks,try-runtime -- -D warnings; \
	fi

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
	cargo test --lib --all --features=runtime-benchmarks
# Run all unit tests with release profile
test-release:
	cargo test --release --lib --all
	cargo test --release --lib --all --features=runtime-benchmarks

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
	cargo build --release --features=runtime-benchmarks
	./target/release/orbinum-node benchmark pallet --chain=dev --pallet=$(PALLET) --extrinsic='*' --steps=50 --repeat=20 --output=./frame/$(PALLET)/src/weights.rs --template=./scripts/frame-weight-template.hbs

.PHONY: audit
# Run security audit (ignoring known Polkadot SDK transitive dependencies via deny.toml)
audit:
	@cargo deny check advisories

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
