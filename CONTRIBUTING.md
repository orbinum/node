# Contributing to Orbinum Network Node

Thank you for your interest in contributing to Orbinum Network Node! This document guides you through the contribution process.

## Contribution Status

**External contributions are NOT currently open.**

Orbinum Network Node is in early development phase and the core team is working on establishing the base architecture and completing the initial security audit.

**Estimated opening date:** Q2 2026

**In the meantime, you can:**
- Star the project to follow updates
- Report critical security vulnerabilities to: security@orbinum.net
- Participate in [GitHub Discussions](https://github.com/orbinum/node/discussions)
- Review documentation and suggest minor improvements

We appreciate your interest. We will notify you when we open contributions.

---

## Getting Started

### Requirements
- **Rust 1.75+** (specified in `rust-toolchain.toml`)
- **Git**
- **Node.js 16+** (for circuit compilation and tests)
- Basic knowledge of Rust, Substrate, and blockchain development

### Setting up your Environment

1. **Fork the repository**
   ```bash
   git clone https://github.com/your-username/orbinum-node.git
   cd orbinum-node
   ```

2. **Install dependencies**
   ```bash
   cargo build --release
   ```

3. **Setup development environment**
   ```bash
   ./scripts/setup-dev.sh
   ```

4. **Run tests**
   ```bash
   cargo test --workspace
   ```

5. **Verify format and lints**
   ```bash
   make check
   ```

## Contribution Workflow

### 1. Identify an area to contribute

**Priority areas:**
- **Core Runtime**: Frame pallets (shielded-pool, zk-verifier, etc.)
- **Client**: Node client, RPC, and consensus implementations
- **ZK Circuits**: Zero-knowledge circuit implementations and optimizations
- **Precompiles**: EVM precompile implementations
- **Bugs**: Reported in Issues
- **Features**: Listed in Issues with `enhancement` label
- **Documentation**: Improve README, docs, architecture documentation
- **Tests**: Increase coverage across runtime, client, and circuits
- **Performance**: Optimize cryptographic operations and runtime execution

### 2. Create an Issue (if it doesn't exist)

If you find a bug or have a feature idea:
1. Check that a similar Issue doesn't already exist
2. Create a new Issue with a clear description
3. Provide context (version, OS, steps to reproduce)

### 3. Create a Branch

```bash
git checkout -b feature/your-feature
# or for bugs:
git checkout -b fix/bug-name
```

Naming convention:
- `feature/`: new functionality
- `fix/`: bug fixes
- `docs/`: documentation changes
- `refactor/`: code improvements

### 4. Make Changes

**Code Guidelines:**

- **Format**: Use `cargo fmt` automatically
  ```bash
  cargo fmt
  ```

- **Lints**: Resolve Clippy warnings
  ```bash
  make clippy
  # or
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  ```

- **Documentation**: Document public functions
  ```rust
  /// Clear description of what this does
  /// 
  /// # Arguments
  /// * `param` - Parameter description
  ///
  /// # Returns
  /// Return value description
  pub fn my_function(param: &str) -> Result<String> {
      // ...
  }
  ```

- **Tests**: Add tests for new functionality
  ```bash
  cargo test --workspace
  # For specific package:
  cargo test -p pallet-shielded-pool
  ```

### 5. Commit and Push

```bash
git add .
git commit -m "feat: clear description of changes"
git push origin feature/your-feature
```

**Commit message conventions:**
- `feat:` new functionality
- `fix:` bug fix
- `docs:` documentation changes
- `refactor:` code changes without new functionality
- `test:` add/update tests
- `chore:` dependency updates, etc.

### 6. Create a Pull Request

1. Go to GitHub and create a PR
2. Complete the description with:
   - What problem it solves
   - How it was tested
   - Any breaking changes
   - Screenshots/examples if applicable

3. Ensure all checks pass:
   - Tests pass
   - Correct formatting
   - Clippy without warnings
   - Clean commits

## Project Structure

```
├── circuits/          # Zero-knowledge circuits (Circom)
├── client/           # Node client implementation
│   ├── api/         # Client API
│   ├── cli/         # Command-line interface
│   ├── consensus/   # Consensus mechanisms
│   ├── db/          # Database layer
│   ├── rpc/         # RPC implementations
│   └── storage/     # Storage layer
├── frame/           # Substrate pallets (runtime modules)
│   ├── shielded-pool/  # Shielded transactions pallet
│   ├── zk-verifier/    # Zero-knowledge proof verifier
│   ├── evm/            # EVM integration
│   └── ...
├── precompiles/     # EVM precompile implementations
├── primitives/      # Core types and traits
│   ├── zk-circuits/     # Circuit primitives
│   ├── zk-primitives/   # ZK cryptographic primitives
│   ├── ethereum/        # Ethereum compatibility
│   └── ...
├── template/        # Node runtime template
└── ts-tests/        # TypeScript integration tests
```

When contributing, place code in the appropriate module based on its functionality.

## Checklist before making a PR

- [ ] My code follows the project style (`make fmt` or `cargo fmt`)
- [ ] I've verified there are no new Clippy warnings (`make clippy`)
- [ ] I've added/updated tests for my changes
- [ ] I've updated documentation if necessary (inline docs, README, architecture docs)
- [ ] I've made commits with descriptive messages
- [ ] Local tests pass (`cargo test --workspace`)
- [ ] If modifying runtime: I've run benchmarks if needed (`make benchmark`)
- [ ] If modifying circuits: I've tested circuit compilation and proof generation
- [ ] I've checked for breaking changes and noted them in the PR

## Code of Conduct

We expect all participants to:
- Be respectful and inclusive
- Accept constructive criticism
- Focus on what's best for the community
- Report inappropriate behavior

## Questions or Help

- Create a Discussion on GitHub
- Email: dev@orbinum.net
- Read README.md for more project information

---

Thank you for contributing to Orbinum Network Node!
