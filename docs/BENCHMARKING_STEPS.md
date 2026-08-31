# Benchmarking Steps — Orbinum Node

Exact, reproducible steps to regenerate the committed `weights.rs` files on the
reference hardware. Follow these in order whenever an extrinsic's logic or storage
access changes.

> For the *why* (hardware sensitivity, which pallets are versioned, when to
> regenerate) see [BENCHMARKING_GUIDE.md](./BENCHMARKING_GUIDE.md). This document
> is the runbook.

---

## What changed vs. the older guide

The benchmark pipeline no longer needs the `groth16-proofs` sibling checkout or
the `pack-verifying-key` binary, and `verify_proof` is now self-contained:

- **Feature set:** builds use `runtime-benchmarks,skip-proof-verification,poseidon-native`.
  `skip-proof-verification` lets `verify_proof` record weight even though its
  synthetic verifying key makes the Groth16 pairing fail. It is a benchmark-only
  feature; an `integrity_test` aborts runtime construction if it is ever compiled
  into a live runtime without `runtime-benchmarks`.
- **`verify_proof` is parametrized by `n`** (public-input count, `Linear<1, 32>`).
  The benchmark builds its own arity-`n` verifying key + inputs, so it needs **no
  external fixture triple** — no VK/proof/inputs files to stage.
- **No ZK artifacts required.** The old `artifacts/*.ark` prerequisite is gone for
  benchmarking. (Registering real VKs on-chain still needs them, but that is a
  deployment step, not a benchmark step.)

---

## Reference hardware

Use **Hetzner CCX33** (8 dedicated vCPU AMD EPYC, 32 GB RAM, NVMe, Ubuntu 24.04
LTS x86-64). Never generate committed weights on a dev laptop or on shared-vCPU
(CX-series) instances — shared cores add statistical noise.

---

## 1. Prepare the VPS (Hetzner CCX33)

```bash
# System dependencies
# libclang-dev + llvm-dev are required by clang-sys (RocksDB bindgen); `clang`
# alone ships no libclang.so and the build fails with a libclang / llvm-config error.
apt update && apt install -y \
  build-essential clang libclang-dev llvm-dev libssl-dev pkg-config \
  git curl protobuf-compiler

# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# The correct toolchain is applied automatically from rust-toolchain.toml.
# Verify:
rustup show
```

## 2. Clone the node repository

Only the node repo is needed — no sibling checkouts.

```bash
cd /root
git clone https://github.com/orbinum/node.git
cd node
git checkout main   # or the branch whose weights you are regenerating
```

## 3. Run the benchmark script

`scripts/run_benchmarks.sh` builds the node with the correct feature set and runs
every own pallet plus the standard Substrate pallets. First build takes ~30-60 min.

```bash
./scripts/run_benchmarks.sh --steps 50 --repeat 20
```

This overwrites the four committed `weights.rs` files:

| Pallet | Output |
|--------|--------|
| `pallet_zk_verifier` | `frame/zk-verifier/src/weights.rs` |
| `pallet_shielded_pool` | `frame/shielded-pool/src/weights.rs` |
| `pallet_relayer` | `frame/relayer/src/weights.rs` |

Auxiliary weights for standard Substrate pallets go to a scratch dir and are not
committed.

### Regenerating a single pallet

To refresh only `pallet_zk_verifier` (e.g. after a `verify_proof` change):

```bash
cargo build --release --features runtime-benchmarks,skip-proof-verification,poseidon-native

./target/release/orbinum-node benchmark pallet \
  --chain dev \
  --pallet pallet_zk_verifier \
  --extrinsic '*' \
  --steps 50 --repeat 20 \
  --wasm-execution=compiled --heap-pages=4096 \
  --template ./scripts/frame-weight-template.hbs \
  --output frame/zk-verifier/src/weights.rs
```

> `--template` is mandatory. Without it the runner emits the default Substrate
> template, whose struct/trait names (`WeightInfo<T>`, `pallet_zk_verifier::WeightInfo`)
> do not match this crate and fail to compile. `run_benchmarks.sh` always passes it;
> a hand-run must too. `--execution=wasm` is deprecated and can be dropped.

## 4. Sanity-check the generated file

`verify_proof` and `batch_register_verification_keys` must carry the `n`
component (they are parametrized); the storage extrinsics must not.

```bash
grep -n "fn verify_proof\|fn batch_register_verification_keys" \
  frame/zk-verifier/src/weights.rs
# Expected:
#   fn verify_proof(n: u32) -> Weight
#   fn batch_register_verification_keys(n: u32) -> Weight
```

A signature without `n` where one is expected means the benchmark ran an
unparametrized case — do not commit it; it will not match the `WeightInfo` trait
and the pallet will fail to compile.

## 5. Commit the weights

```bash
git add frame/*/src/weights.rs
git commit -m "chore: update benchmark weights (reference hardware)"
git push
```

---

## Script parameters

| Flag | Default | Meaning |
|------|---------|---------|
| `--steps` | 50 | Sample points across each linear component's range |
| `--repeat` | 20 | Repetitions per point — reduces statistical noise |
| `--wasm-execution=compiled` | compiled | Wasmtime JIT — matches nodes on the network |
| `--heap-pages=4096` | 4096 | WASM heap = 16 MB |

For pre-mainnet precision:

```bash
./scripts/run_benchmarks.sh --steps 100 --repeat 50
```

---

## Release ordering

When a runtime upgrade depends on fresh weights, regenerate **before** cutting the
release tag, so the tagged WASM embeds the measured weights:

1. Merge the logic change to `main`, CI green.
2. On the VPS: regenerate weights, commit to `main`.
3. Tag `vX.Y.Z-rc.N` → the release build embeds the committed weights.

Generating weights after the tag ships a WASM with stale (conservative) weights.
