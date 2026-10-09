# Threat model

## What this project does and where untrusted input enters

Orbinum is a Substrate chain (Aura + GRANDPA) built on a Frontier fork, with full EVM
compatibility and a ZK shielded pool. Native value moves between public accounts and
private notes, proven with Groth16 proofs verified on-chain.

Treat all of the following as attacker-controlled:

- **Extrinsics** from any signed account, and **unsigned extrinsics** accepted through
  `validate_unsigned` (shielded-pool spends carry no signer; the proof is the authority).
- **EVM transactions** and calldata, including calls into custom precompiles.
- **ZK proofs and public inputs** submitted to `pallet-zk-verifier` / `pallet-shielded-pool`.
- **JSON-RPC** on public nodes: `eth_*`, `orbinum_*` (including `orbinum_relayShieldedCall`,
  which makes the node sign and submit an EVM transaction with its own key).
- **ISMP / Hyperbridge messages** arriving through `pallet-ismp-messaging`.
- **P2P network** input (blocks, gossip) from untrusted peers.

Trusted: Root / sudo origin, genesis configuration, validator session keys.

## Components that matter most / least

Highest priority:

- `frame/shielded-pool` — note commitments, nullifiers, Merkle tree, shield / unshield /
  private transfer, unsigned validation. Double spends, nullifier reuse, value inflation,
  and fee/amount mismatches between proof and extrinsic are the worst outcomes.
- `frame/zk-verifier`, `primitives/zk-verifier`, `primitives/zk-core` — Groth16 verification,
  verifying-key storage and encoding, public-input binding.
- `frame/relayer` and `client/rpc/src/relay/` — gasless relay: fee accounting, relayer
  commitment, and anything that lets a caller drain or grief the node's relay key.
- Custom precompiles in `template/runtime/src/precompiles.rs`: shielded pool (`0x801`) and
  balances (`0x802`), and the `precompiles/` utility crate.
- `frame/ismp-messaging` — cross-chain message authentication (proxy / state-machine checks).
- `template/runtime` — runtime wiring, origins, `evm_account.rs`, `orbinum_signature.rs`.
- `frame/validator-set`.

Lower priority (in scope, but mostly unchanged from upstream Frontier):

- `frame/evm`, `frame/ethereum`, standard precompiles, `frame/base-fee`, `frame/dynamic-fee`,
  `client/*` RPC and mapping-sync.

Out of scope:

- `ts-tests/`, `scripts/`, `docs/`, `docker/`, benchmark fixtures, `mock.rs` / test-only code.
- Vulnerabilities that exist identically in upstream Frontier or polkadot-sdk; report those
  upstream unless Orbinum's integration makes them reachable or worse.

## How to exercise it

- Pallet unit tests: `cargo test --release -p pallet-shielded-pool` (likewise
  `pallet-zk-verifier`, `pallet-relayer`, `pallet-ismp-messaging`). Each pallet has a
  `mock.rs` runtime and `tests/` or `tests.rs`.
- Runtime-level tests: `template/runtime/src/runtime_tests.rs`.
- Fuzz harness: `template/fuzz/`.
- Local dev chain: `target/release/orbinum-node --dev --tmp`.

## How we rate severity

- **Critical**: minting or stealing funds; spending a note twice; accepting an invalid or
  forged ZK proof; spending another user's note; unauthorized privileged origin; a single
  transaction or message that halts block production or finality.
- **High**: runtime panic reachable from an extrinsic or EVM call; underweighted call or
  free unsigned path enabling cheap block-filling DoS; deanonymizing shielded users from
  on-chain data; draining the relayer key's balance; forged ISMP message accepted.
- **Medium**: RPC crash or resource exhaustion on a public node; relay griefing without
  fund loss; state bloat paid below cost.
- **Low**: issues needing a malicious validator or Root, info leaks without fund or privacy
  impact.

A panic only reachable from a privileged origin, or only in tests/benchmarks, is not a
vulnerability.

## Reports and patches

Include a failing test against the relevant pallet `mock.rs` runtime where possible. Patches
should be minimal, keep storage layout compatible, and note any weight or migration impact.
