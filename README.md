<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/orbinum-horizontal-white.svg">
    <img src=".github/assets/orbinum-horizontal-black.svg" alt="Orbinum" width="360">
  </picture>
</p>

<p align="center">
  A privacy-focused blockchain built on Substrate: confidential transfers with zero-knowledge proofs, EVM compatibility and nominated proof of stake.
</p>

<p align="center">
  <a href="https://orbinum.network">Website</a> ·
  <a href="https://docs.orbinum.network">Docs</a> ·
  <a href="https://app.orbinum.network">Hub</a> ·
  <a href="https://explorer.testnet.orbinum.network">Explorer</a> ·
  <a href="https://faucet.orbinum.network">Faucet</a> ·
  <a href="https://telemetry.orbinum.network">Telemetry</a>
</p>

## Network status

*As of November 2026.*

| | |
|---|---|
| **Testnet** | Live, public. EVM chain ID `2700` |
| **Runtime** | spec 21 (node `v0.7.0`), live since 2026-11-08: nominated proof of stake |
| **Consensus** | Aura block production, GRANDPA finality; validators elected each era by stake |
| **Next upgrade** | spec 22 (node `v0.8.0`, in development): pool role changes signable from EVM and Solana wallets; only validators are slashed, so nominators and pool members unbond in 2 eras |
| **Mainnet** | Not launched |

The full runtime history is in [`template/runtime/RUNTIME_VERSIONS.md`](template/runtime/RUNTIME_VERSIONS.md).

### Testnet endpoints

| Service | URL |
|---|---|
| RPC (Substrate and Ethereum JSON-RPC) | `https://rpc-1.testnet.orbinum.io` · `wss://rpc-1.testnet.orbinum.io` |
| Hub (wallet, privacy and staking app) | https://app.orbinum.network |
| Explorer | https://explorer.testnet.orbinum.network |
| Faucet | https://faucet.orbinum.network |
| Telemetry | https://telemetry.orbinum.network |

## Features

### Privacy
- **Shielded pool**: shield, transfer privately and unshield. Amounts, sender and recipient stay hidden.
- **Zero-knowledge proofs**: Groth16 on BN254, verified on-chain; Poseidon commitments in Merkle trees.
- **Encrypted memos and viewing keys**: the recipient finds its notes, and an owner can disclose selected ones.

### Nominated proof of stake
- **Staking**: `pallet-staking-async` with an on-chain, paged seq-Phragmén election; no off-chain miners.
- **Validators**: elected each era (one day) from the bonded candidates admitted by `pallet-validator-set`; GRANDPA equivocations are slashed after a 26-era window in which governance may cancel them.
- **Nomination pools**: stake from 1 ORB through a pool that nominates for its members.
- **Rewards**: a fixed emission schedule, paid automatically every era (`pallet-auto-payout`); transaction fees fund the era's rewards.

### Accounts and EVM
- **One account, three wallets**: Substrate (sr25519/ed25519), EVM addresses (mapped to Orbinum accounts) and Solana addresses use the same account space.
- **Readable signing**: MetaMask and Solana wallets sign native transactions as human-readable text that the runtime renders and checks, so a site cannot get a different transaction signed.
- **Frontier EVM**: Ethereum JSON-RPC and Solidity contracts, with precompiles that send ORB to any Orbinum account and shield it into the private pool.

### Interoperability
- **Hyperbridge (ISMP)**: cross-chain messaging verified through Orbinum's GRANDPA finality proofs, without becoming a parachain.

## Repository layout

| Path | Contents |
|---|---|
| `template/node` | The node binary (`orbinum-node`) |
| `template/runtime` | The runtime: pallet configuration, staking, economy, text signatures, migrations |
| `frame/` | Orbinum pallets: `shielded-pool`, `zk-verifier`, `validator-set`, `paged-election`, `auto-payout`, `ismp-messaging`, plus the Frontier EVM pallets |
| `primitives/` | Core libraries: `zk-core`, `zk-verifier`, accounts, EVM and RPC primitives |
| `client/` | RPC and the Ethereum client stack (Frontier) |

## Building

Requires the [Rust toolchain](https://rustup.rs) (version pinned in `rust-toolchain.toml`) and `protoc`, the protobuf compiler (`brew install protobuf` / `apt install protobuf-compiler`), required by the networking stack since polkadot-sdk 2606.

```sh
cargo build --release
```

## Running a node

```sh
# A local development chain
./target/release/orbinum-node --dev

# The public testnet
./target/release/orbinum-node --chain testnet
```

Release images are published to `ghcr.io/orbinum/node`. To run an RPC node or a validator on testnet, see the [docs](https://docs.orbinum.network).

## License

Copyright © 2026 Orbinum Technologies. Portions © Parity Technologies (UK) Ltd. and other Frontier contributors.

Each crate states its license in its `Cargo.toml`, and each file in its `SPDX-License-Identifier`:

| Component | License |
|---|---|
| Orbinum pallets (`shielded-pool`, `zk-verifier`, `validator-set`, `paged-election`, `auto-payout`, `ismp-messaging`) | GPL-3.0-or-later |
| Runtime, `zk-core`, `zk-verifier` primitives, precompile utilities | Apache-2.0 OR GPL-3.0-or-later |
| Orbinum EVM precompiles (`balances`, `shielded-pool`), `zk-verifier` RPC and runtime API | Apache-2.0 |
| Node (`template/node`) and client crates (`client/`) | GPL-3.0-or-later WITH Classpath-exception-2.0 |
| Frontier EVM pallets and Ethereum primitives (`frame/`, `primitives/`) | Apache-2.0 |

The license texts are in [LICENSE-APACHE2](LICENSE-APACHE2) and [LICENSE-GPL3](LICENSE-GPL3). Third-party notices are in [NOTICE](NOTICE).

"Orbinum" and the Orbinum logo are trademarks of Orbinum Technologies; the licenses grant no rights to them.

## Attribution

Orbinum is built upon and extends [Frontier](https://github.com/polkadot-evm/frontier), the Ethereum compatibility layer for Substrate. The EVM integration, Ethereum RPC, and related client infrastructure are derived from Frontier's work by Parity Technologies and contributors.

We are grateful to the Frontier and Substrate communities for their foundational work.
