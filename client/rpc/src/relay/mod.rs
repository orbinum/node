// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Node-native EVM relay RPC.
//!
//! When the node is started with `--evm-relayer-key <hex>`, it exposes:
//!
//! - `orbinum_relayShieldedCall(calldata: "0x...")` → `txHash`
//! - `orbinum_relayerStatus()` → `{ address, minFee, balanceWei, enabled, isRegistered }`
//!
//! The relay pays gas on a user's behalf, so it will only call the ShieldedPool
//! precompile (`0x…0801`), only with a whitelisted selector, and only when the
//! fee in ABI slot 6 covers what the transaction will cost it. The whitelist and
//! fee floor come from `pallet-relayer` via Runtime API, read on every call so
//! governance changes apply without a node restart.
//!
//! # Module layout
//!
//! The split is by what each part needs in order to run:
//!
//! | Sub-module     | Responsibility                                            |
//! |----------------|-----------------------------------------------------------|
//! | [`config`]     | Constants: the target, admission limits, tx parameters, and Runtime API fallbacks |
//! | [`types`]      | `OrbinumRelayApi` RPC trait + `RelayerStatus` response     |
//! | [`operations`] | Per-operation selector, length, and fee extraction         |
//! | [`validation`] | Pure calldata checks — bytes in, verdict out; no chain state |
//! | [`rpc`]        | `OrbinumRelay`: dry run, nonce, signing, pool submission   |
//!
//! Keeping [`validation`] free of chain state is what lets `tests/adversarial.rs`
//! throw hostile calldata at it without a node.

pub mod config;
pub mod operations;
pub mod rpc;
pub mod types;
pub mod validation;

#[cfg(test)]
mod tests;

pub use rpc::OrbinumRelay;
pub use types::{OrbinumRelayApiServer, RelayerStatus};
