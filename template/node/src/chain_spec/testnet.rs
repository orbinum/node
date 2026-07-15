//! Orbinum public testnet chain configuration.
//!
//! Activated with `--chain testnet` or `--chain orbinum_testnet`.
//!
//! EVM chain ID: **2700** (registered in ChainList).
//!
//! Genesis state (sudo, treasury, faucet, validators, balances) lives in the
//! runtime preset `orbinum_testnet_runtime_preset` — see
//! `template/runtime/src/genesis_config_preset/testnet.rs`. This file only
//! defines network metadata (name, id, chain type, properties).
//!
//! Session keys must be inserted into each running validator node after
//! deployment using `scripts/testnet-keys/insert-session-keys.sh`.

use sc_chain_spec::ChainType;

use orbinum_runtime::WASM_BINARY;

use super::{properties, ChainSpec};

/// Orbinum public testnet configuration.
///
/// - **Genesis preset:** `"orbinum_testnet_runtime_preset"`
/// - **Validators:** 3 nodes with real keys generated for testnet launch
/// - **EVM chain ID:** 2700
pub fn orbinum_testnet_config() -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Orbinum Testnet")
		.with_id("orbinum_testnet")
		.with_chain_type(ChainType::Live)
		.with_properties(properties())
		.with_genesis_config_preset_name("orbinum_testnet_runtime_preset")
		.build()
}
