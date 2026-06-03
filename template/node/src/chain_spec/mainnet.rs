//! Orbinum Mainnet chain configuration (stub — not yet launched).
//!
//! Activated with `--chain mainnet` or `--chain orbinum_mainnet`.
//!
//! EVM chain ID: **270** (registered in ChainList).
//!
//! This file is a placeholder. Before triggering mainnet genesis, configure:
//! - Sudo key (Sr25519)
//! - Validator set (Aura + GRANDPA keys)
//! - Genesis balances (treasury, team, investors)

use sc_chain_spec::ChainType;

use super::{properties, ChainSpec, EVM_CHAIN_ID};

/// Orbinum Mainnet configuration (placeholder — not yet launched).
///
/// Currently only registers the EVM chain ID (270). All other genesis
/// parameters must be filled in before mainnet launch.
pub fn orbinum_mainnet_config() -> ChainSpec {
	ChainSpec::builder(
		orbinum_runtime::WASM_BINARY.expect("WASM not available"),
		Default::default(),
	)
	.with_name("Orbinum Mainnet")
	.with_id("orbinum_mainnet")
	.with_chain_type(ChainType::Live)
	.with_properties(properties())
	.with_genesis_config_patch(mainnet_genesis())
	.build()
}

fn mainnet_genesis() -> serde_json::Value {
	// TODO: Add sudo key, validators and genesis balances before mainnet launch.
	serde_json::json!({
		"evmChainId": { "chainId": EVM_CHAIN_ID }
	})
}
