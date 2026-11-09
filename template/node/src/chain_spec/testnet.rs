//! Orbinum public testnet (`--chain testnet`), EVM chain ID 2700.
//!
//! Genesis (sudo, treasury, faucet, validators, balances) is the runtime preset
//! `orbinum_testnet_runtime_preset`. Each genesis validator inserts its session keys
//! into its node's keystore (`orbinum-node key insert` or `author_insertKey`).

use sc_chain_spec::ChainType;

use super::{base_builder, ChainSpec};

/// Orbinum public testnet configuration.
pub fn orbinum_testnet_config() -> Result<ChainSpec, String> {
	Ok(
		base_builder("Orbinum Testnet", "orbinum_testnet", ChainType::Live)?
			.with_genesis_config_preset_name("orbinum_testnet_runtime_preset")
			.build(),
	)
}
