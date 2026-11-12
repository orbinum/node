// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Local testnet (`--chain local`): three validators on one machine, run by
//! `scripts/local-net/start.sh`.

use sc_chain_spec::ChainType;

use super::{base_builder, validators_patch, ChainSpec};

/// Seeds of the local validators. Three is the smallest set GRANDPA tolerates a
/// fault in, and leaves one validator to remove or slash in staking tests.
pub(crate) const LOCAL_VALIDATORS: [&str; 3] = ["Alice", "Bob", "Charlie"];

/// Three-validator local testnet on the `development` preset, the same balances and EVM
/// chain ID (42) as `--dev`; Aura and GRANDPA, no manual seal.
pub fn local_testnet_config() -> Result<ChainSpec, String> {
	Ok(
		base_builder("Local Testnet", "local_testnet", ChainType::Local)?
			.with_genesis_config_preset_name("development")
			.with_genesis_config_patch(validators_patch(&LOCAL_VALIDATORS))
			.build(),
	)
}
