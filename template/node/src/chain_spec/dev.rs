// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Development chain (`--dev` or `--chain dev`): Alice as the single validator.

use sc_chain_spec::ChainType;

use super::{base_builder, validators_patch, ChainSpec};

/// Single-node development configuration, on the `development` preset (the dev accounts
/// funded, EVM chain ID 42). With `manual_seal` the runtime accepts blocks without an
/// Aura author: only with `--sealing`.
pub fn development_config(manual_seal: bool) -> Result<ChainSpec, String> {
	let mut patch = validators_patch(&["Alice"]);
	patch["manualSeal"] = serde_json::json!({ "enable": manual_seal });
	Ok(base_builder("Development", "dev", ChainType::Development)?
		.with_genesis_config_preset_name("development")
		.with_genesis_config_patch(patch)
		.build())
}
