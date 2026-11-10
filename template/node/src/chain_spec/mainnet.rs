//! Orbinum Mainnet (`--chain mainnet`), EVM chain ID 270. Not launched.
//!
//! Genesis is the runtime preset `orbinum_mainnet_runtime_preset`, which the runtime
//! only builds once `MAINNET_CONFIGURED` is set (`template/runtime/src/genesis`).

use sc_chain_spec::{ChainType, GenesisConfigBuilderRuntimeCaller};

use super::{base_builder, wasm_binary, ChainSpec};

const PRESET: &str = "orbinum_mainnet_runtime_preset";

/// Orbinum Mainnet configuration. Refused while the runtime does not build its preset.
pub fn orbinum_mainnet_config() -> Result<ChainSpec, String> {
	let presets = GenesisConfigBuilderRuntimeCaller::<()>::new(wasm_binary()?).preset_names()?;
	if !presets.iter().any(|preset| preset == PRESET) {
		return Err(format!(
			"mainnet genesis not configured: this runtime does not build the `{PRESET}` \
			 preset (`MAINNET_CONFIGURED` in template/runtime/src/genesis)"
		));
	}
	Ok(
		base_builder("Orbinum Mainnet", "orbinum_mainnet", ChainType::Live)?
			.with_genesis_config_preset_name(PRESET)
			.build(),
	)
}
