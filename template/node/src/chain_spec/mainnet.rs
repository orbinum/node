//! Orbinum Mainnet chain configuration (stub — not yet launched).
//!
//! Activated with `--chain mainnet` or `--chain orbinum_mainnet`.
//!
//! EVM chain ID: **270** (registered in ChainList).
//!
//! Genesis state lives in the runtime preset `orbinum_mainnet_runtime_preset`
//! — see `template/runtime/src/genesis_config_preset/mainnet.rs`. It is a
//! placeholder: before triggering mainnet genesis, configure there:
//! - Sudo key (Sr25519)
//! - Validator set (Aura + GRANDPA keys)
//! - Genesis balances (treasury, team, investors)

use sc_chain_spec::ChainType;

use super::{properties, ChainSpec};

/// Orbinum Mainnet configuration (placeholder — not yet launched).
///
/// - **Genesis preset:** `"orbinum_mainnet_runtime_preset"` (placeholder values)
/// - **EVM chain ID:** 270
pub fn orbinum_mainnet_config() -> ChainSpec {
	ChainSpec::builder(
		orbinum_runtime::WASM_BINARY.expect("WASM not available"),
		Default::default(),
	)
	.with_name("Orbinum Mainnet")
	.with_id("orbinum_mainnet")
	.with_chain_type(ChainType::Live)
	.with_properties(properties())
	.with_genesis_config_preset_name("orbinum_mainnet_runtime_preset")
	.build()
}
