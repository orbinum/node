//! Genesis presets: the development, local and testnet chains, and mainnet once it is
//! configured.
//!
//! - `builder`: the genesis every preset is built from.
//! - `development`, `testnet`, `mainnet`: each preset's accounts, keys and bonds.

mod builder;
mod development;
pub(crate) mod mainnet;
pub(crate) mod testnet;
#[cfg(test)]
mod tests;

use crate::{primitives::constants::ORB, Runtime, RuntimeGenesisConfig};
use alloc::{vec, vec::Vec};
use sp_genesis_builder::PresetId;

/// Total project supply: 1,000,000,000 ORB.
pub(crate) const TOTAL_SUPPLY: u128 = 1_000_000_000 * ORB;
/// Faucet allocation at genesis: 100,000,000 ORB.
pub(crate) const FAUCET_BALANCE: u128 = 100_000_000 * ORB;
/// Development/test account allocation: 10,000 ORB.
pub(crate) const DEV_BALANCE: u128 = 10_000 * ORB;

pub(crate) const DEV_PRESET_ID: &str = sp_genesis_builder::DEV_RUNTIME_PRESET;
pub(crate) const LOCAL_PRESET_ID: &str = "orbinum_local_testnet_runtime_preset";
pub(crate) const TESTNET_PRESET_ID: &str = "orbinum_testnet_runtime_preset";
pub(crate) const MAINNET_PRESET_ID: &str = "orbinum_mainnet_runtime_preset";
/// The development genesis for benchmarks; built only with `runtime-benchmarks`.
#[cfg(feature = "runtime-benchmarks")]
pub(crate) const BENCHMARK_PRESET_ID: &str = "benchmark";

/// Whether mainnet's genesis is configured: its sudo key, authorities and
/// endowments (`mainnet.rs`). Until then the mainnet preset is neither listed
/// nor built, so no chain starts from a zero sudo key and no validators.
pub(crate) const MAINNET_CONFIGURED: bool = false;

/// The presets this runtime builds.
pub fn preset_names() -> Vec<PresetId> {
	let mut names = vec![
		PresetId::from(DEV_PRESET_ID),
		PresetId::from(LOCAL_PRESET_ID),
		PresetId::from(TESTNET_PRESET_ID),
	];
	if MAINNET_CONFIGURED {
		names.push(PresetId::from(MAINNET_PRESET_ID));
	}
	#[cfg(feature = "runtime-benchmarks")]
	names.push(PresetId::from(BENCHMARK_PRESET_ID));
	names
}

/// The genesis patch of preset `id`, as JSON bytes.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
	let patch = match id.as_str() {
		DEV_PRESET_ID | LOCAL_PRESET_ID => development::development(),
		#[cfg(feature = "runtime-benchmarks")]
		BENCHMARK_PRESET_ID => development::benchmark(),
		TESTNET_PRESET_ID => testnet::testnet(),
		MAINNET_PRESET_ID if MAINNET_CONFIGURED => mainnet::mainnet(),
		_ => return None,
	};
	Some(
		serde_json::to_string(&patch)
			.expect("serialization to json is expected to work. qed.")
			.into_bytes(),
	)
}

/// Builds the genesis state from a full `RuntimeGenesisConfig` JSON, on empty
/// storage only. `state_call` reaches this API on a live chain's state, where
/// genesis-only code (`pallet_balances`' `devAccounts`, a loop the caller sizes)
/// would run with no bound; a built genesis keeps its block hash 0.
pub fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
	if frame_system::BlockHash::<Runtime>::contains_key(0) {
		return Err("genesis is already built".into());
	}
	frame_support::genesis_builder_helper::build_state::<RuntimeGenesisConfig>(config)
}
