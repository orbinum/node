//! Development chain configuration.
//!
//! Activated with `--dev` or `--chain dev`.
//!
//! Runs a single validator using Alice's well-known Sr25519/Ed25519 keys.
//! Supports optional manual block sealing (`--manual-seal`) for step-by-step
//! testing without waiting for Aura slot intervals.

use sc_chain_spec::ChainType;

use super::{aura_to_account, authority_keys_from_seed, properties, session_keys, ChainSpec};

/// Single-node development configuration.
///
/// - **1 validator:** Alice (well-known dev keys, deterministic)
/// - **Genesis preset:** `"development"` — includes all Substrate dev accounts
///   (Alice, Bob, Charlie, Dave, Eve, Ferdie) with pre-funded balances
/// - **Manual seal:** when `enable_manual_seal = true`, blocks are only produced
///   on demand via RPC (`engine_createBlock`), ideal for unit/integration tests
pub fn development_config(enable_manual_seal: bool) -> ChainSpec {
	let (alice_aura, alice_grandpa) = authority_keys_from_seed("Alice");
	let alice_account = aura_to_account(&alice_aura);

	ChainSpec::builder(
		orbinum_runtime::WASM_BINARY.expect("WASM not available"),
		Default::default(),
	)
	.with_name("Development")
	.with_id("dev")
	.with_chain_type(ChainType::Development)
	.with_properties(properties())
	.with_genesis_config_preset_name("development")
	.with_genesis_config_patch(serde_json::json!({
		"manualSeal": { "enable": enable_manual_seal },
		// Aura and GRANDPA are populated by pallet-session — leave empty.
		"aura": { "authorities": [] },
		"grandpa": { "authorities": [] },
		// pallet-session: Alice's session keys.
		"session": {
			"keys": [[alice_account, alice_account, session_keys(alice_aura, alice_grandpa)]]
		},
		// pallet-validator-set: Alice is the single approved validator.
		"validatorSet": { "initialValidators": [alice_account] }
	}))
	.build()
}
