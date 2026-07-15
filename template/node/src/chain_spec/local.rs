//! Local testnet chain configuration.
//!
//! Activated with `--chain local` or `--chain ""`.
//!
//! Simulates a real two-node network on a single machine using Alice and Bob's
//! well-known keys. Useful for testing peer-to-peer behaviour, GRANDPA finality,
//! and multi-validator consensus without external infrastructure.

use sc_chain_spec::ChainType;

use super::{aura_to_account, authority_keys_from_seed, properties, session_keys, ChainSpec};

/// Two-validator local testnet configuration.
///
/// - **2 validators:** Alice + Bob (well-known dev keys, deterministic)
/// - **No manual seal:** Aura produces blocks on a fixed slot schedule;
///   GRANDPA finalises once 2/3+1 validators agree (both nodes required)
/// - **Genesis preset:** `"development"` — shared with `--dev`, which supplies
///   the same balances and EVM chain ID (42). The validator set is the only
///   difference and is patched in below.
pub fn local_testnet_config() -> ChainSpec {
	let (alice_aura, alice_grandpa) = authority_keys_from_seed("Alice");
	let (bob_aura, bob_grandpa) = authority_keys_from_seed("Bob");
	let alice_account = aura_to_account(&alice_aura);
	let bob_account = aura_to_account(&bob_aura);

	ChainSpec::builder(
		orbinum_runtime::WASM_BINARY.expect("WASM not available"),
		Default::default(),
	)
	.with_name("Local Testnet")
	.with_id("local_testnet")
	.with_chain_type(ChainType::Local)
	.with_properties(properties())
	.with_genesis_config_preset_name("development")
	.with_genesis_config_patch(serde_json::json!({
		// Aura and GRANDPA are populated by pallet-session — leave empty.
		"aura": { "authorities": [] },
		"grandpa": { "authorities": [] },
		// pallet-session: Alice and Bob's session keys.
		"session": {
			"keys": [
				[alice_account, alice_account, session_keys(alice_aura, alice_grandpa)],
				[bob_account, bob_account, session_keys(bob_aura, bob_grandpa)]
			]
		},
		// pallet-validator-set: Alice and Bob are the approved validators.
		"validatorSet": { "initialValidators": [alice_account, bob_account] }
	}))
	.build()
}
