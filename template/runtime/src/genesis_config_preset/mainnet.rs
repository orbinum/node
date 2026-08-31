use crate::genesis_config_preset::build_genesis;
use crate::AccountId;
use sp_std::vec;

/// PLACEHOLDER. This preset does not describe a launchable chain.
///
/// Three of its arguments are unset, and each is individually fatal:
///
/// - the sudo key is the all-zero `AccountId32`, which nobody holds the secret
///   for, so the chain would have no governance origin and no way to register
///   verification keys with `pallet-zk-verifier`;
/// - the validator and session-key lists are empty, so `pallet-session` would
///   hand Aura an empty authority set and no block would ever be produced;
/// - no genesis verification keys are supplied, so every shielded operation
///   would fail even if the first two were fixed.
///
/// Fill all three in before this is used for anything. Left in place so the
/// preset id resolves and `get_preset` stays total.
pub fn mainnet() -> serde_json::Value {
	build_genesis(
		AccountId::from([0u8; 32]),
		vec![],
		vec![],
		270,
		false,
		1_000_000_000, // 1 gwei — economical starting point; EIP-1559 adjusts upward with traffic
	)
}
