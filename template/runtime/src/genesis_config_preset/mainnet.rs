use crate::genesis_config_preset::build_genesis;
use crate::AccountId;
use sp_std::vec;

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
