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
	)
}
