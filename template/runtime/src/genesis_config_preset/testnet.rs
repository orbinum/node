use crate::genesis_config_preset::{build_genesis, ethereum_to_account_id, DEV_BALANCE, TOTAL_SUPPLY};
use crate::AccountId;
use hex_literal::hex;
use sp_std::vec;

pub fn testnet() -> serde_json::Value {
	build_genesis(
		AccountId::from(hex!(
			"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
		)),
		vec![
			(
				ethereum_to_account_id(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
				TOTAL_SUPPLY,
			),
			(
				AccountId::from(hex!(
					"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
				)),
				DEV_BALANCE,
			),
			(
				AccountId::from(hex!(
					"8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
				)),
				DEV_BALANCE,
			),
			(
				ethereum_to_account_id(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")),
				DEV_BALANCE,
			),
		],
		vec![],
		2700,
		false,
	)
}
