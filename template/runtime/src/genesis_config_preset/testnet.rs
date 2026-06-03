use crate::genesis_config_preset::{
	build_genesis, ethereum_to_account_id, DEV_BALANCE, FAUCET_BALANCE, TOTAL_SUPPLY,
};
use crate::AccountId;
use hex_literal::hex;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{ed25519, sr25519};
use sp_std::vec;

fn aura_id(bytes: [u8; 32]) -> AuraId {
	sr25519::Public::from_raw(bytes).into()
}

fn grandpa_id(bytes: [u8; 32]) -> GrandpaId {
	ed25519::Public::from_raw(bytes).into()
}

pub fn testnet() -> serde_json::Value {
	let sudo_key = AccountId::from(hex!(
		"76eb8fe6dbed156f72f4f6c62c2430375fb51a46f09c2d86ffe1e2153e3d5524"
	));
	let treasury = ethereum_to_account_id(hex!("0bFEF65000b390F5E00e551451e5ce00a9c9930c"));
	let faucet = ethereum_to_account_id(hex!("0d4313eAa69c90c45DB96f2828Ff0D5e3BFE6BD5"));

	build_genesis(
		sudo_key.clone(),
		vec![
			(treasury, TOTAL_SUPPLY - FAUCET_BALANCE),
			(faucet, FAUCET_BALANCE),
			(sudo_key, DEV_BALANCE),
			// Validators need enough balance for the 1 000 ORB registration bond + fees.
			// These AccountIds are the same bytes as each validator's Aura (sr25519) public key.
			(
				AccountId::from(hex!(
					"b873599c026d0066aebe213d7984e7f84a6e3425d39f5fafcf681528a555ce47"
				)),
				DEV_BALANCE,
			), // Validator 1
			(
				AccountId::from(hex!(
					"641a682160d6298090cf1b1998dc3dad0c3df962fd29728fa1f7d3253c260362"
				)),
				DEV_BALANCE,
			), // Validator 2
			(
				AccountId::from(hex!(
					"0e24a46982207bc39fb1aa11724e127784b0b155330680583170a50fcd2bd052"
				)),
				DEV_BALANCE,
			), // Validator 3
		],
		vec![
			// Validator 1
			(
				aura_id(hex!(
					"b873599c026d0066aebe213d7984e7f84a6e3425d39f5fafcf681528a555ce47"
				)),
				grandpa_id(hex!(
					"c8f990b25f78f7aa7a25c00a62f9d62ca5f45ed7fc83a419b75e5131130f2346"
				)),
			),
			// Validator 2
			(
				aura_id(hex!(
					"641a682160d6298090cf1b1998dc3dad0c3df962fd29728fa1f7d3253c260362"
				)),
				grandpa_id(hex!(
					"edd77017b97db02805b19060ca28aca163e52fa0d299fd2864447247f6c3229d"
				)),
			),
			// Validator 3
			(
				aura_id(hex!(
					"0e24a46982207bc39fb1aa11724e127784b0b155330680583170a50fcd2bd052"
				)),
				grandpa_id(hex!(
					"75a964ae2ac4b5df490c57949ef030f5857b4b84b611ff48ea880d1637eca18c"
				)),
			),
		],
		2700,
		false,
		1_000_000_000, // 1 gwei — EIP-1559 adjusts upward with traffic
	)
}
