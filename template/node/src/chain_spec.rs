use std::{collections::BTreeMap, str::FromStr};

use hex_literal::hex;
// Substrate
use sc_chain_spec::{ChainType, Properties};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
#[allow(unused_imports)]
use sp_core::ecdsa;
use sp_core::{Pair, Public, H160, U256};
use sp_runtime::traits::{IdentifyAccount, Verify};
// Frontier
use orbinum_runtime::{AccountId, Balance, SS58Prefix, Signature, WASM_BINARY};

use orbinum_zk_verifier::infrastructure::storage::verification_keys;
use pallet_zk_verifier::CircuitId;

// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Map Ethereum address (20 bytes) to AccountId32.
/// Matches TruncatedAddressMapping in the runtime: [0x00; 12] ++ H160_bytes.
fn ethereum_account_id(eth_address: [u8; 20]) -> AccountId {
	let mut bytes = [0u8; 32];
	bytes[12..].copy_from_slice(&eth_address);
	AccountId::from(bytes)
}

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{seed}"), None)
		.expect("static values are valid; qed")
		.public()
}

#[allow(dead_code)]
type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
/// For use with `AccountId32`, `dead_code` if `AccountId20`.
#[allow(dead_code)]
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

fn properties() -> Properties {
	let mut properties = Properties::new();
	properties.insert("tokenSymbol".into(), "ORB".into());
	properties.insert("tokenDecimals".into(), 12.into());
	properties.insert("ss58Format".into(), SS58Prefix::get().into());
	properties.insert("isEthereum".into(), true.into());
	properties
}

/// 1 ORB = 1_000_000_000_000 planck (12 decimals)
const PLANCK: Balance = 1_000_000_000_000;
const TOTAL_SUPPLY: Balance = 1_000_000_000 * PLANCK; // 1 billion ORB
const DEV_BALANCE: Balance = 10_000 * PLANCK;         // 10,000 ORB per dev account

const UNITS: Balance = 1_000_000_000_000_000_000;
const EVM_CHAIN_ID: u64 = 1984;

pub fn development_config(enable_manual_seal: bool) -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Development")
		.with_id("dev")
		.with_chain_type(ChainType::Development)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			// Sudo account (Alice sr25519)
			AccountId::from(hex!(
				"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
			)),
			// (account, balance) — Alith holds total supply; others get 10,000 ORB
			vec![
				// Primary account (MetaMask / Alith) — total project supply
				(ethereum_account_id(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")), TOTAL_SUPPLY),
				// Substrate sr25519 dev accounts
				(AccountId::from(hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")), DEV_BALANCE), // Alice
				(AccountId::from(hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")), DEV_BALANCE), // Bob
				(AccountId::from(hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22")), DEV_BALANCE), // Charlie
				// Ethereum dev accounts
				(ethereum_account_id(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")), DEV_BALANCE), // Baltathar
				(ethereum_account_id(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")), DEV_BALANCE), // Charleth
				(ethereum_account_id(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")), DEV_BALANCE), // Dorothy
				(ethereum_account_id(hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB")), DEV_BALANCE), // Ethan
				(ethereum_account_id(hex!("C0F0f4ab324C46e55D02D0033343B4Be8A55532d")), DEV_BALANCE), // Faith
				// CI test runner
				(ethereum_account_id(hex!("6be02d1d3665660d22ff9624b7be0551ee1ac91b")), DEV_BALANCE),
			],
			// Initial PoA authorities
			vec![authority_keys_from_seed("Alice")],
			EVM_CHAIN_ID,
			enable_manual_seal,
		))
		.build()
}

pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Local Testnet")
		.with_id("local_testnet")
		.with_chain_type(ChainType::Local)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			AccountId::from(hex!(
				"d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
			)),
			vec![
				(ethereum_account_id(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")), TOTAL_SUPPLY),
				(AccountId::from(hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")), DEV_BALANCE),
				(AccountId::from(hex!("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48")), DEV_BALANCE),
				(AccountId::from(hex!("90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22")), DEV_BALANCE),
				(ethereum_account_id(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")), DEV_BALANCE),
				(ethereum_account_id(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")), DEV_BALANCE),
				(ethereum_account_id(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")), DEV_BALANCE),
				(ethereum_account_id(hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB")), DEV_BALANCE),
				(ethereum_account_id(hex!("C0F0f4ab324C46e55D02D0033343B4Be8A55532d")), DEV_BALANCE),
				(ethereum_account_id(hex!("6be02d1d3665660d22ff9624b7be0551ee1ac91b")), DEV_BALANCE),
			],
			vec![
				authority_keys_from_seed("Alice"),
				authority_keys_from_seed("Bob"),
			],
			EVM_CHAIN_ID,
			false,
		))
		.build()
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	sudo_key: AccountId,
	endowed_accounts: Vec<(AccountId, Balance)>,
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	enable_manual_seal: bool,
) -> serde_json::Value {
	let evm_accounts = {
		let mut map = BTreeMap::new();
		// Benchmark helper account only — balances live in pallet-balances via TruncatedAddressMapping
		map.insert(
			H160::from_str("1000000000000000000000000000000000000001")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				nonce: U256::from(1),
				balance: U256::zero(),
				storage: Default::default(),
				code: vec![0x00],
			},
		);
		map
	};

	serde_json::json!({
		"sudo": { "key": Some(sudo_key) },
		"balances": {
			"balances": endowed_accounts
		},
		"aura": { "authorities": initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>() },
		"grandpa": { "authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>() },
		"evmChainId": { "chainId": chain_id },
		"evm": { "accounts": evm_accounts },
		"manualSeal": { "enable": enable_manual_seal },
		"zkVerifier": {
			"verificationKeys": vec![
				(CircuitId::TRANSFER, verification_keys::get_transfer_vk_bytes()),
				(CircuitId::UNSHIELD, verification_keys::get_unshield_vk_bytes()),
				(CircuitId::DISCLOSURE, verification_keys::get_disclosure_vk_bytes()),
			]
		}
	})
}
