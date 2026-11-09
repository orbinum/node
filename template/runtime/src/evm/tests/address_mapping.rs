//! One account for an EVM address and its secp256k1 key: the `[address | 0x00×12]`
//! mapping, and `EnsureAddressMatches`, the EVM origin check built on it.

use crate::{
	evm::account::{EeSuffixAddressMapping, EnsureAddressMatches},
	evm_h160_to_account_id,
	signature::OrbinumSigner,
	test_utils::{with_ext, ALITH_ADDRESS},
	AccountId, Runtime, RuntimeOrigin,
};
use hex_literal::hex;
use pallet_evm::{AddressMapping, EnsureAddressOrigin};
use sp_core::{ecdsa, Pair, H160};
use sp_runtime::traits::IdentifyAccount;

#[test]
fn ee_suffix_mapping_is_deterministic() {
	with_ext(|| {
		let eth_addr = H160::from([0x42u8; 20]);
		let acc1 = EeSuffixAddressMapping::<Runtime>::into_account_id(eth_addr);
		let acc2 = EeSuffixAddressMapping::<Runtime>::into_account_id(eth_addr);
		assert_eq!(
			acc1, acc2,
			"the same H160 must produce the same AccountId32"
		);
	});
}

#[test]
fn ee_suffix_mapping_is_unique() {
	with_ext(|| {
		let addr1 = H160::from([0x01u8; 20]);
		let addr2 = H160::from([0x02u8; 20]);
		let acc1 = EeSuffixAddressMapping::<Runtime>::into_account_id(addr1);
		let acc2 = EeSuffixAddressMapping::<Runtime>::into_account_id(addr2);
		assert_ne!(
			acc1, acc2,
			"different H160 values must produce distinct AccountId32"
		);
	});
}

#[test]
fn ee_suffix_mapping_layout_is_correct() {
	with_ext(|| {
		let alith_eth = H160(ALITH_ADDRESS);
		let account_id = EeSuffixAddressMapping::<Runtime>::into_account_id(alith_eth);
		let bytes: &[u8; 32] = account_id.as_ref();

		assert_eq!(
			&bytes[..20],
			alith_eth.as_bytes(),
			"first 20 bytes must match H160"
		);
		assert_eq!(&bytes[20..], &[0x00u8; 12], "last 12 bytes must be 0x00");
	});
}

#[test]
fn chain_spec_mapping_matches_runtime_fallback_mapping() {
	with_ext(|| {
		let alith_eth = H160(ALITH_ADDRESS);

		let chain_spec_account = {
			let mut bytes = [0u8; 32];
			bytes[..20].copy_from_slice(alith_eth.as_bytes());
			bytes[20..].copy_from_slice(&[0x00u8; 12]);
			AccountId::from(bytes)
		};

		let runtime_account = EeSuffixAddressMapping::<Runtime>::into_account_id(alith_eth);

		assert_eq!(
			chain_spec_account, runtime_account,
			"genesis_config and the runtime must produce the same AccountId32 for Alith"
		);
	});
}

#[test]
fn all_evm_dev_accounts_map_to_unique_accounts() {
	with_ext(|| {
		let dev_addresses: [[u8; 20]; 6] = [
			hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"),
			hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0"),
			hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc"),
			hex!("773539d4Ac0e786233D90A233654ccEE26a613D9"),
			hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB"),
			hex!("C0F0f4ab324C46e55D02D0033343B4Be8A55532d"),
		];

		let accounts: alloc::vec::Vec<AccountId> = dev_addresses
			.iter()
			.map(|b| EeSuffixAddressMapping::<Runtime>::into_account_id(H160::from(*b)))
			.collect();

		for i in 0..accounts.len() {
			for j in (i + 1)..accounts.len() {
				assert_ne!(
					accounts[i], accounts[j],
					"EVM dev accounts must map to unique AccountId32 values (indices {i} and {j})"
				);
			}
		}
	});
}

#[test]
fn ecdsa_evm_and_substrate_paths_are_unified() {
	with_ext(|| {
		let ecdsa_pair = ecdsa::Pair::from_string("//Alice", None).unwrap();

		// Substrate path: `OrbinumSigner::Ecdsa` gives `[eth_addr | 0x00×12]`.
		let substrate_account: AccountId = OrbinumSigner::Ecdsa(ecdsa_pair.public()).into_account();

		let bytes: &[u8; 32] = substrate_account.as_ref();
		assert_eq!(
			&bytes[20..],
			&[0u8; 12],
			"OrbinumSigner::Ecdsa must produce AccountId32 with 12-byte zero suffix"
		);

		// EVM path: the same H160 through `EeSuffixAddressMapping`.
		let eth_addr = H160::from_slice(&bytes[..20]);
		let evm_account = EeSuffixAddressMapping::<Runtime>::into_account_id(eth_addr);

		assert_eq!(
			substrate_account, evm_account,
			"OrbinumSigner::Ecdsa and EeSuffixAddressMapping must produce identical AccountId32 \
			 for the same secp256k1 keypair"
		);
	});
}

/// `OrbinumSigner::Ecdsa` against a known vector, independent of the runtime's derivation:
/// Alith, the well-known Frontier/Moonbeam dev key, must map to `[H160 | 0x00×12]`.
///
/// - Private key: `0x5fb92d6e98884f76de468fa3f6278f8807c48bebc13595d45af5bdc4da702133`.
/// - H160: `0xf24FF3a9CF04c71Dbc94D0b566f7A27B94566cac`.
/// - Compressed public key: `02509540919faacf9ab52146c9aa40db68172d83777250b28e4679176e49ccdd9f`.
#[test]
fn ecdsa_known_vector_alith_derives_correct_account() {
	with_ext(|| {
		let compressed_pk: [u8; 33] =
			hex!("02509540919faacf9ab52146c9aa40db68172d83777250b28e4679176e49ccdd9f");
		let alith_h160: [u8; 20] = ALITH_ADDRESS;

		let pub_key = sp_core::ecdsa::Public::from_raw(compressed_pk);
		let derived: AccountId = OrbinumSigner::Ecdsa(pub_key).into_account();
		let derived_bytes: &[u8; 32] = derived.as_ref();

		assert_eq!(
			&derived_bytes[..20],
			&alith_h160,
			"OrbinumSigner::Ecdsa must derive Alith's H160 as the first 20 bytes"
		);
		assert_eq!(
			&derived_bytes[20..],
			&[0u8; 12],
			"OrbinumSigner::Ecdsa must produce 12-byte zero suffix"
		);

		let evm_account =
			EeSuffixAddressMapping::<Runtime>::into_account_id(H160::from(alith_h160));
		assert_eq!(
			derived, evm_account,
			"OrbinumSigner::Ecdsa(Alith) must equal EeSuffixAddressMapping(Alith H160)"
		);
	});
}

#[test]
fn evm_and_substrate_addresses_share_unified_balance() {
	with_ext(|| {
		let alith_h160 = H160(ALITH_ADDRESS);

		let substrate_account = EeSuffixAddressMapping::<Runtime>::into_account_id(alith_h160);
		let substrate_bytes: &[u8; 32] = substrate_account.as_ref();

		assert_eq!(
			&substrate_bytes[..20],
			alith_h160.as_bytes(),
			"First 20 bytes must match H160"
		);
		assert_eq!(
			&substrate_bytes[20..],
			&[0x00u8; 12],
			"Last 12 bytes must be 0x00"
		);

		let substrate_account_2 = EeSuffixAddressMapping::<Runtime>::into_account_id(alith_h160);
		assert_eq!(
			substrate_account, substrate_account_2,
			"Mapping must be deterministic — same H160 always produces same AccountId32"
		);

		let different_h160 = H160::from(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0"));
		let different_account = EeSuffixAddressMapping::<Runtime>::into_account_id(different_h160);
		assert_ne!(
			substrate_account, different_account,
			"Different H160 addresses must map to different AccountId32 values"
		);
	});
}

/// The EVM's call and withdraw origin: a signed origin of exactly the mapped account.
#[test]
fn ensure_address_matches_accepts_only_the_mapped_account() {
	let alith = H160(ALITH_ADDRESS);
	let mapped = evm_h160_to_account_id(alith);
	assert_eq!(
		EnsureAddressMatches::try_address_origin(&alith, RuntimeOrigin::signed(mapped.clone()))
			.ok(),
		Some(mapped.clone())
	);
	let other = AccountId::from([0x42; 32]);
	for origin in [
		RuntimeOrigin::signed(other),
		RuntimeOrigin::root(),
		RuntimeOrigin::none(),
	] {
		assert!(EnsureAddressMatches::try_address_origin(&alith, origin).is_err());
	}
	// The same 20 bytes with another suffix are another account.
	let mut suffixed: [u8; 32] = mapped.into();
	suffixed[31] = 1;
	assert!(EnsureAddressMatches::try_address_origin(
		&alith,
		RuntimeOrigin::signed(AccountId::from(suffixed))
	)
	.is_err());
}
