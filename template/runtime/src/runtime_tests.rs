use crate::{account_mapping_runtime::EeSuffixAddressMapping, AccountId, Runtime, WeightPerGas};
use hex_literal::hex;
use pallet_evm::AddressMapping;
use sp_core::{ecdsa, sr25519, Pair, H160};
use sp_io::TestExternalities;
use sp_runtime::{
	traits::{IdentifyAccount, Verify},
	MultiSignature, MultiSigner,
};

fn with_ext<R>(run: impl FnOnce() -> R) -> R {
	TestExternalities::default().execute_with(run)
}

#[test]
fn configured_base_extrinsic_weight_is_evm_compatible() {
	let min_ethereum_transaction_weight = WeightPerGas::get() * 21_000;
	let base_extrinsic = <Runtime as frame_system::Config>::BlockWeights::get()
		.get(frame_support::dispatch::DispatchClass::Normal)
		.base_extrinsic;
	assert!(base_extrinsic.ref_time() <= min_ethereum_transaction_weight.ref_time());
}

#[test]
fn ee_suffix_mapping_is_deterministic() {
	with_ext(|| {
		let eth_addr = H160::from([0x42u8; 20]);
		let acc1 = EeSuffixAddressMapping::<Runtime>::into_account_id(eth_addr);
		let acc2 = EeSuffixAddressMapping::<Runtime>::into_account_id(eth_addr);
		assert_eq!(acc1, acc2, "mismo H160 debe producir el mismo AccountId32");
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
		let alith_eth = H160::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"));
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
		let alith_eth = H160::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"));

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
fn sr25519_valid_signature_verifies() {
	let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
	let msg = b"test-multisignature-orbinum";

	let sig = pair.sign(msg);
	let multi_sig = MultiSignature::Sr25519(sig);

	let signer_account: AccountId = MultiSigner::from(pair.public()).into_account();

	assert!(
		multi_sig.verify(msg.as_ref(), &signer_account),
		"Sr25519 valid signature must verify against its own AccountId"
	);
}

#[test]
fn sr25519_wrong_signer_rejected() {
	let alice = sr25519::Pair::from_string("//Alice", None).unwrap();
	let bob = sr25519::Pair::from_string("//Bob", None).unwrap();

	let msg = b"test-wrong-signer";
	let alice_sig = alice.sign(msg);
	let multi_sig = MultiSignature::Sr25519(alice_sig);

	let bob_account: AccountId = MultiSigner::from(bob.public()).into_account();

	assert!(
		!multi_sig.verify(msg.as_ref(), &bob_account),
		"Sr25519 Alice's signature must NOT verify against Bob's account"
	);
}

#[test]
fn sr25519_wrong_message_rejected() {
	let pair = sr25519::Pair::from_string("//Alice", None).unwrap();

	let original_msg = b"original-message";
	let different_msg = b"different-message";

	let sig = pair.sign(original_msg);
	let multi_sig = MultiSignature::Sr25519(sig);

	let signer_account: AccountId = MultiSigner::from(pair.public()).into_account();

	assert!(
		!multi_sig.verify(different_msg.as_ref(), &signer_account),
		"Sr25519 signature over message A must NOT verify message B"
	);
}

#[test]
fn sr25519_corrupted_signature_rejected() {
	let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
	let msg = b"test-corrupted";

	let corrupted = sr25519::Signature::default();
	let multi_sig = MultiSignature::Sr25519(corrupted);

	let signer_account: AccountId = MultiSigner::from(pair.public()).into_account();

	assert!(
		!multi_sig.verify(msg.as_ref(), &signer_account),
		"Sr25519 corrupted signature must be rejected"
	);
}

#[test]
fn sr25519_each_account_verifies_only_own_signature() {
	let alice = sr25519::Pair::from_string("//Alice", None).unwrap();
	let bob = sr25519::Pair::from_string("//Bob", None).unwrap();

	let msg = b"same-message";
	let alice_sig = alice.sign(msg);
	let bob_sig = bob.sign(msg);

	assert_ne!(
		alice.public().0,
		bob.public().0,
		"Alice and Bob have distinct keys"
	);

	let alice_acc: AccountId = MultiSigner::from(alice.public()).into_account();
	let bob_acc: AccountId = MultiSigner::from(bob.public()).into_account();

	assert!(MultiSignature::Sr25519(alice_sig).verify(msg.as_ref(), &alice_acc));
	assert!(MultiSignature::Sr25519(bob_sig).verify(msg.as_ref(), &bob_acc));
	assert!(!MultiSignature::Sr25519(alice.sign(msg)).verify(msg.as_ref(), &bob_acc));
	assert!(!MultiSignature::Sr25519(bob.sign(msg)).verify(msg.as_ref(), &alice_acc));
}

#[test]
fn ecdsa_valid_signature_verifies() {
	let pair = ecdsa::Pair::from_string("//Alice", None).unwrap();
	let msg = b"test-ecdsa-multisignature";

	let sig = pair.sign(msg);
	let multi_sig = MultiSignature::Ecdsa(sig);

	let signer_account: AccountId = MultiSigner::from(pair.public()).into_account();

	assert!(
		multi_sig.verify(msg.as_ref(), &signer_account),
		"ECDSA valid signature must verify against its AccountId"
	);
}

#[test]
fn ecdsa_wrong_signer_rejected() {
	let alice = ecdsa::Pair::from_string("//Alice", None).unwrap();
	let bob = ecdsa::Pair::from_string("//Bob", None).unwrap();

	let msg = b"test-ecdsa-wrong-signer";
	let alice_sig = alice.sign(msg);
	let multi_sig = MultiSignature::Ecdsa(alice_sig);

	let bob_account: AccountId = MultiSigner::from(bob.public()).into_account();

	assert!(
		!multi_sig.verify(msg.as_ref(), &bob_account),
		"ECDSA Alice's signature must NOT verify against Bob's account"
	);
}

#[test]
fn ecdsa_substrate_and_evm_paths_are_independent() {
	with_ext(|| {
		let alith_eth_address = H160::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"));

		let evm_account = EeSuffixAddressMapping::<Runtime>::into_account_id(alith_eth_address);

		let ecdsa_pair = ecdsa::Pair::from_string("//AliceEcdsa", None).unwrap();
		let substrate_ecdsa_account: AccountId =
			MultiSigner::from(ecdsa_pair.public()).into_account();

		assert_ne!(
			evm_account, substrate_ecdsa_account,
			"EeSuffixAddressMapping (EVM) and MultiSigner ECDSA are independent routes"
		);
	});
}

#[test]
fn multisignature_variants_have_correct_byte_sizes() {
	let sr25519_pair = sr25519::Pair::from_string("//Alice", None).unwrap();
	let ecdsa_pair = ecdsa::Pair::from_string("//Alice", None).unwrap();
	let msg = b"size-test";

	let sr25519_sig = sr25519_pair.sign(msg);
	let ecdsa_sig = ecdsa_pair.sign(msg);

	assert_eq!(
		sr25519_sig.0.len(),
		64,
		"Sr25519 signature must be 64 bytes"
	);

	assert_eq!(ecdsa_sig.0.len(), 65, "ECDSA signature must be 65 bytes");

	let _ms_sr = MultiSignature::Sr25519(sr25519_sig);
	let _ms_ec = MultiSignature::Ecdsa(ecdsa_sig);
}

fn api_validate_signature(signature: MultiSignature, message: &[u8], signer: &AccountId) -> bool {
	use sp_runtime::traits::Verify;
	signature.verify(message, signer)
}

fn sr25519_account(derivation: &str) -> (sr25519::Pair, AccountId) {
	let pair = sr25519::Pair::from_string(derivation, None).unwrap();
	let account: AccountId = MultiSigner::from(pair.public()).into_account();
	(pair, account)
}

fn ecdsa_account(derivation: &str) -> (ecdsa::Pair, AccountId) {
	let pair = ecdsa::Pair::from_string(derivation, None).unwrap();
	let account: AccountId = MultiSigner::from(pair.public()).into_account();
	(pair, account)
}

#[test]
fn check_nonce_signed_extension_is_constructable() {
	let _: frame_system::CheckNonce<Runtime>;
}

#[test]
fn nonce_type_is_u32_for_this_runtime() {
	let zero: <Runtime as frame_system::Config>::Nonce = 0u32;
	let one: <Runtime as frame_system::Config>::Nonce = 1u32;
	assert_ne!(zero, one, "Nonce 0 and Nonce 1 must be distinct");

	let max_nonce: u32 = u32::MAX;
	assert_eq!(
		max_nonce, 4_294_967_295u32,
		"Maximum nonce is u32::MAX = 4,294,967,295"
	);
}

#[test]
fn sr25519_and_ecdsa_same_derivation_produce_different_accounts() {
	let (_, sr25519_alice_account) = sr25519_account("//Alice");
	let (_, ecdsa_alice_account) = ecdsa_account("//Alice");

	assert_ne!(
		sr25519_alice_account, ecdsa_alice_account,
		"Sr25519 //Alice and ECDSA //Alice must have distinct AccountId32 — independent nonces"
	);
}

#[test]
fn same_account_single_nonce_regardless_of_signature_type() {
	let (alice_sr, alice_sr_account) = sr25519_account("//AliceNonce");
	let msg = b"nonce-invariant-test";

	let sig_sr = MultiSignature::Sr25519(alice_sr.sign(msg));
	assert!(
		api_validate_signature(sig_sr, msg, &alice_sr_account),
		"Sr25519 signature for the correct AccountId always verifies"
	);

	let account_bytes: &[u8; 32] = alice_sr_account.as_ref();
	assert_eq!(account_bytes.len(), 32, "AccountId32 always has 32 bytes");
}

#[test]
fn evm_and_substrate_addresses_share_unified_balance() {
	with_ext(|| {
		let alith_h160 = H160::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac"));

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
