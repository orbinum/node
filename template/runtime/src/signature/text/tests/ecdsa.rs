//! `EcdsaText`: an EVM wallet's `personal_sign` (EIP-191) over the same text, for the
//! account its EVM address maps to.

use super::*;
use crate::{
	signature::{eip191_text_message, OrbinumSigner},
	test_utils::ALITH_KEY,
};
use sp_core::ecdsa;
use sp_runtime::{traits::IdentifyAccount, transaction_validity::InvalidTransaction};

/// secp256k1 group order, big-endian.
const SECP256K1_ORDER: [u8; 32] =
	hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// `n − s` for a big-endian scalar.
fn order_minus(s: &[u8]) -> [u8; 32] {
	let mut out = [0u8; 32];
	let mut borrow = 0i16;
	for i in (0..32).rev() {
		let d = SECP256K1_ORDER[i] as i16 - s[i] as i16 - borrow;
		borrow = (d < 0) as i16;
		out[i] = (d + 256 * borrow) as u8;
	}
	out
}

/// Alith's mapped account, written out as an independent check.
const ALITH_ACCOUNT: [u8; 32] =
	hex!("f24ff3a9cf04c71dbc94d0b566f7a27b94566cac000000000000000000000000");

fn alith() -> (ecdsa::Pair, AccountId) {
	let pair = ecdsa::Pair::from_seed(&ALITH_KEY);
	let account = OrbinumSigner::Ecdsa(pair.public()).into_account();
	(pair, account)
}

/// `personal_sign` as EVM wallets compute it: keccak256 of the EIP-191 message.
pub(super) fn sign_eip191(pair: &ecdsa::Pair, payload: &[u8]) -> ecdsa::Signature {
	let genesis = frame_system::Pallet::<Runtime>::block_hash(0u32);
	let message = eip191_text_message(genesis.as_fixed_bytes(), payload);
	pair.sign_prehashed(&sp_io::hashing::keccak_256(&message))
}

#[test]
fn alith_maps_to_her_evm_address() {
	assert_eq!(alith().1, AccountId::from(ALITH_ACCOUNT));
}

#[test]
fn an_evm_wallet_signs_the_text_for_its_mapped_account() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = alith();
		for call in [transfer(ORB), remark(300)] {
			let sig = sign_eip191(&pair, &raw_payload(&call, 0));
			assert_eq!(
				check(call, &account, OrbinumSignature::EcdsaText(sig), 0),
				Ok(())
			);
		}
	});
}

#[test]
fn another_account_another_payload_or_another_variant_fail() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = alith();
		let call = transfer(ORB);
		let sig = sign_eip191(&pair, &raw_payload(&call, 0));
		let bad = Err(InvalidTransaction::BadProof.into());
		assert_eq!(
			check(
				call.clone(),
				&AccountId::from(BOB),
				OrbinumSignature::EcdsaText(sig),
				0
			),
			bad
		);
		assert_eq!(
			check(
				transfer(2 * ORB),
				&account,
				OrbinumSignature::EcdsaText(sig),
				0
			),
			bad
		);
		assert_eq!(
			check(call.clone(), &account, OrbinumSignature::EcdsaText(sig), 1),
			bad
		);
		// Raw `Ecdsa` never verifies.
		assert_eq!(check(call, &account, OrbinumSignature::Ecdsa(sig), 0), bad);
	});
}

#[test]
fn only_the_canonical_encoding_verifies() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = alith();
		let call = transfer(ORB);
		let mut sig = sign_eip191(&pair, &raw_payload(&call, 0)).0;
		// Wallets return `v` as 27/28; clients send the raw recovery id (0/1).
		sig[64] += 27;
		assert_eq!(
			check(
				call,
				&account,
				OrbinumSignature::EcdsaText(ecdsa::Signature::from_raw(sig)),
				0
			),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

#[test]
fn a_mainnet_text_does_not_verify_on_another_chain() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = alith();
		let call = transfer(ORB);
		let sig = sign_eip191(&pair, &raw_payload(&call, 0));
		set_genesis([0x11; 32]);
		assert_eq!(
			check(call, &account, OrbinumSignature::EcdsaText(sig), 0),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

#[test]
fn an_evm_wallet_cannot_sign_a_call_that_hides_its_parameters() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = alith();
		let burn = RuntimeCall::Balances(BalancesCall::burn {
			value: ORB,
			keep_alive: false,
		});
		let sig = sign_eip191(&pair, &raw_payload(&burn, 0));
		assert_eq!(
			check(burn, &account, OrbinumSignature::EcdsaText(sig), 0),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

/// `(r, n − s)` with the other recovery id recovers the same key; only the low-`s`
/// encoding verifies.
#[test]
fn ecdsa_text_high_s_alias_is_refused() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = alith();
		let call = transfer(ORB);
		let payload = raw_payload(&call, 0);
		let sig = sign_eip191(&pair, &payload).0;
		assert!(
			sig[32..64] <= order_minus(&sig[32..64])[..],
			"sp_core signs with a low s"
		);
		let mut alias = sig;
		alias[32..64].copy_from_slice(&order_minus(&sig[32..64]));
		alias[64] ^= 1;
		let hash = sp_io::hashing::keccak_256(&eip191_text_message(&TESTNET_GENESIS, &payload));
		let recover = |sig: &[u8; 65]| sp_io::crypto::secp256k1_ecdsa_recover(sig, &hash).ok();
		assert!(recover(&sig).is_some());
		assert_eq!(recover(&alias), recover(&sig));
		assert_eq!(
			check(
				call,
				&account,
				OrbinumSignature::EcdsaText(ecdsa::Signature::from_raw(alias)),
				0
			),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}

/// A wallet, MPC or KMS that signs a raw digest can be handed `blake2_256(payload)`:
/// that signature recovers the key but authorizes nothing.
#[test]
fn raw_ecdsa_over_payload_hash_authorizes_nothing() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = alith();
		let call = transfer(ORB);
		let payload = raw_payload(&call, 0);
		// Up to 256 bytes `Verify` receives the payload itself.
		assert!(payload.len() <= 256);
		let hash = sp_io::hashing::blake2_256(&payload);
		let blind = pair.sign_prehashed(&hash);
		assert_eq!(blind.recover_prehashed(&hash), Some(pair.public()));
		assert_eq!(
			check(call, &account, OrbinumSignature::Ecdsa(blind), 0),
			Err(InvalidTransaction::BadProof.into())
		);
	});
}
