//! Sr25519 signatures verify for their own account only; raw ECDSA never verifies.

use crate::{
	signature::{OrbinumSignature, OrbinumSigner},
	AccountId,
};
use sp_core::{ecdsa, sr25519, Pair};
use sp_runtime::traits::{IdentifyAccount, Verify};

fn sr25519_account(derivation: &str) -> (sr25519::Pair, AccountId) {
	let pair = sr25519::Pair::from_string(derivation, None).unwrap();
	let account: AccountId = OrbinumSigner::from(pair.public()).into_account();
	(pair, account)
}

fn ecdsa_account(derivation: &str) -> (ecdsa::Pair, AccountId) {
	let pair = ecdsa::Pair::from_string(derivation, None).unwrap();
	let account: AccountId = OrbinumSigner::Ecdsa(pair.public()).into_account();
	(pair, account)
}

#[test]
fn sr25519_valid_signature_verifies() {
	let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
	let msg = b"test-multisignature-orbinum";

	let sig = pair.sign(msg);
	let orbinum_sig = OrbinumSignature::Sr25519(sig);

	let signer_account: AccountId = OrbinumSigner::from(pair.public()).into_account();

	assert!(
		orbinum_sig.verify(msg.as_ref(), &signer_account),
		"Sr25519 valid signature must verify against its own AccountId"
	);
}

#[test]
fn sr25519_wrong_signer_rejected() {
	let alice = sr25519::Pair::from_string("//Alice", None).unwrap();
	let bob = sr25519::Pair::from_string("//Bob", None).unwrap();

	let msg = b"test-wrong-signer";
	let alice_sig = alice.sign(msg);
	let orbinum_sig = OrbinumSignature::Sr25519(alice_sig);

	let bob_account: AccountId = OrbinumSigner::from(bob.public()).into_account();

	assert!(
		!orbinum_sig.verify(msg.as_ref(), &bob_account),
		"Sr25519 Alice's signature must NOT verify against Bob's account"
	);
}

#[test]
fn sr25519_wrong_message_rejected() {
	let pair = sr25519::Pair::from_string("//Alice", None).unwrap();

	let original_msg = b"original-message";
	let different_msg = b"different-message";

	let sig = pair.sign(original_msg);
	let orbinum_sig = OrbinumSignature::Sr25519(sig);

	let signer_account: AccountId = OrbinumSigner::from(pair.public()).into_account();

	assert!(
		!orbinum_sig.verify(different_msg.as_ref(), &signer_account),
		"Sr25519 signature over message A must NOT verify message B"
	);
}

#[test]
fn sr25519_corrupted_signature_rejected() {
	let pair = sr25519::Pair::from_string("//Alice", None).unwrap();
	let msg = b"test-corrupted";

	let corrupted = sr25519::Signature::default();
	let orbinum_sig = OrbinumSignature::Sr25519(corrupted);

	let signer_account: AccountId = OrbinumSigner::from(pair.public()).into_account();

	assert!(
		!orbinum_sig.verify(msg.as_ref(), &signer_account),
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

	let alice_acc: AccountId = OrbinumSigner::from(alice.public()).into_account();
	let bob_acc: AccountId = OrbinumSigner::from(bob.public()).into_account();

	assert!(OrbinumSignature::Sr25519(alice_sig).verify(msg.as_ref(), &alice_acc));
	assert!(OrbinumSignature::Sr25519(bob_sig).verify(msg.as_ref(), &bob_acc));
	assert!(!OrbinumSignature::Sr25519(alice.sign(msg)).verify(msg.as_ref(), &bob_acc));
	assert!(!OrbinumSignature::Sr25519(bob.sign(msg)).verify(msg.as_ref(), &alice_acc));
}

#[test]
fn raw_ecdsa_signature_never_verifies() {
	let pair = ecdsa::Pair::from_string("//Alice", None).unwrap();
	let msg = b"test-ecdsa-multisignature";
	let signer_account: AccountId = OrbinumSigner::from(pair.public()).into_account();
	assert!(
		!OrbinumSignature::Ecdsa(pair.sign(msg)).verify(msg.as_ref(), &signer_account),
		"raw ECDSA must not verify, even for its own account"
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
