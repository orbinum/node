//! Produces valid EVM ownership proofs for tests and benchmarks.
//!
//! `register_relayer` requires a signature from the EVM key, so both callers need
//! to sign the binding digest for real — a hard-coded signature would silently
//! rot the moment the digest format changes, and the tests would keep passing
//! against a format nobody uses.
//!
//! Compiled only under `test` or `runtime-benchmarks`, never in a plain build.

use crate::{Config, EvmSignature, evm_proof};
use frame_support::pallet_prelude::*;
use sp_core::H160;

/// Deterministic 32-byte secret, so the derived address is stable across runs.
/// Not a secret in any real sense — it is committed in plain sight.
///
/// Tests that need several distinct addresses pass their own seeds; see
/// `mock::seeds`.
pub const DEFAULT_SEED: [u8; 32] = [0xb0; 32];

/// Produce `(evm_address, signature)` proving control of that address for `who`
/// on the current chain, using `seed` as the secret key.
///
/// Uses `libsecp256k1` rather than `sp_core::ecdsa::Pair`, whose
/// `sign_prehashed` is std-only — benchmarks run in WASM.
pub fn signed_binding_with<T: Config>(who: &T::AccountId, seed: &[u8; 32]) -> (H160, EvmSignature) {
	let secret = libsecp256k1::SecretKey::parse(seed).expect("static seed is a valid key; qed");
	// serialize() is 65 bytes with a 0x04 tag; the derivation wants the 64 after it.
	let tagged = libsecp256k1::PublicKey::from_secret_key(&secret).serialize();
	let untagged: [u8; 64] = tagged[1..].try_into().expect("65 - 1 == 64; qed");
	let evm_address = evm_proof::evm_address_from_uncompressed(&untagged);

	let digest = evm_proof::binding_digest(
		who.encode().as_slice(),
		&evm_address,
		&evm_proof::genesis_hash::<T>(),
	);
	let (signature, recovery) = libsecp256k1::sign(&libsecp256k1::Message::parse(&digest), &secret);

	let mut raw = [0u8; 65];
	raw[..64].copy_from_slice(&signature.serialize());
	raw[64] = recovery.serialize();
	(evm_address, EvmSignature(raw))
}

/// [`signed_binding_with`] using [`DEFAULT_SEED`].
pub fn signed_binding<T: Config>(who: &T::AccountId) -> (H160, EvmSignature) {
	signed_binding_with::<T>(who, &DEFAULT_SEED)
}
