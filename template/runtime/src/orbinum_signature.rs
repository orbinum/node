//! OrbinumSignature — unified signature type for Orbinum.
//!
//! Extends the standard [`sp_runtime::MultiSignature`] so that the ECDSA variant
//! derives `AccountId32` using Ethereum-compatible address encoding:
//!
//! ```text
//! AccountId32 = [keccak256(uncompressed_pubkey[1..])[12..] | 0x00 × 12]
//! ```
//!
//! This is identical to the mapping produced by `EeSuffixAddressMapping`, meaning
//! the same secp256k1 keypair produces the **same** `AccountId32` from both an
//! EVM transaction and a native Substrate extrinsic.
//!
//! Sr25519 and Ed25519 variants behave identically to `MultiSignature`.
//!
//! ## SCALE discriminants
//!
//! The variant ordering mirrors `sp_runtime::MultiSignature` so that SCALE-encoded
//! bytes remain wire-compatible with existing tooling:
//!
//! | Discriminant | Variant  |
//! |:---:|----------|
//! | 0x00 | Ed25519  |
//! | 0x01 | Sr25519  |
//! | 0x02 | Ecdsa    |

use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::{ecdsa, ed25519, sr25519, H160};
use sp_runtime::traits::{IdentifyAccount, Lazy, Verify};

use crate::account_mapping_runtime::evm_bytes_to_account_id_bytes;

/// The account ID type used by this runtime.
pub type AccountId = sp_runtime::AccountId32;

/// Derive an Ethereum `H160` address from the 64-byte uncompressed public-key
/// body (the 64 bytes *after* the `0x04` prefix byte).
///
/// This is the standard Ethereum address derivation:
/// `keccak256(uncompressed_pubkey[1..])[12..]`
fn pub64_to_eth_address(pub64: &[u8; 64]) -> H160 {
	let hash = sp_io::hashing::keccak_256(pub64);
	H160::from_slice(&hash[12..])
}

// ─── OrbinumSigner ────────────────────────────────────────────────────────────

/// The signer type that corresponds to [`OrbinumSignature`].
///
/// For ECDSA keys the `AccountId` is derived as `[eth_address | 0x00 × 12]`
/// rather than `blake2_256(compressed_pubkey)` used by `MultiSigner`.
///
/// Variant order matches `sp_runtime::MultiSigner` for SCALE compatibility.
#[derive(
	Clone,
	Eq,
	PartialEq,
	Debug,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen
)]
pub enum OrbinumSigner {
	Ed25519(ed25519::Public),
	Sr25519(sr25519::Public),
	/// ECDSA key — `AccountId` derived as `[eth_address | 0x00 × 12]`.
	Ecdsa(ecdsa::Public),
}

impl From<ed25519::Public> for OrbinumSigner {
	fn from(k: ed25519::Public) -> Self {
		Self::Ed25519(k)
	}
}

impl From<sr25519::Public> for OrbinumSigner {
	fn from(k: sr25519::Public) -> Self {
		Self::Sr25519(k)
	}
}

impl From<ecdsa::Public> for OrbinumSigner {
	fn from(k: ecdsa::Public) -> Self {
		Self::Ecdsa(k)
	}
}

impl IdentifyAccount for OrbinumSigner {
	type AccountId = AccountId;

	fn into_account(self) -> AccountId {
		match self {
			OrbinumSigner::Ed25519(k) => sp_runtime::MultiSigner::Ed25519(k).into_account(),
			OrbinumSigner::Sr25519(k) => sp_runtime::MultiSigner::Sr25519(k).into_account(),
			OrbinumSigner::Ecdsa(k) => {
				// Decompress the 33-byte compressed key to 65-byte uncompressed form,
				// then derive the Ethereum address with keccak256.
				use libsecp256k1::{PublicKey, PublicKeyFormat};
				let compressed: &[u8; 33] = k.as_ref();
				let pk = match PublicKey::parse_slice(compressed, Some(PublicKeyFormat::Compressed))
				{
					Ok(pk) => pk,
					// Invalid key — fall back to standard MultiSigner derivation.
					Err(_) => return sp_runtime::MultiSigner::Ecdsa(k).into_account(),
				};
				let uncompressed = pk.serialize(); // [u8; 65], 0x04 prefix
				let pub64: [u8; 64] = uncompressed[1..65]
					.try_into()
					.expect("uncompressed key without prefix is exactly 64 bytes; qed");
				let h160 = pub64_to_eth_address(&pub64);
				AccountId::from(evm_bytes_to_account_id_bytes(*h160.as_fixed_bytes()))
			}
		}
	}
}

// ─── OrbinumSignature ─────────────────────────────────────────────────────────

/// Unified signature type for Orbinum.
///
/// - `Ed25519` / `Sr25519`: identical to [`sp_runtime::MultiSignature`].
/// - `Ecdsa`: verifies using `blake2_256` of the payload; the signer `AccountId`
///   is derived as `[keccak256(uncompressed_pubkey[1..])[12..] | 0x00 × 12]`,
///   matching `EeSuffixAddressMapping`.
///
/// Variant order mirrors `sp_runtime::MultiSignature` for SCALE wire compatibility
/// (Ed25519 = 0x00, Sr25519 = 0x01, Ecdsa = 0x02).
#[derive(
	Clone,
	Eq,
	PartialEq,
	Debug,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo,
	MaxEncodedLen
)]
pub enum OrbinumSignature {
	Ed25519(ed25519::Signature),
	Sr25519(sr25519::Signature),
	/// ECDSA: payload hashed with blake2_256; AccountId via keccak256 / EVM-suffix.
	Ecdsa(ecdsa::Signature),
}

impl Verify for OrbinumSignature {
	type Signer = OrbinumSigner;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId) -> bool {
		match self {
			OrbinumSignature::Ed25519(sig) => {
				sp_runtime::MultiSignature::Ed25519(*sig).verify(msg, signer)
			}
			OrbinumSignature::Sr25519(sig) => {
				sp_runtime::MultiSignature::Sr25519(*sig).verify(msg, signer)
			}
			OrbinumSignature::Ecdsa(sig) => {
				// 1. Hash the payload with blake2_256 (standard Substrate signing).
				let hash = sp_io::hashing::blake2_256(msg.get());
				// 2. Recover the 64-byte uncompressed public key (without 0x04 prefix).
				let sig_bytes: &[u8; 65] = sig.as_ref();
				let pub64 = match sp_io::crypto::secp256k1_ecdsa_recover(sig_bytes, &hash) {
					Ok(k) => k,
					Err(_) => return false,
				};
				// 3. Derive the Ethereum address: keccak256(pub64)[12..].
				let h160 = pub64_to_eth_address(&pub64);
				// 4. Build AccountId32 = [H160 | 0x00 × 12] and compare.
				let expected =
					AccountId::from(evm_bytes_to_account_id_bytes(*h160.as_fixed_bytes()));
				expected == *signer
			}
		}
	}
}
