//! `OrbinumSigner`: the public key behind an `OrbinumSignature`, and its account.

use crate::AccountId;
use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::{ecdsa, ed25519, sr25519};
use sp_runtime::{traits::IdentifyAccount, MultiSigner};

/// Variant order matches `sp_runtime::MultiSigner`.
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
	/// Account `[eth_address ‖ 0x00 × 12]`, not `MultiSigner`'s `blake2_256(key)`.
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
			Self::Ed25519(k) => MultiSigner::Ed25519(k).into_account(),
			Self::Sr25519(k) => MultiSigner::Sr25519(k).into_account(),
			Self::Ecdsa(k) => {
				use libsecp256k1::{PublicKey, PublicKeyFormat};
				match PublicKey::parse_slice(k.as_ref(), Some(PublicKeyFormat::Compressed)) {
					Ok(pk) => {
						let mut pub64 = [0u8; 64];
						pub64.copy_from_slice(&pk.serialize()[1..]);
						super::ecdsa::account_from_pubkey(&pub64)
					}
					// No ECDSA signature recovers an invalid key, so this account never verifies.
					Err(_) => MultiSigner::Ecdsa(k).into_account(),
				}
			}
		}
	}
}
