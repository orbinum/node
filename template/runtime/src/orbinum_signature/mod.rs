//! `OrbinumSignature`: the runtime's extrinsic signature.
//!
//! | Discriminant | Variant              | Signed bytes                       | Account                               |
//! |:---:|----------------------|------------------------------------|---------------------------------------|
//! | 0x00 | `Ed25519`            | never verifies                     | —                                     |
//! | 0x01 | `Sr25519`            | `msg`                              | raw key                               |
//! | 0x02 | `Ecdsa`              | `blake2_256(msg)`                  | `[keccak256(pubkey)[12..] ‖ 0x00×12]` |
//! | 0x03 | `Ed25519Text`        | [`text_message`] of `msg`          | raw key                               |
//! | 0x04 | `Ed25519WrappedText` | [`wrapped_text_message`] of `msg`  | raw key                               |
//!
//! `msg` is what `Verify::verify` receives: the signing payload, or its blake2_256 when
//! longer than 256 bytes. 0x01–0x02 keep `sp_runtime::MultiSignature`'s wire format. The
//! ECDSA account matches `EeSuffixAddressMapping`, so one secp256k1 key is the same
//! account on the EVM and Substrate paths.
//!
//! Ed25519 keys sign only text that names an Orbinum transaction. A raw ed25519 signature
//! over `msg` (`Ed25519`) is never accepted: Solana wallets sign arbitrary bytes through `signMessage`,
//! so a signature they give for a "login nonce" could be a payload's blake2_256.
//! `Ed25519Text` covers wallets that sign text as given (Phantom, MetaMask, Backpack…),
//! `Ed25519WrappedText` Substrate extensions' `signRaw`. `Ed25519` stays in the type only
//! because clients read it from the metadata: polkadot-api refuses to build any extrinsic
//! for a signature enum without `Ed25519`, `Sr25519` and `Ecdsa`.
//!
//! Each variant accepts a single encoding per signature and refuses keys that verify
//! forged signatures: small-order ed25519 keys, the sr25519 identity key, and ECDSA
//! signatures with a high `s` or an aliased recovery id.

mod ecdsa;
mod ed25519;
mod signer;
mod sr25519;
mod text;

pub use signer::OrbinumSigner;
#[cfg(test)]
pub use text::{text_message, wrapped_text_message, TEXT_MESSAGE_LEN, WRAPPED_TEXT_MESSAGE_LEN};

use crate::AccountId;
use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::traits::{Lazy, Verify};

/// Indices are wire format: never reuse one.
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
	/// Refused: see the module doc.
	#[codec(index = 0)]
	Ed25519(sp_core::ed25519::Signature),
	#[codec(index = 1)]
	Sr25519(sp_core::sr25519::Signature),
	#[codec(index = 2)]
	Ecdsa(sp_core::ecdsa::Signature),
	#[codec(index = 3)]
	Ed25519Text(sp_core::ed25519::Signature),
	#[codec(index = 4)]
	Ed25519WrappedText(sp_core::ed25519::Signature),
}

impl Verify for OrbinumSignature {
	type Signer = OrbinumSigner;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId) -> bool {
		let key: &[u8; 32] = signer.as_ref();
		match self {
			Self::Ed25519(_) => false,
			Self::Sr25519(sig) => sr25519::verify(sig, msg.get(), key),
			Self::Ecdsa(sig) => ecdsa::verify(sig, msg.get(), signer),
			Self::Ed25519Text(sig) => text::verify(sig, msg.get(), key),
			Self::Ed25519WrappedText(sig) => text::verify_wrapped(sig, msg.get(), key),
		}
	}
}
