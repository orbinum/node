//! `OrbinumSignature`: the runtime's extrinsic signature.
//!
//! | Tag  | Variant              | Signs                              | Account                   |
//! |------|----------------------|------------------------------------|---------------------------|
//! | 0x00 | `Ed25519`            | never verifies                     | —                         |
//! | 0x01 | `Sr25519`            | `msg`                              | raw key                   |
//! | 0x02 | `Ecdsa`              | never verifies                     | —                         |
//! | 0x03 | `Ed25519Text`        | `text_message` of the payload      | raw key                   |
//! | 0x04 | `Ed25519WrappedText` | `wrapped_text_message` of it       | raw key                   |
//! | 0x05 | `EcdsaText`          | keccak256 of `eip191_text_message` | `[eth_address ‖ 0x00×12]` |
//!
//! `msg` is what `Verify::verify` receives: the signing payload, or its blake2_256 when
//! longer than 256 bytes. `eth_address` is `keccak256(pubkey)[12..]`; the account matches
//! `EeSuffixAddressMapping`, so one secp256k1 key is the same account on the EVM and
//! Substrate paths. 0x00–0x02 keep `sp_runtime::MultiSignature`'s wire format.
//!
//! The text variants (0x03–0x05) sign text that names an Orbinum transaction, rendered
//! from the whole payload ([`text`]), and are checked through
//! `fp_self_contained::VerifyFullPayload`, never through `Verify`. Ed25519 keys sign only
//! such text: Solana wallets sign arbitrary bytes through `signMessage`, so a raw signature
//! given for a "login nonce" could be a payload's blake2_256. `Ed25519Text` covers wallets
//! that sign text as given (Phantom, Solflare, Backpack…), `Ed25519WrappedText` Substrate
//! extensions' `signRaw`. `EcdsaText` is the same text signed by an EVM wallet with
//! `personal_sign` (EIP-191). secp256k1 keys sign only such text too: a wallet, MPC or
//! KMS that signs a raw 32-byte digest could be handed a payload's blake2_256.
//!
//! `Ed25519` and `Ecdsa` stay in the type only because polkadot-api builds no extrinsic
//! for a signature enum without `Ed25519`, `Sr25519` and `Ecdsa`.
//!
//! Each variant accepts a single encoding per signature and refuses keys that verify
//! forged signatures: small-order ed25519 keys, the sr25519 identity key, and ECDSA
//! signatures with a high `s` or an aliased recovery id.

mod keys;
#[cfg(test)]
mod tests;
mod text;

pub use keys::signer::OrbinumSigner;
#[cfg(test)]
pub use text::{eip191_text_message, text_message, text_signable, wrapped_text_message};

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
	/// Refused: see the module doc.
	#[codec(index = 2)]
	Ecdsa(sp_core::ecdsa::Signature),
	#[codec(index = 3)]
	Ed25519Text(sp_core::ed25519::Signature),
	#[codec(index = 4)]
	Ed25519WrappedText(sp_core::ed25519::Signature),
	#[codec(index = 5)]
	EcdsaText(sp_core::ecdsa::Signature),
}

impl Verify for OrbinumSignature {
	type Signer = OrbinumSigner;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId) -> bool {
		let key: &[u8; 32] = signer.as_ref();
		match self {
			Self::Ed25519(_) | Self::Ecdsa(_) => false,
			Self::Sr25519(sig) => keys::sr25519::verify(sig, msg.get(), key),
			// Whole payload only (`VerifyFullPayload`): `msg` may be a blake2_256, which
			// renders no transaction a person can read.
			Self::Ed25519Text(_) | Self::Ed25519WrappedText(_) | Self::EcdsaText(_) => false,
		}
	}
}

impl fp_self_contained::VerifyFullPayload<AccountId> for OrbinumSignature {
	fn covers_full_payload(&self) -> bool {
		matches!(
			self,
			Self::Ed25519Text(_) | Self::Ed25519WrappedText(_) | Self::EcdsaText(_)
		)
	}

	fn verify_full_payload(&self, payload: &[u8], signer: &AccountId) -> bool {
		let key: &[u8; 32] = signer.as_ref();
		match self {
			Self::Ed25519Text(sig) => text::verify(sig, payload, key),
			Self::Ed25519WrappedText(sig) => text::verify_wrapped(sig, payload, key),
			Self::EcdsaText(sig) => text::verify_ecdsa(sig, payload, signer),
			_ => false,
		}
	}
}
