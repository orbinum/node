//! # Orbinum Signature RuntimeAPI
//!
//! Defines the `SignatureApi` trait so clients can query which signature types
//! the runtime supports and validate signatures without executing extrinsics.
//!
//! ## Usage from TypeScript (polkadot.js)
//!
//! ```typescript
//! // Available types
//! const types = await api.call.signatureApi.getSupportedSignatureTypes();
//!
//! // Validate a signature
//! const valid = await api.call.signatureApi.validateSignature(sig, msg, signer);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;

/// Signature variants supported by the Orbinum runtime.
///
/// - `Sr25519`: native Substrate signature (recommended for Substrate accounts)
/// - `Ed25519`: ed25519 signature (legacy, supported for compatibility)
/// - `Ecdsa`: ECDSA signature with 33-byte compressed public key (Ethereum-compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum SignatureType {
	/// Native Substrate signature: 32-byte public key, 64-byte signature.
	Sr25519 = 0,
	/// Ed25519 signature: 32-byte public key, 64-byte signature.
	Ed25519 = 1,
	/// Substrate ECDSA signature: 33-byte compressed public key, 65-byte signature.
	Ecdsa = 2,
}

sp_api::decl_runtime_apis! {
	/// Runtime API for querying and validating MultiSignature signatures.
	///
	/// This API allows clients to:
	/// 1. Discover which signature types the runtime accepts.
	/// 2. Validate a signature without building or submitting an extrinsic.
	pub trait SignatureApi {
		/// Returns the signature types supported by this runtime.
		///
		/// The order indicates preference: the first entry is the recommended
		/// type for Substrate-native accounts.
		fn get_supported_signature_types() -> Vec<SignatureType>;

		/// Validates a `MultiSignature` against a message and an `AccountId32`.
		///
		/// Returns `true` if the signature is cryptographically valid for the
		/// given `signer`. Does not modify state or consume fees.
		///
		/// # Parameters
		/// - `signature`: the signature serialized as SCALE-encoded `MultiSignature`
		/// - `message`: the original message (raw bytes, no prefix)
		/// - `signer`: the expected signer's `AccountId32`
		fn validate_signature(
			signature: sp_runtime::MultiSignature,
			message: Vec<u8>,
			signer: sp_core::crypto::AccountId32,
		) -> bool;
	}
}
