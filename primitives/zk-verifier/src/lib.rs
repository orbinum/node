//! # orbinum-zk-verifier
//!
//! Groth16 proof verification for Substrate runtime (BN254 curve).
//!
//! ## Example
//!
//! ```rust,ignore
//! use orbinum_zk_verifier::{Groth16Verifier, Proof, PublicInputs, VerifyingKey};
//!
//! let result = Groth16Verifier::verify(&vk, &public_inputs, &proof);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod field_utils;
mod snarkjs;
mod types;
mod verifier;

// ─── Type aliases ─────────────────────────────────────────────────────────────

pub type Bn254Fr = ark_bn254::Fr;
pub use ark_bn254::Bn254;

// ─── Public API ───────────────────────────────────────────────────────────────

pub use field_utils::{bytes_to_field, field_to_bytes, field_to_u64, u64_to_field};
pub use snarkjs::SnarkjsProofPoints;
#[cfg(feature = "std")]
pub use snarkjs::{parse_proof_from_snarkjs, parse_public_inputs_from_snarkjs};
pub use types::{
	Proof, PublicInputs, VerifierError, VerifyingKey, BASE_VERIFICATION_COST,
	CIRCUIT_ID_PRIVATE_LINK, CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, CIRCUIT_ID_VALUE_PROOF,
	MAX_PUBLIC_INPUTS, PER_INPUT_COST, PRIVATE_LINK_PUBLIC_INPUTS, TRANSFER_PUBLIC_INPUTS,
	UNSHIELD_PUBLIC_INPUTS, VALUE_PROOF_PUBLIC_INPUTS,
};
pub use verifier::Groth16Verifier;
