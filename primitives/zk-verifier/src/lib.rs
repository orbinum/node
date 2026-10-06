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

mod circuits;
mod snarkjs;
mod types;
mod verifier;

// ─── Type aliases ─────────────────────────────────────────────────────────────

pub type Bn254Fr = ark_bn254::Fr;
pub use ark_bn254::Bn254;
pub use ark_groth16::PreparedVerifyingKey;

// ─── Public API ───────────────────────────────────────────────────────────────

pub use circuits::{
	expected_public_inputs, has_memo_layout, input_layout, InputLayout, CIRCUIT_ID_SHIELD,
	CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, MEMO_HASH_INPUTS, SHIELD_PUBLIC_INPUTS,
	TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS,
};
pub use snarkjs::SnarkjsProofPoints;
#[cfg(feature = "std")]
pub use snarkjs::{parse_proof_from_snarkjs, parse_public_inputs_from_snarkjs};
pub use types::{
	to_field_le, Proof, PublicInputs, VerifierError, VerifyingKey, BASE_VERIFICATION_COST,
	MAX_PUBLIC_INPUTS, MAX_VK_BYTES, PER_INPUT_COST,
};
pub use verifier::Groth16Verifier;
