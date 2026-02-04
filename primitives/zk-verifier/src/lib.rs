//! # orbinum-zk-verifier
//!
//! Groth16 proof verification for Substrate runtime.
//!
//! ## Example
//!
//! ```rust,ignore
//! use orbinum_zk_verifier::{
//!     application::use_cases::VerifyProofUseCase,
//!     infrastructure::verification::Groth16Verifier,
//!     domain::value_objects::{Proof, PublicInputs, VerifyingKey},
//! };
//!
//! let verifier = Groth16Verifier::new();
//! let use_case = VerifyProofUseCase::new(verifier);
//! let result = use_case.execute(&vk, &public_inputs, &proof, expected_inputs);
//! ```
//!

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// Type Aliases
pub type Bn254Fr = ark_bn254::Fr;
pub use ark_bn254::Bn254;

// Clean Architecture Layers
pub mod application;
pub mod domain;
pub mod infrastructure;
