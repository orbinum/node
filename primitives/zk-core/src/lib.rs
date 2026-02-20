//! # Orbinum ZK Core
//!
//! Poseidon-based cryptographic primitives for Zero-Knowledge proofs in Orbinum Network.
//!
//! This crate provides ZK-SNARK foundations using Poseidon hash functions for optimal
//! circuit efficiency and compatibility with circomlib. Follows Clean Architecture
//! principles with strict separation between domain logic, application use cases,
//! and infrastructure implementations.
//!
//! ## Architecture
//!
//! - **Domain**: Pure business logic with Poseidon-based cryptographic primitives
//! - **Application**: Use cases for note creation, commitment computation, nullifiers
//! - **Infrastructure**: Concrete Poseidon implementations and storage adapters
//!
//! ## Features
//!
//! - `std`: Enable standard library support (default)
//! - `poseidon-native`: Enable native Poseidon host functions for 3x performance boost (default)
//! - `native-poseidon`: Legacy alias for `poseidon-native` (deprecated)
//!
//! ## Hash Functions
//!
//! **Poseidon Only**: This crate exclusively uses Poseidon hash functions for all
//! cryptographic operations, ensuring ZK-circuit compatibility and optimal proof generation.
//!
//! ## No-std Support
//!
//! This crate is `no_std` compatible by default, using `alloc` for heap allocations.
//! Enable the `std` feature for standard library support.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod application;
pub mod domain;
pub mod infrastructure;

// Re-export commonly used types
pub use domain::{
	entities::note::Note,
	value_objects::{
		blinding::Blinding, commitment::Commitment, field_element::FieldElement,
		nullifier::Nullifier, owner_pubkey::OwnerPubkey, spending_key::SpendingKey,
	},
};

pub use application::{
	dto::{merkle_proof_dto::MerkleProofDto, note_dto::NoteDto},
	use_cases::{
		compute_commitment::ComputeCommitmentUseCase, compute_nullifier::ComputeNullifierUseCase,
		create_note::CreateNoteUseCase, verify_merkle_proof::VerifyMerkleProofUseCase,
	},
};

// Re-export infrastructure implementations
pub use infrastructure::crypto::poseidon_hash_1::poseidon_hash_1;
pub use infrastructure::crypto::poseidon_hasher::LightPoseidonHasher;

#[cfg(feature = "poseidon-native")]
pub use infrastructure::crypto::native_poseidon_hasher::NativePoseidonHasher;

pub use infrastructure::repositories::in_memory_merkle_repository::InMemoryMerkleRepository;
