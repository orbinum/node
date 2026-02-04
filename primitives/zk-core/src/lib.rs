//! # Orbinum ZK Core
//!
//! Core cryptographic primitives for Zero-Knowledge proofs in Orbinum Network.
//!
//! This crate provides the fundamental building blocks for ZK-SNARK based private
//! transactions, following Clean Architecture principles with strict separation
//! between domain logic, application use cases, and infrastructure implementations.
//!
//! ## Architecture
//!
//! - **Domain**: Pure business logic with cryptographic primitives
//! - **Application**: Use cases for note creation, commitment computation, etc.
//! - **Infrastructure**: Concrete implementations (Poseidon hasher, repositories)
//!
//! ## Features
//!
//! - `std`: Enable standard library support (default)
//! - `native-poseidon`: Enable native Poseidon host functions for 3x performance boost
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
pub use infrastructure::crypto::poseidon_hasher::LightPoseidonHasher;
pub use infrastructure::repositories::in_memory_merkle_repository::InMemoryMerkleRepository;
