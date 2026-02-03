//! Application Use Cases
//!
//! This module contains all use cases (application business logic) following
//! Clean Architecture principles.
//!

//! Use cases are part of the **Application Layer** (middle circle):
//! - Orchestrate domain objects to fulfill user intentions
//! - Depend on domain layer (entities, value objects, services, ports)
//! - Independent of infrastructure (databases, frameworks, UI)

//!

//! Each use case follows a consistent structure:
//! - **Input**: Data required to execute the use case
//! - **Output**: Result of the use case execution
//! - **Execute**: Main method that orchestrates domain objects
//! - **Error**: Application-specific errors
//!

//! - `CreateNote`: Create a new note entity
//! - `ComputeCommitment`: Compute commitment for a note
//! - `ComputeNullifier`: Compute nullifier for spending a note
//! - `VerifyMerkleProof`: Verify a Merkle proof

mod compute_commitment;
mod compute_nullifier;
mod create_note;
mod verify_merkle_proof;

pub use compute_commitment::{
	ComputeCommitmentError, ComputeCommitmentInput, ComputeCommitmentOutput,
	ComputeCommitmentResult, ComputeCommitmentUseCase,
};
pub use compute_nullifier::{
	ComputeNullifierError, ComputeNullifierInput, ComputeNullifierOutput, ComputeNullifierResult,
	ComputeNullifierUseCase,
};
pub use create_note::{
	CreateNoteError, CreateNoteInput, CreateNoteOutput, CreateNoteResult, CreateNoteUseCase,
};
pub use verify_merkle_proof::{
	VerifyMerkleProofError, VerifyMerkleProofInput, VerifyMerkleProofOutput,
	VerifyMerkleProofResult, VerifyMerkleProofUseCase,
};
