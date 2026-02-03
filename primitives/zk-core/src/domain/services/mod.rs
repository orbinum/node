//! # Domain Services
//!
//! Domain services following Domain-Driven Design principles.
//!

//! Services that encapsulate domain logic that doesn't naturally fit
//! into a value object or entity.
//!
//! Characteristics:
//! - **Stateless**: Don't maintain state between calls
//! - **Operation-focused**: Named after domain activities
//! - **Coordinate value objects**: Orchestrate interactions between VOs
//!

//! Domain services depend only on:
//! - Domain value objects
//! - Domain ports (interfaces)
//! - NO infrastructure implementations
//!

//! - `commitment_service`: Create note commitments
//! - `nullifier_service`: Compute nullifiers for spending
//! - `merkle_service`: Merkle tree operations and proofs

pub mod commitment_service;
pub mod merkle_service;
pub mod nullifier_service;

pub use commitment_service::CommitmentService;
pub use merkle_service::MerkleService;
pub use nullifier_service::NullifierService;
