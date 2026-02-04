//! Domain layer - Pure business logic
//!
//! This layer contains:
//! - Entities: Objects with identity (VerificationKey, Proof, Circuit)
//! - Value Objects: Immutable objects (CircuitId, ProofSystem, PublicInputs)
//! - Domain Services: Business logic that doesn't fit in entities
//! - Repository Traits: Interfaces for data access
//! - Domain Errors: Business rule violations
//!
//! The domain layer is completely independent of FRAME and infrastructure.
//! It contains pure Rust code with no_std compatibility.

pub mod entities;
pub mod errors;
pub mod repositories;
pub mod services;
pub mod value_objects;

// Re-export commonly used domain types (para uso interno del pallet)
pub use entities::{Circuit, Proof, VerificationKey};
pub use errors::DomainError;
pub use repositories::{Statistics, StatisticsRepository, VerificationKeyRepository};
pub use services::{ProofValidator, VkValidator, ZkVerifierPort};
pub use value_objects::{CircuitId, ProofSystem, PublicInputs};
