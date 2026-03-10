//! Domain layer - Pure business logic
//!
//! This layer contains:
//! - Entities: Objects with identity (VerificationKey, Proof, Circuit)
//! - Value Objects: Immutable objects (CircuitId, ProofSystem, PublicInputs)
//! - Domain Services: Business logic that doesn't fit in entities
//! - Repository Traits: Interfaces for data access
//! - Domain Errors: Business rule violations
//!
//! Most of this layer is infrastructure-agnostic and no_std compatible.
//! The runtime-facing verification port intentionally uses dispatch errors
//! because it is consumed directly by other pallets.

pub mod entities;
pub mod errors;
pub mod repositories;
pub mod services;
pub mod value_objects;

// Re-export commonly used domain types for internal pallet usage.
pub use entities::{Circuit, Proof, VerificationKey};
pub use errors::DomainError;
pub use repositories::{Statistics, StatisticsRepository, VerificationKeyRepository};
pub use services::{ProofValidator, VkValidator, ZkVerifierPort};
pub use value_objects::{CircuitId, ProofSystem, PublicInputs};
