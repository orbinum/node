//! Domain Repositories (Ports)
//!
//! This module defines repository ports (interfaces) following Clean Architecture.
//! These are abstractions that the domain layer uses to interact with persistence,
//! without depending on concrete implementations.
//!

//! Repositories are **Ports** in the hexagonal architecture pattern:
//! - Domain layer defines the interface (what operations are needed)
//! - Infrastructure layer provides implementations (how operations are done)
//! - Follows Dependency Inversion Principle (depend on abstractions)

mod merkle_repository;

pub use merkle_repository::{MerklePath, MerkleRepository, RepositoryError, RepositoryResult};
