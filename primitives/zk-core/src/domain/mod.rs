//! Domain Layer
//!
//! Core business logic following Clean Architecture principles.
//!
//! Contains pure domain logic with zero infrastructure dependencies:
//! - `value_objects/`: Immutable value objects (Commitment, Nullifier, etc.)
//! - `entities/`: Domain entities (Note)
//! - `services/`: Domain services (CommitmentService, MerkleService, etc.)
//! - `ports/`: Port interfaces (PoseidonHasher)
//! - `repositories/`: Repository ports
//! - `constants/`: Domain constants

pub mod constants;
pub mod entities;
pub mod ports;
pub mod repositories;
pub mod services;
pub mod value_objects;
