//! # Domain Layer
//!
//! Core business logic following Domain-Driven Design principles.
//!

//! The domain layer is the **innermost circle** and has:
//! - ✅ Zero dependencies on infrastructure
//! - ✅ Zero dependencies on frameworks
//! - ✅ Pure business logic only
//!

//! - `value_objects/`: Immutable value objects (Commitment, Nullifier, etc.) ✅
//! - `entities/`: Aggregates and entities (Note) ✅
//! - `services/`: Domain services (CommitmentService, etc.) ✅
//! - `ports/`: Port interfaces for infrastructure (PoseidonHasher) ✅
//! - `repositories/`: Repository ports (interfaces) ✅
//! - `constants/`: Domain-level business rules and constraints ✅
//!

//! Domain can only depend on:
//! - Standard library (core, alloc)
//! - External pure math libraries (arkworks)
//! - NO infrastructure, NO application layer

pub mod constants;
pub mod entities;
pub mod ports;
pub mod repositories;
pub mod services;
pub mod value_objects;
