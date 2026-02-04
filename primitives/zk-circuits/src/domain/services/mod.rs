//! # Domain Services
//!
//! Pure business logic for circuit operations.
//! Services coordinate between value objects and maintain invariants.

pub mod circuit_validator;

pub use circuit_validator::*;
