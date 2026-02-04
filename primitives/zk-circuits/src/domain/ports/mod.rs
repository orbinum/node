//! # Ports - Domain Interfaces
//!
//! Defines abstractions for constraint system operations.
//! These are implemented by infrastructure adapters following the Hexagonal Architecture pattern.

pub mod constraint_system;
pub mod hash_gadget;

pub use constraint_system::*;
pub use hash_gadget::*;
