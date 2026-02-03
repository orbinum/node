//! # Domain Ports
//!
//! Ports (interfaces) following Clean Architecture.
//!

//! Ports are interfaces defined by the domain layer that specify
//! what the domain needs from the infrastructure layer.
//!
//! Benefits:
//! - Domain remains independent of infrastructure
//! - Easy to test with mocks
//! - Easy to swap implementations
//!

//! - `hasher`: Poseidon hash function interface

pub mod hasher;

pub use hasher::PoseidonHasher;
