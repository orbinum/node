//! # Domain Layer - ZK Circuits
//!
//! Core abstractions for constraint system operations following DDD principles.
//! This layer contains:
//! - Value Objects: Immutable domain primitives
//! - Services: Pure business logic
//! - Ports: Abstract interfaces for infrastructure
//!
//! This layer is independent of specific R1CS implementations.

pub mod ports;
pub mod services;
pub mod value_objects;

pub use services::*;
pub use value_objects::*;
