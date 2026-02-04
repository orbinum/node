//! # Application Layer - ZK Verifier
//!
//! High-level use cases and DTOs following Clean Architecture.
//! This layer orchestrates domain and infrastructure components.

pub mod dto;
pub mod use_cases;

pub use dto::*;
pub use use_cases::*;
