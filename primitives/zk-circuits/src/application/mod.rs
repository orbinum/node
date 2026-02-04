//! # Application Layer - ZK Circuits
//!
//! High-level circuit compositions and use cases following Clean Architecture.
//! This layer contains:
//! - Circuits: Complete circuit implementations (use cases)
//! - DTOs: Data Transfer Objects for public/private inputs
//!
//! This layer orchestrates domain and infrastructure components.

pub mod circuits;
pub mod dto;

pub use circuits::*;
pub use dto::*;
