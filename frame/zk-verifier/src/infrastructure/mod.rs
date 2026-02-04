//! Infrastructure layer - FRAME integration
//!
//! This layer contains:
//! - Adapters: Convert between domain types and primitive types
//! - Repository implementations using FRAME storage
//! - Mappers between domain and storage types
//! - Domain service implementations requiring crypto
//! - Config trait
//!
//! This layer depends on domain and application layers.

pub mod adapters;
pub mod mappers;
pub mod repositories;
pub mod services;
