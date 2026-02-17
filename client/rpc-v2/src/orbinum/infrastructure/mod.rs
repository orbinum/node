//! Infrastructure layer - Adapters and technical details
//!
//! This layer implements domain ports with concrete technologies:
//! - Substrate/FRAME adapters
//! - Mappers for type conversions
//! - Storage keys for runtime storage access
//!
//! This layer DOES depend on FRAME and Substrate.

pub mod adapters;
pub mod mappers;
pub mod storage;

// Adapter re-exports
pub use adapters::SubstrateStorageAdapter;

// Mapper re-exports
pub use mappers::{CommitmentMapper, DomainMapper};
