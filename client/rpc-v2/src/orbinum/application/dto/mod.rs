//! DTOs (Data Transfer Objects) - Mapping between layers
//!
//! DTOs are used to:
//! - Decouple domain entities from the presentation layer
//! - Support JSON-RPC serialization/deserialization
//! - Enable API versioning without changing the domain layer

mod merkle_proof_response;
mod nullifier_status_response;
mod pool_stats_response;

pub use merkle_proof_response::MerkleProofResponse;
pub use nullifier_status_response::NullifierStatusResponse;
pub use pool_stats_response::PoolStatsResponse;
