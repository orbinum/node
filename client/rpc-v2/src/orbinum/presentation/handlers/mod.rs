//! Handlers - Endpoint-specific logic
//!
//! Each handler manages one RPC endpoint:
//! - Input validation
//! - Delegation to the corresponding service
//! - Mapping domain entities to DTOs
//! - Error handling

mod merkle_proof_handler;
mod merkle_root_handler;
mod nullifier_status_handler;
mod pool_stats_handler;

pub use merkle_proof_handler::MerkleProofHandler;
pub use merkle_root_handler::MerkleRootHandler;
pub use nullifier_status_handler::NullifierStatusHandler;
pub use pool_stats_handler::PoolStatsHandler;
