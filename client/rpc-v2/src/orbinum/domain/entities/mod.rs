//! RPC domain entities
//!
//! These entities are specific to the RPC domain and differ from
//! pallet entities. For shared entities (`Commitment`, `Nullifier`),
//! we reuse the ones from `pallet-shielded-pool`.

mod merkle_proof_path;
mod pool_statistics;

pub use merkle_proof_path::MerkleProofPath;
pub use pool_statistics::PoolStatistics;
