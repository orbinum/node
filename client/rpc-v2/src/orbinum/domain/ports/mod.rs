//! Ports - Interfaces for external services (Hexagonal Architecture)
//!
//! Ports define contracts implemented by infrastructure-layer
//! adapters. This decouples the domain from implementation details
//! (Substrate, storage, etc.).

mod blockchain_query;
mod merkle_tree_query;
mod nullifier_query;
mod pool_query;

pub use blockchain_query::BlockchainQuery;
pub use merkle_tree_query::MerkleTreeQuery;
pub use nullifier_query::NullifierQuery;
pub use pool_query::{PoolBalance, PoolQuery};
