//! RPC domain value objects
//!
//! Value objects are immutable objects identified by their value,
//! not by identity. They represent domain concepts with
//! specific validation rules.

mod block_hash;
mod tree_depth;
mod tree_size;

pub use block_hash::BlockHash;
pub use tree_depth::TreeDepth;
pub use tree_size::TreeSize;
