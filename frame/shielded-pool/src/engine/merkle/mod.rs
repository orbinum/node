//! Merkle tree — hashing, the incremental structure, and the on-chain service.
//!
//! Split by responsibility so the storage-touching code is separable from the
//! pure maths:
//!
//! - [`hashing`] — Poseidon over field elements, plus the zero-hash ladder.
//! - [`tree`] — `IncrementalMerkleTree`, the in-memory frontier structure.
//! - [`batch`] — whole-tree root computation, off-chain and test use only.
//! - [`service`] — `MerkleTreeService`: leaf insertion, sealing, the
//!   historic-root window, and the sealed-tree node sweep. The only module here
//!   that reads or writes storage.

pub mod batch;
pub mod hashing;
pub mod service;
pub mod tree;

pub use batch::{compute_root_from_leaves, compute_root_from_leaves_poseidon};
pub use hashing::{get_zero_hash_cached, hash_pair, hash_pair_poseidon, zero_hash_at_level};
pub use service::MerkleTreeService;
pub use tree::IncrementalMerkleTree;

/// Most expired historic roots a single leaf insert may prune.
///
/// Pruning is amortised across inserts so one extrinsic never pays for a backlog
/// it did not create: after a long idle stretch the whole queue can be expired
/// at once, and clearing it in one call would be storage work outside the
/// benchmarked weight. Leftovers are cleaned by the following inserts, and an
/// expired entry lingering in the queue is harmless — spendability is decided by
/// the expiry stored per root, never by queue membership.
///
/// Each pruned slot costs at most 2 reads and 2 writes (the queue slot and the
/// map entry), so this bounds the extra work per insert at 8 reads and 8 writes
/// on top of the benchmarked cost.
pub(crate) const MAX_ROOTS_PRUNED_PER_INSERT: usize = 4;
