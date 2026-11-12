// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

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

/// Most expired historic roots one leaf insert may prune, across the roots it
/// records (retired, new and, on a seal, empty).
///
/// Pruning is amortised so an insert never pays for a backlog it did not create;
/// leftovers go with later inserts, and a lingering expired entry is harmless:
/// spendability reads each root's stored expiry, not the queue.
///
/// Each pruned or evicted slot costs 2 reads and 2 writes, so at most 8 and 8 per
/// insert, plus one read per drain that stops at a live slot. The insert
/// benchmarks start from an expired backlog to measure it; a seal's few constant
/// writes are not measured.
pub(crate) const MAX_ROOTS_PRUNED_PER_INSERT: usize = 4;
