//! Pallet types — every struct, newtype and alias defined by the pallet.
//!
//! Split by domain, but re-exported flat so consumers keep reaching them through
//! `crate::types::*` regardless of which module they live in:
//!
//! - [`ids`] — `Commitment`, `Nullifier`, `AssetId`.
//! - [`note`] — the off-chain shielded note.
//! - [`merkle`] — Merkle path plus the tree-depth constants.
//! - [`memo`] — the fixed-size encrypted memo.
//! - [`asset`] — registered asset metadata.
//! - [`proof`] — the serialized proof a call carries.

pub mod asset;
pub mod ids;
pub mod memo;
pub mod merkle;
pub mod note;
pub mod proof;

pub use asset::{AssetMetadata, NATIVE_ASSET_ID};
pub use ids::{AssetId, Commitment, Nullifier};
pub use memo::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE};
pub use merkle::{
	DEFAULT_TREE_DEPTH, DefaultMerklePath, MAX_SUBTREE_ROOTS, MAX_TREE_DEPTH, MerklePath,
	SUBTREE_LEVEL, SubtreeRoots,
};
pub use note::Note;
pub use proof::{MAX_PROOF_SIZE, Proof};

/// A 32-byte hash used for Merkle roots, cryptographic hashes and identifiers.
///
/// Deliberately a bare alias, not a newtype: it names a shape, not a role. The
/// roles that must not be interchanged — commitments and nullifiers — get real
/// newtypes in [`ids`].
pub type Hash = [u8; 32];
