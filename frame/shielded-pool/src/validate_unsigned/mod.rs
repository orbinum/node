//! Unsigned transaction validation for `private_transfer` and `unshield`.
//!
//! Cheap checks first, the proof last. The proof IS verified at admission:
//! without it, a copy of a pending spend with swapped memos or a higher fee
//! would share the original's nullifier tag, outrank it on priority, replace it
//! and then fail in the block — free, repeatable censorship — and junk spends
//! would fill blocks for nothing. The price is node CPU per admission and
//! revalidation; a peer that sends invalid proofs loses reputation for it.
//! Inside a block (`pre_dispatch`) only the cheap checks run: the dispatchable
//! verifies the proof, and its weight covers one pairing.
//!
//! Every check here is also re-done in the dispatchable. That is deliberate: a
//! check performed only at admission could be skipped by a malicious block
//! author, so admission may reject more than execution but never less.
//!
//! - [`codes`] — named pool-rejection codes shared by both validators.
//! - [`transfer`] — admission for `private_transfer`.
//! - [`unshield`] — admission for `unshield`.

pub mod codes;
pub mod transfer;
pub mod unshield;

pub use transfer::validate_private_transfer;
pub use unshield::validate_unshield;

/// How long an unsigned transaction stays valid in the pool, in blocks. Bounded
/// so a transaction that never gets included does not linger indefinitely.
///
/// `Config::RootRetentionBlocks` must exceed this (checked in `integrity_test`):
/// a root has to outlive every transaction admitted against it, or a spend can
/// pass admission, propagate, and only then revert with `UnknownMerkleRoot`.
pub(crate) const TX_LONGEVITY: u64 = 64;

/// ONE tag namespace for every operation that spends a note.
///
/// A nullifier identifies a NOTE, not an operation, and the on-chain rule is
/// simply "each note is spent once" — whether by a transfer or an unshield.
/// With a prefix per operation, the same note could back one of each in the
/// pool at the same time: both propagate and get revalidated network-wide, only
/// one can ever execute. Sharing the namespace makes pool admission mirror the
/// chain: one note, one entry.
pub(crate) const SPEND_TAG_PREFIX: &str = "ShieldedPoolSpend";

#[cfg(test)]
mod tests;
