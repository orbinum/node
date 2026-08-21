//! Pool admission for `private_transfer`.
//!
//! No ZK verification happens here; that is the extrinsic's job. Verifying a
//! proof at admission would let anyone burn a node's CPU for free, since
//! unsigned submissions cost nothing to make.
//!
//! ## Order of checks
//!
//! The steps below are numbered, and the order is the anti-spam property, not a
//! style choice: each step is more expensive than the last, so a junk
//! transaction is rejected as early — and as cheaply — as possible.
//!
//! | # | Check                  | Cost                        |
//! |---|------------------------|-----------------------------|
//! | 1 | circuit version        | in-memory lookup            |
//! | 2 | fee floor              | one storage read + compare  |
//! | 3 | Merkle root known      | one storage read            |
//! | 4 | nullifiers not spent   | up to two storage reads     |
//! | 5 | not all-dummy          | in-memory scan              |
//! | 6 | build the pool tags    | no reads                    |
//!
//! Every check here is ALSO re-done in the dispatchable. That is deliberate: a
//! check performed only at admission could be skipped by a malicious block
//! author, so admission may reject more than execution — never less.

use super::{
	TX_LONGEVITY,
	codes::{self, reject},
};
use crate::{
	pallet::{BalanceOf, Config, NullifierSet},
	storage::MerkleRepository,
	types::{Hash, Nullifier},
};
use frame_support::pallet_prelude::*;
use pallet_relayer::RelayerInterface as _;
use pallet_zk_verifier::ZkVerifierPort as _;
use sp_runtime::{
	SaturatedConversion,
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
};

/// On-chain circuit id for the transfer/unshield version guard (mirrors the
/// zk-verifier's `CircuitId` constants).
const CIRCUIT_TRANSFER: u32 = 1;

/// Validate an incoming `private_transfer` unsigned transaction.
///
/// The fee recipient is absent by construction — it comes from the dispatch
/// origin, not the call — and it must not enter the pool tag either way: binding
/// it once made a copy with a swapped recipient a separate pool entry, so anyone
/// could duplicate an honest transaction at no cost.
pub fn validate_private_transfer<T: Config>(
	merkle_root: &Hash,
	nullifiers: &BoundedVec<Nullifier, ConstU32<2>>,
	fee: &BalanceOf<T>,
	circuit_version: u32,
) -> TransactionValidity {
	// ── 1. Circuit version ───────────────────────────────────────────────────
	// Cheapest gate first: a transaction proving against a retired circuit can
	// never execute, so it must not reach the pool at all.
	if !T::ZkVerifier::is_supported_version(CIRCUIT_TRANSFER, circuit_version) {
		return reject(codes::UNSUPPORTED_CIRCUIT_VERSION).into();
	}

	// ── 2. Fee floor ─────────────────────────────────────────────────────────
	// The pool's price of entry. Submissions are unsigned and gasless, so this
	// is what stops an attacker from filling it for nothing.
	let min_fee: BalanceOf<T> = T::Relayer::min_relay_fee().saturated_into();
	if *fee < min_fee {
		return InvalidTransaction::Payment.into();
	}

	// ── 3. Merkle root ───────────────────────────────────────────────────────
	// An unknown root cannot verify, and the retention window is sized to
	// outlive `TX_LONGEVITY` so a root accepted here stays valid until the
	// transaction expires.
	if !MerkleRepository::is_known_root::<T>(merkle_root) {
		return reject(codes::UNKNOWN_ROOT).into();
	}

	// ── 4. Nullifiers not already spent ──────────────────────────────────────
	// The dummy nullifier (all zeros) pads a single-input spend. It is never
	// inserted into the set, so it can never be stale — skipping it is required,
	// not an optimisation: treating it as spent would reject every one-input
	// transfer after the first.
	for nullifier in nullifiers.iter() {
		if nullifier.0 == [0u8; 32] {
			continue;
		}
		if NullifierSet::<T>::contains_key(nullifier) {
			return InvalidTransaction::Stale.into();
		}
	}

	// ── 5. At least one real input ───────────────────────────────────────────
	// All-dummy means no note is being spent, so the transfer would insert two
	// commitments at zero cost — free Merkle tree growth.
	if nullifiers.iter().all(|n| n.0 == [0u8; 32]) {
		return reject(codes::ALL_INPUTS_DUMMY).into();
	}

	// ── 6. Pool tags — ONE PER NULLIFIER, never one over the whole set ───────
	//
	// `and_provides(x)` contributes exactly ONE tag: passing a `Vec<Vec<u8>>`
	// encodes the entire vector into one blob. Doing that made the tag depend on
	// the ORDER of the inputs and on the OTHER note in the pair, so:
	//   - reordering the two inputs minted a second admissible entry for the
	//     same spend, and
	//   - two transfers sharing only one note (A+B and A+C) did not collide at
	//     all, letting one note back an unbounded number of pool entries.
	// Since the fee is only charged on execution, that was free mempool
	// amplification: every variant propagates and is revalidated network-wide
	// while at most one can ever execute.
	//
	// Calling `and_provides` once PER nullifier makes any two transactions that
	// share a note mutually exclusive, in any order — which is what makes the
	// pool mirror the on-chain nullifier set.
	//
	// Dummy nullifiers (zero) are excluded: they carry no identity, and tagging
	// them would collide every padded single-input spend with every other.
	let mut builder = ValidTransaction::with_tag_prefix(super::SPEND_TAG_PREFIX)
		.priority((*fee).saturated_into())
		.longevity(TX_LONGEVITY)
		.propagate(true);

	for nullifier in nullifiers.iter().filter(|n| n.0 != [0u8; 32]) {
		builder = builder.and_provides(nullifier);
	}

	builder.build()
}
