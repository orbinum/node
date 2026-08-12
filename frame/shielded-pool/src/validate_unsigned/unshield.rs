//! Pool admission for `unshield`.
//!
//! Mirrors [`super::transfer`] step for step, with one extra check: unshield is
//! the only call that moves value OUT of the pool, so it also verifies the pool
//! can cover it.
//!
//! ## Order of checks
//!
//! The steps below are numbered, and the order is the anti-spam property, not a
//! style choice: each step is more expensive than the last, so a junk
//! transaction is rejected as early — and as cheaply — as possible. Steps 1–4
//! are identical to `transfer`; step 5 is unshield's own.
//!
//! | # | Check                | Cost                       |
//! |---|----------------------|----------------------------|
//! | 1 | circuit version      | in-memory lookup           |
//! | 2 | fee floor            | one storage read + compare |
//! | 3 | Merkle root known    | one storage read           |
//! | 4 | nullifier not spent  | one storage read           |
//! | 5 | pool can cover it    | one storage read + add     |
//! | 6 | build the pool tag   | no reads                   |
//!
//! Step 5 is ADVISORY: the balance can move between admission and execution, so
//! the extrinsic re-verifies it. Rejecting here only avoids gossiping a spend
//! the pool visibly cannot cover.
//!
//! Every check here is ALSO re-done in the dispatchable. That is deliberate: a
//! check performed only at admission could be skipped by a malicious block
//! author, so admission may reject more than execution — never less.

use super::{
	TX_LONGEVITY,
	codes::{self, reject},
};
use crate::{
	pallet::{BalanceOf, Config, NullifierSet, PoolBalancePerAsset},
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
const CIRCUIT_UNSHIELD: u32 = 2;

/// Validate an incoming `unshield` unsigned transaction.
///
/// `_relayer` is intentionally unused — see the note in `transfer.rs`: the fee
/// recipient must not enter the pool tag, or a spoofed copy becomes a separate
/// pool entry instead of colliding with the original.
pub fn validate_unshield<T: Config>(
	merkle_root: &Hash,
	nullifier: &Nullifier,
	asset_id: &u32,
	amount: &BalanceOf<T>,
	fee: &BalanceOf<T>,
	_relayer: &Option<sp_core::H160>,
	circuit_version: u32,
) -> TransactionValidity {
	// ── 1. Circuit version ───────────────────────────────────────────────────
	// Cheapest gate first: a transaction proving against a retired circuit can
	// never execute, so it must not reach the pool at all.
	if !T::ZkVerifier::is_supported_version(CIRCUIT_UNSHIELD, circuit_version) {
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

	// ── 4. Nullifier not already spent ───────────────────────────────────────
	// Unlike `transfer`, unshield has exactly one input and no dummy padding —
	// so there is no zero sentinel to skip here.
	if NullifierSet::<T>::contains_key(nullifier) {
		return InvalidTransaction::Stale.into();
	}

	// ── 5. Pool solvency (unshield only) ─────────────────────────────────────
	// `amount + fee` both leave the pool, so both count against its balance.
	// The addition is CHECKED: a wrapping sum would produce a small total that
	// passes the comparison below, admitting a spend the pool cannot cover.
	// Advisory — the balance can move before execution, so the extrinsic checks
	// it again (see the module header).
	let total = amount
		.checked_add(fee)
		.ok_or(reject(codes::AMOUNT_OVERFLOW))?;
	if PoolBalancePerAsset::<T>::get(asset_id) < total {
		return reject(codes::INSUFFICIENT_POOL_BALANCE).into();
	}

	// ── 6. Pool tag — the NULLIFIER ALONE: one note, one pool entry ──────────
	//
	// `relayer` used to be concatenated in, which made a copy differing only in
	// the fee recipient a SEPARATE entry: anyone could rebroadcast someone
	// else's unshield pointed at their own account and have both sit in the pool,
	// racing for a fee the copy never paid for. Keyed on the nullifier the two
	// are mutually exclusive, so taking the fee requires out-bidding — which
	// means actually paying it. Mirrors `transfer.rs`.
	ValidTransaction::with_tag_prefix(super::SPEND_TAG_PREFIX)
		.priority((*fee).saturated_into())
		.longevity(TX_LONGEVITY)
		.and_provides(nullifier)
		.propagate(true)
		.build()
}
