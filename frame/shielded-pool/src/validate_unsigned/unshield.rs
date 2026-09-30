//! Pool admission for `unshield`.
//!
//! | # | Check                  | Cost                              |
//! |---|------------------------|-----------------------------------|
//! | 1 | circuit version        | in-memory lookup                  |
//! | 2 | dispatch checks        | `validate`, cheapest first        |
//! | 3 | proof verifies         | one pairing (pool only)           |
//! | 4 | build the pool tag     | no reads                          |
//!
//! Step 2 IS the dispatchable's validation, so admission can never reject less
//! than execution. Its pool-solvency check is advisory here: the balance can
//! move before execution, which checks it again. Rejecting early only avoids
//! gossiping a spend the pool visibly cannot cover.

use super::{
	TX_LONGEVITY,
	codes::{self, reject},
};
use crate::{
	operations::{
		ensure_valid_proof,
		unshield::{UnshieldOperation, UnshieldRequest},
	},
	pallet::{Config, Error},
};
use pallet_zk_verifier::{CircuitId, ZkVerifierPort as _};
use sp_runtime::{
	SaturatedConversion,
	traits::Zero,
	transaction_validity::{
		InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
	},
};

/// Validate an incoming `unshield` unsigned transaction.
///
/// `proof` is `Some` at pool admission and `None` in `pre_dispatch`, where the
/// dispatchable verifies it and a second pairing would go unweighed.
pub fn validate_unshield<T: Config>(
	proof: Option<&[u8]>,
	req: &UnshieldRequest<T>,
) -> TransactionValidity {
	// ── 1. Circuit version ───────────────────────────────────────────────────
	if !T::ZkVerifier::is_supported_version(CircuitId::UNSHIELD.0, req.circuit_version) {
		return reject(codes::UNSUPPORTED_CIRCUIT_VERSION).into();
	}

	// ── 2. Everything the dispatchable checks ────────────────────────────────
	UnshieldOperation::validate::<T>(req).map_err(|e| admission_error(e, req))?;

	// ── 3. Proof ─────────────────────────────────────────────────────────────
	// Without it, a copy of a pending spend with swapped memos or a higher fee
	// would share the nullifier tag, outrank the original on priority, replace
	// it, and then fail in the block — free, repeatable censorship. An invalid
	// proof from a peer also costs that peer reputation.
	if let Some(proof) = proof {
		let valid = req.statement().is_ok_and(|statement| {
			ensure_valid_proof::<T>(|| {
				T::ZkVerifier::verify_unshield_proof(proof, &statement, Some(req.circuit_version))
			})
			.is_ok()
		});
		if !valid {
			return reject(codes::INVALID_PROOF).into();
		}
	}

	// ── 4. Pool tag: the nullifier alone (one note, one pool entry) ──────────
	//
	// Every copy of a spend is mutually exclusive in the pool, whatever else it
	// changes; with the proof checked, only a valid one gets in. Mirrors
	// `transfer.rs`.
	ValidTransaction::with_tag_prefix(super::SPEND_TAG_PREFIX)
		.priority(req.fee.saturated_into())
		.longevity(TX_LONGEVITY)
		.and_provides(req.nullifier)
		.propagate(true)
		.build()
}

/// The pool rejection for a failed unshield check.
fn admission_error<T: Config>(
	error: Error<T>,
	req: &UnshieldRequest<T>,
) -> TransactionValidityError {
	match error {
		// The pool's price of entry: submissions are unsigned and gasless.
		Error::FeeTooLow => InvalidTransaction::Payment.into(),
		Error::UnknownMerkleRoot => reject(codes::UNKNOWN_ROOT).into(),
		Error::NullifierAlreadyUsed => InvalidTransaction::Stale.into(),
		// `validate` refuses a zero amount before summing, so with a non-zero
		// amount this is `amount + fee` overflowing.
		Error::InvalidAmount if !req.amount.is_zero() => reject(codes::AMOUNT_OVERFLOW).into(),
		Error::InsufficientPoolBalance => reject(codes::INSUFFICIENT_POOL_BALANCE).into(),
		Error::InvalidMemoSize => reject(codes::INVALID_MEMO).into(),
		_ => reject(codes::INVALID_SPEND).into(),
	}
}
