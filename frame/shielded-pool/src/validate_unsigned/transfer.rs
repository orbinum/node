//! Pool admission for `private_transfer`.
//!
//! | # | Check                  | Cost                              |
//! |---|------------------------|-----------------------------------|
//! | 1 | circuit version        | in-memory lookup                  |
//! | 2 | dispatch checks        | `validate`, cheapest first        |
//! | 3 | proof verifies         | one pairing (pool only)           |
//! | 4 | build the pool tags    | no reads                          |
//!
//! Step 2 IS the dispatchable's validation, so admission can never reject less
//! than execution. Its checks run cheapest first — shape, fee floor, root,
//! nullifiers, memos, then the rest — and each failure maps to the rejection a
//! wallet or relayer can act on (see [`admission_error`]).

use super::{
	TX_LONGEVITY,
	codes::{self, reject},
};
use crate::{
	operations::{
		ensure_valid_proof,
		private_transfer::{PrivateTransferOperation, TransferRequest},
	},
	pallet::{Config, Error},
};
use pallet_zk_verifier::{CircuitId, ZkVerifierPort as _};
use sp_runtime::{
	SaturatedConversion,
	transaction_validity::{
		InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
	},
};

/// Validate an incoming `private_transfer` unsigned transaction.
///
/// `proof` is `Some` at pool admission and `None` in `pre_dispatch`, where the
/// dispatchable verifies it and a second pairing would go unweighed.
pub fn validate_private_transfer<T: Config>(
	proof: Option<&[u8]>,
	req: &TransferRequest<T>,
) -> TransactionValidity {
	// ── 1. Circuit version ───────────────────────────────────────────────────
	// Cheapest gate first: a transaction proving against a retired circuit can
	// never execute, so it must not reach the pool at all.
	if !T::ZkVerifier::is_supported_version(CircuitId::TRANSFER.0, req.circuit_version) {
		return reject(codes::UNSUPPORTED_CIRCUIT_VERSION).into();
	}

	// ── 2. Everything the dispatchable checks ────────────────────────────────
	PrivateTransferOperation::validate::<T>(req).map_err(admission_error::<T>)?;

	// ── 3. Proof ─────────────────────────────────────────────────────────────
	// Without it, a copy of a pending spend with swapped memos or a higher fee
	// would share the nullifier tags, outrank the original on priority, replace
	// it, and then fail in the block — free, repeatable censorship. An invalid
	// proof from a peer also costs that peer reputation.
	if let Some(proof) = proof {
		let valid = ensure_valid_proof::<T>(|| {
			T::ZkVerifier::verify_transfer_proof(proof, &req.statement(), Some(req.circuit_version))
		})
		.is_ok();
		if !valid {
			return reject(codes::INVALID_PROOF).into();
		}
	}

	// ── 4. Pool tags: one per nullifier, never one over the whole set ────────
	//
	// `and_provides(x)` contributes exactly ONE tag: passing a `Vec<Vec<u8>>`
	// encodes the entire vector into one blob. Such a tag depends on the ORDER
	// of the inputs and on the OTHER note in the pair, so:
	//   - reordering the two inputs would mint a second admissible entry for
	//     the same spend, and
	//   - two transfers sharing only one note (A+B and A+C) would not collide,
	//     letting one note back an unbounded number of pool entries.
	// Since the fee is only charged on execution, that is free mempool
	// amplification: every variant propagates and is revalidated network-wide
	// while at most one can ever execute.
	//
	// Calling `and_provides` once PER nullifier makes any two transactions that
	// share a note mutually exclusive, in any order, so the pool mirrors the
	// on-chain nullifier set.
	//
	// Dummy nullifiers (zero) are excluded: they carry no identity, and tagging
	// them would collide every padded single-input spend with every other.
	let mut builder = ValidTransaction::with_tag_prefix(super::SPEND_TAG_PREFIX)
		.priority(req.fee.saturated_into())
		.longevity(TX_LONGEVITY)
		.propagate(true);

	for nullifier in req.real_nullifiers() {
		builder = builder.and_provides(nullifier);
	}

	builder.build()
}

/// The pool rejection for a failed transfer check.
fn admission_error<T: Config>(error: Error<T>) -> TransactionValidityError {
	match error {
		// The pool's price of entry: submissions are unsigned and gasless.
		Error::FeeTooLow => InvalidTransaction::Payment.into(),
		Error::UnknownMerkleRoot => reject(codes::UNKNOWN_ROOT).into(),
		Error::NullifierAlreadyUsed => InvalidTransaction::Stale.into(),
		// The only `InvalidAmount` a transfer raises: it spends no real note.
		Error::InvalidAmount => reject(codes::ALL_INPUTS_DUMMY).into(),
		Error::MemoCommitmentMismatch | Error::InvalidMemoSize => {
			reject(codes::INVALID_MEMO).into()
		}
		_ => reject(codes::INVALID_SPEND).into(),
	}
}
