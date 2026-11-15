// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pool admission for `bound_spend`: `unshield`'s, with the action checked too.
//!
//! | # | Check                  | Cost                              |
//! |---|------------------------|-----------------------------------|
//! | 1 | circuit version        | in-memory lookup                  |
//! | 2 | dispatch checks        | `validate`, the action's included |
//! | 3 | proof verifies         | one pairing (pool only)           |
//! | 4 | build the pool tag     | no reads                          |

use super::{
	TX_LONGEVITY,
	codes::{self, reject},
};
use crate::{
	operations::{
		bound::{BoundSpendOperation, BoundSpendRequest},
		ensure_valid_proof,
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

/// Validate an incoming `bound_spend` unsigned transaction.
///
/// `proof` is `Some` at pool admission and `None` in `pre_dispatch`.
pub fn validate_bound_spend<T: Config>(
	proof: Option<&[u8]>,
	req: &BoundSpendRequest<T>,
) -> TransactionValidity {
	let spend = &req.spend;
	if !T::ZkVerifier::is_supported_version(CircuitId::UNSHIELD.0, spend.circuit_version) {
		return reject(codes::UNSUPPORTED_CIRCUIT_VERSION).into();
	}

	BoundSpendOperation::validate::<T>(req).map_err(|e| admission_error(e, req))?;

	if let Some(proof) = proof {
		let valid = req.statement().is_ok_and(|statement| {
			ensure_valid_proof::<T>(|| {
				T::ZkVerifier::verify_unshield_proof(proof, &statement, Some(spend.circuit_version))
			})
			.is_ok()
		});
		if !valid {
			return reject(codes::INVALID_PROOF).into();
		}
	}

	// The nullifier shares the namespace of every other spend: one note, one
	// pool entry, whichever call spends it.
	let mut builder = ValidTransaction::with_tag_prefix(super::SPEND_TAG_PREFIX)
		.priority(crate::operations::fees::priority::<T>(
			spend.asset_id,
			spend.fee.saturated_into(),
		))
		.longevity(TX_LONGEVITY)
		.and_provides(spend.nullifier)
		.propagate(true);
	if spend.has_change() {
		builder = builder.and_provides((super::OUTPUT_TAG, spend.change_commitment));
	}
	builder.build()
}

/// The pool rejection for a failed bound-spend check.
fn admission_error<T: Config>(
	error: Error<T>,
	req: &BoundSpendRequest<T>,
) -> TransactionValidityError {
	match error {
		Error::FeeTooLow => InvalidTransaction::Payment.into(),
		Error::UnknownMerkleRoot => reject(codes::UNKNOWN_ROOT).into(),
		Error::NullifierAlreadyUsed => InvalidTransaction::Stale.into(),
		Error::InvalidAmount if !req.spend.amount.is_zero() => {
			reject(codes::AMOUNT_OVERFLOW).into()
		}
		Error::InsufficientPoolBalance => reject(codes::INSUFFICIENT_POOL_BALANCE).into(),
		Error::InvalidMemoSize => reject(codes::INVALID_MEMO).into(),
		Error::InvalidBoundAction => reject(codes::INVALID_ACTION).into(),
		_ => reject(codes::INVALID_SPEND).into(),
	}
}
