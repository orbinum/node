//! Pool admission for `unshield`.
//!
//! Mirrors [`super::transfer`], plus a pool-solvency check. That check is
//! advisory only: the balance can move between admission and execution, so the
//! extrinsic re-verifies it. Rejecting early just avoids gossiping a spend the
//! pool cannot cover.

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
use parity_scale_codec::Encode;
use sp_runtime::{
	SaturatedConversion,
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
};

/// On-chain circuit id for the transfer/unshield version guard (mirrors the
/// zk-verifier's `CircuitId` constants).
const CIRCUIT_UNSHIELD: u32 = 2;

/// Validate an incoming `unshield` unsigned transaction.
pub fn validate_unshield<T: Config>(
	merkle_root: &Hash,
	nullifier: &Nullifier,
	asset_id: &u32,
	amount: &BalanceOf<T>,
	fee: &BalanceOf<T>,
	relayer: &Option<sp_core::H160>,
	circuit_version: u32,
) -> TransactionValidity {
	// Anti-spam: reject an unsupported circuit version before pool admission.
	if !T::ZkVerifier::is_supported_version(CIRCUIT_UNSHIELD, circuit_version) {
		return reject(codes::UNSUPPORTED_CIRCUIT_VERSION).into();
	}

	// Anti-spam: fee must meet minimum relay fee
	let min_fee: BalanceOf<T> = T::Relayer::min_relay_fee().saturated_into();
	if *fee < min_fee {
		return InvalidTransaction::Payment.into();
	}

	// Reject unknown Merkle roots
	if !MerkleRepository::is_known_root::<T>(merkle_root) {
		return reject(codes::UNKNOWN_ROOT).into();
	}

	// Reject already-spent nullifier
	if NullifierSet::<T>::contains_key(nullifier) {
		return InvalidTransaction::Stale.into();
	}

	// Reject if pool balance is insufficient
	let total = amount
		.checked_add(fee)
		.ok_or(reject(codes::AMOUNT_OVERFLOW))?;
	if PoolBalancePerAsset::<T>::get(asset_id) < total {
		return reject(codes::INSUFFICIENT_POOL_BALANCE).into();
	}

	// Bind `relayer` into the tag alongside the nullifier: a variant differing only
	// in the fee recipient is a distinct pool entry, so it cannot silently replace
	// the honest tx. Same-nullifier variants stay mutually exclusive (first-seen
	// wins at equal fee).
	ValidTransaction::with_tag_prefix("ShieldedPoolUnshield")
		.priority((*fee).saturated_into())
		.longevity(TX_LONGEVITY)
		.and_provides([nullifier.encode(), relayer.encode()])
		.propagate(true)
		.build()
}
