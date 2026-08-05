//! Pool admission for `private_transfer`.
//!
//! Checks run cheapest-first — a version lookup, a fee compare, then two point
//! reads — so flooding the pool with invalid transactions stays cheap to reject.
//! No ZK verification happens here; that is the extrinsic's job.

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
use parity_scale_codec::Encode;
use sp_runtime::{
	SaturatedConversion,
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
};

/// On-chain circuit id for the transfer/unshield version guard (mirrors the
/// zk-verifier's `CircuitId` constants).
const CIRCUIT_TRANSFER: u32 = 1;

pub fn validate_private_transfer<T: Config>(
	merkle_root: &Hash,
	nullifiers: &BoundedVec<Nullifier, ConstU32<2>>,
	fee: &BalanceOf<T>,
	relayer: &Option<sp_core::H160>,
	circuit_version: u32,
) -> TransactionValidity {
	// Anti-spam: reject an unsupported circuit version before pool admission.
	if !T::ZkVerifier::is_supported_version(CIRCUIT_TRANSFER, circuit_version) {
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

	// Reject already-spent nullifiers (skip dummy nullifiers — value zero, forced by circuit)
	for nullifier in nullifiers.iter() {
		if nullifier.0 == [0u8; 32] {
			continue; // dummy input — never inserted in the set, cannot be stale
		}
		if NullifierSet::<T>::contains_key(nullifier) {
			return InvalidTransaction::Stale.into();
		}
	}

	// Reject transactions where all nullifiers are dummy (both inputs value=0).
	// This prevents free Merkle tree spam (2 commitments inserted at zero cost).
	if nullifiers.iter().all(|n| n.0 == [0u8; 32]) {
		return reject(codes::ALL_INPUTS_DUMMY).into();
	}

	// Exclude dummy nullifiers (zero) from provides — they carry no identity.
	// Bind the fee recipient (`relayer`) into the tag so a variant differing only
	// in `relayer` is a distinct pool entry and cannot silently replace the honest
	// tx. The shared nullifier tag already makes same-nullifier variants mutually
	// exclusive (first-seen wins at equal fee); this hardens that boundary.
	let mut provides: alloc::vec::Vec<alloc::vec::Vec<u8>> = nullifiers
		.iter()
		.filter(|n| n.0 != [0u8; 32])
		.map(|n| n.encode())
		.collect();
	provides.push(relayer.encode());

	ValidTransaction::with_tag_prefix("ShieldedPoolTransfer")
		.priority((*fee).saturated_into())
		.longevity(TX_LONGEVITY)
		.and_provides(provides)
		.propagate(true)
		.build()
}
