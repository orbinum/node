// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! [`ZkVerifierPort`] for the pallet: each statement is encoded for the key it
//! is checked against ([`crate::encoding`]) and verified by [`super::verifier`].

use super::verifier;
use crate::{
	Config, Error, Pallet, RetiredVersions, ShieldStatement, TransferStatement, UnshieldStatement,
	VerificationKeys, VkHashes, ZkVerifierPort, encoding, types::CircuitId,
};

/// Public inputs of the largest spend layout: a cross-tree transfer.
pub(crate) const MAX_SPEND_PUBLIC_INPUTS: u32 = {
	use orbinum_zk_verifier::{CIRCUIT_ID_TRANSFER, CIRCUIT_ID_UNSHIELD, max_public_inputs};
	let (Some(transfer), Some(unshield)) = (
		max_public_inputs(CIRCUIT_ID_TRANSFER),
		max_public_inputs(CIRCUIT_ID_UNSHIELD),
	) else {
		panic!("spend circuits have a known arity")
	};
	max(transfer, unshield) as u32
};

const fn max(a: usize, b: usize) -> usize {
	if a > b { a } else { b }
}

impl<T: Config> ZkVerifierPort for Pallet<T> {
	fn verify_transfer_proof(
		proof: &[u8],
		statement: &TransferStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// One nullifier per input and one commitment per output, and the circuit
		// has as many outputs as inputs.
		frame_support::ensure!(
			statement.nullifiers.len() == statement.commitments.len(),
			Error::<T>::InvalidPublicInputs
		);
		verifier::verify_statement::<T>(CircuitId::TRANSFER, version, proof, |layout| {
			encoding::encode_transfer(statement, layout)
		})
		.map(|(ok, _)| ok)
	}

	fn verify_unshield_proof(
		proof: &[u8],
		statement: &UnshieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		verifier::verify_statement::<T>(CircuitId::UNSHIELD, version, proof, |layout| {
			encoding::encode_unshield(statement, layout)
		})
		.map(|(ok, _)| ok)
	}

	fn verify_shield_proof(
		proof: &[u8],
		statement: &ShieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Shield has a single layout; a key of another arity fails the length check.
		verifier::verify_statement::<T>(CircuitId::SHIELD, version, proof, |_| {
			Some(encoding::encode_shield(statement))
		})
		.map(|(ok, _)| ok)
	}

	fn is_supported_version(circuit_id: u32, version: u32) -> bool {
		let cid = CircuitId(circuit_id);
		VerificationKeys::<T>::contains_key(cid, version)
			&& !RetiredVersions::<T>::contains_key(cid, version)
			&& !VkHashes::<T>::get(cid, version).is_some_and(|h| Pallet::<T>::is_denied(&h))
	}

	fn verification_weight() -> frame_support::weights::Weight {
		use crate::weights::WeightInfo;
		use frame_support::traits::Get;
		// Plus the `VkHashes` read of the denied-key check.
		T::WeightInfo::verify_proof(MAX_SPEND_PUBLIC_INPUTS)
			.saturating_add(T::DbWeight::get().reads(1))
	}
}
