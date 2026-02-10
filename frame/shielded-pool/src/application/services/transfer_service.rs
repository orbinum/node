//! Transfer service - Handles private transfer logic

use crate::{
	domain::{Commitment, Nullifier},
	infrastructure::{
		frame_types::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
		repositories::MerkleRepository,
	},
	pallet::{CommitmentMemos, Config, Error, Event, NullifierSet, Pallet},
};
use frame_support::{BoundedVec, pallet_prelude::*};
use frame_system;
#[cfg(not(feature = "runtime-benchmarks"))]
use pallet_zk_verifier::ZkVerifierPort;

pub struct TransferService;

impl TransferService {
	/// Execute private transfer
	pub fn execute<T: Config>(
		_proof: BoundedVec<u8, ConstU32<512>>,
		merkle_root: [u8; 32],
		nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
		commitments: BoundedVec<Commitment, ConstU32<2>>,
		encrypted_memos: BoundedVec<EncryptedMemo, ConstU32<2>>,
	) -> DispatchResult {
		// 1. Ensure memos match commitments
		ensure!(
			encrypted_memos.len() == commitments.len(),
			Error::<T>::MemoCommitmentMismatch
		);

		// 2. Validate all memo sizes
		for memo in encrypted_memos.iter() {
			ensure!(
				memo.0.len() == MAX_ENCRYPTED_MEMO_SIZE as usize,
				Error::<T>::InvalidMemoSize
			);
		}

		// 3. Verify Merkle root is known (Poseidon only)
		ensure!(
			MerkleRepository::is_known_root::<T>(&merkle_root),
			Error::<T>::UnknownMerkleRoot
		);

		// 4. Check nullifiers haven't been used
		for nullifier in nullifiers.iter() {
			ensure!(
				!NullifierSet::<T>::contains_key(nullifier),
				Error::<T>::NullifierAlreadyUsed
			);
		}

		// 5. Convert to arrays for ZK verification
		let nullifier_arrays: sp_std::vec::Vec<[u8; 32]> = nullifiers.iter().map(|n| n.0).collect();
		let commitment_arrays: sp_std::vec::Vec<[u8; 32]> =
			commitments.iter().map(|c| c.0).collect();

		// 6. Verify ZK proof (skip in benchmarking mode)
		#[cfg(not(feature = "runtime-benchmarks"))]
		{
			let valid = T::ZkVerifier::verify_transfer_proof(
				&_proof,
				&merkle_root,
				&nullifier_arrays,
				&commitment_arrays,
				None, // Use active version
			)
			.map_err(|_| Error::<T>::ProofVerificationFailed)?;

			ensure!(valid, Error::<T>::InvalidProof);
		}

		// In benchmarking mode, suppress unused variable warnings
		#[cfg(feature = "runtime-benchmarks")]
		{
			let _ = nullifier_arrays;
			let _ = commitment_arrays;
		}

		// 7. Mark nullifiers as used
		let current_block = frame_system::Pallet::<T>::block_number();
		for nullifier in nullifiers.iter() {
			NullifierSet::<T>::insert(nullifier, current_block);
		}

		// 8. Add new commitments to tree and store memos
		let mut leaf_indices: BoundedVec<u32, ConstU32<2>> = BoundedVec::new();
		for (commitment, memo) in commitments.iter().zip(encrypted_memos.iter()) {
			let index = Pallet::<T>::insert_leaf(*commitment)?;
			CommitmentMemos::<T>::insert(commitment, memo.clone());
			leaf_indices
				.try_push(index)
				.map_err(|_| Error::<T>::TooManyInputsOrOutputs)?;
		}

		// 9. Emit event
		Pallet::<T>::deposit_event(Event::PrivateTransfer {
			nullifiers,
			commitments,
			encrypted_memos,
			leaf_indices,
		});

		Ok(())
	}
}
