//! Private transfer: spend up to two notes into two new ones, all inside the pool.

use crate::{
	merkle::MerkleTreeService,
	operations::{assets::AssetOperation, ensure_valid_proof, fees, statement},
	pallet::{BalanceOf, Config, Error, Event, Pallet},
	storage::{CommitmentRepository, MerkleRepository, NullifierRepository},
	types::{Commitment, EncryptedMemo, Nullifier},
};
use frame_support::{
	BoundedVec, CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound, pallet_prelude::*,
};
use pallet_relayer::RelayerInterface as _;
use pallet_zk_verifier::{TransferStatement, ZkVerifierPort as _};
use sp_runtime::{SaturatedConversion, traits::Zero};

/// Inputs of the transfer circuit; a zero nullifier pads a one-input spend.
pub const TRANSFER_INPUTS: usize = 2;
/// Outputs of the transfer circuit.
pub const TRANSFER_OUTPUTS: usize = 2;

/// A private transfer as submitted. A zero nullifier marks a dummy input, which
/// the circuit skips.
#[derive(CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound)]
pub struct TransferRequest<T: Config> {
	pub merkle_root: [u8; 32],
	pub nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
	pub commitments: BoundedVec<Commitment, ConstU32<2>>,
	/// One per commitment, in the same order.
	pub memos: BoundedVec<EncryptedMemo, ConstU32<2>>,
	pub asset_id: u32,
	pub fee: BalanceOf<T>,
	/// Version whose key the proof is checked against.
	pub circuit_version: u32,
}

impl<T: Config> TransferRequest<T> {
	/// What the proof attests to.
	pub fn statement(&self) -> TransferStatement {
		TransferStatement {
			merkle_root: self.merkle_root,
			nullifiers: self.nullifiers.iter().map(|n| n.0).collect(),
			commitments: self.commitments.iter().map(|c| c.0).collect(),
			asset_id: self.asset_id,
			fee: self.fee.saturated_into(),
			memo_digest: statement::memo_digest(&self.memos),
		}
	}

	/// The identity a relayer commits to (see [`fees::transfer_op_hash`]).
	pub fn op_hash(&self) -> [u8; 32] {
		fees::transfer_op_hash(&self.statement(), self.circuit_version)
	}

	/// The inputs that spend a real note: every nullifier but the zero dummy.
	pub(crate) fn real_nullifiers(&self) -> impl Iterator<Item = &Nullifier> {
		self.nullifiers.iter().filter(|n| n.0 != [0u8; 32])
	}
}

pub struct PrivateTransferOperation;

impl PrivateTransferOperation {
	pub fn execute<T: Config>(proof: &[u8], req: TransferRequest<T>) -> DispatchResult {
		Self::validate(&req)?;
		let statement = req.statement();
		ensure_valid_proof::<T>(|| {
			T::ZkVerifier::verify_transfer_proof(proof, &statement, Some(req.circuit_version))
		})?;

		let leaf_indices = Self::settle(&req)?;
		if !req.fee.is_zero() {
			let op_hash = fees::transfer_op_hash(&statement, req.circuit_version);
			fees::credit_relay_fee::<T>(&op_hash, req.asset_id, req.fee.saturated_into())?;
		}

		Pallet::<T>::deposit_event(Event::NullifiersSpent {
			nullifiers: req.nullifiers,
		});
		Pallet::<T>::deposit_event(Event::CommitmentsInserted {
			commitments: req.commitments,
			encrypted_memos: req.memos,
			leaf_indices,
		});
		Ok(())
	}

	/// Every check that does not need the proof, cheapest first. Pool admission
	/// runs it too, so nothing that passes here fails after the proof is
	/// verified; it maps each error to a rejection code.
	pub(crate) fn validate<T: Config>(req: &TransferRequest<T>) -> Result<(), Error<T>> {
		// The circuit is two in, two out; a zero nullifier pads a one-input spend.
		ensure!(
			req.nullifiers.len() == TRANSFER_INPUTS && req.commitments.len() == TRANSFER_OUTPUTS,
			Error::<T>::TooManyInputsOrOutputs
		);
		ensure!(
			req.fee >= T::Relayer::min_relay_fee().saturated_into(),
			Error::<T>::FeeTooLow
		);
		ensure!(
			MerkleRepository::is_known_root::<T>(&req.merkle_root),
			Error::<T>::UnknownMerkleRoot
		);

		for nullifier in req.real_nullifiers() {
			ensure!(nullifier.is_canonical(), Error::<T>::InvalidPublicSignals);
			ensure!(
				!NullifierRepository::is_used::<T>(nullifier),
				Error::<T>::NullifierAlreadyUsed
			);
		}
		let real: sp_std::vec::Vec<_> = req.real_nullifiers().collect();
		ensure!(
			!(real.len() == 2 && real[0] == real[1]),
			Error::<T>::NullifierAlreadyUsed
		);
		// Two dummy inputs would insert notes backed by nothing.
		ensure!(!real.is_empty(), Error::<T>::InvalidAmount);

		ensure!(
			req.memos.len() == req.commitments.len(),
			Error::<T>::MemoCommitmentMismatch
		);
		ensure!(
			req.memos.iter().all(EncryptedMemo::is_valid_size),
			Error::<T>::InvalidMemoSize
		);

		AssetOperation::ensure_movable::<T>(req.asset_id)?;

		for commitment in req.commitments.iter() {
			ensure!(
				commitment.is_canonical() && commitment.is_valid(),
				Error::<T>::InvalidPublicSignals
			);
			// Checked here, not left to `insert_leaf`: a spend that would fail
			// after its proof is verified is free block filler.
			ensure!(
				!CommitmentRepository::exists::<T>(commitment),
				Error::<T>::CommitmentAlreadyExists
			);
		}
		if let [first, second] = req.commitments.as_slice() {
			ensure!(first != second, Error::<T>::CommitmentAlreadyExists);
		}
		Ok(())
	}

	/// Spend the real nullifiers and insert the output notes. Returns their leaf
	/// indices.
	fn settle<T: Config>(
		req: &TransferRequest<T>,
	) -> Result<BoundedVec<u32, ConstU32<2>>, DispatchError> {
		let now = frame_system::Pallet::<T>::block_number();
		for nullifier in req.real_nullifiers() {
			NullifierRepository::mark_as_used::<T>(*nullifier, now);
		}

		let mut leaf_indices = BoundedVec::new();
		for (commitment, memo) in req.commitments.iter().zip(req.memos.iter()) {
			let index = MerkleTreeService::insert_leaf::<T>(*commitment)?;
			CommitmentRepository::store_memo::<T>(*commitment, memo.clone());
			leaf_indices
				.try_push(index)
				.map_err(|_| Error::<T>::TooManyInputsOrOutputs)?;
		}
		Ok(leaf_indices)
	}
}
