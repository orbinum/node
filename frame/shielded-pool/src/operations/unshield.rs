//! Unshield: spend a note to a public account, optionally keeping change private.

use crate::{
	merkle::MerkleTreeService,
	operations::{assets::AssetOperation, ensure_valid_proof, fees, statement},
	pallet::{BalanceOf, Config, Error, Event, Pallet},
	storage::{CommitmentRepository, MerkleRepository, NullifierRepository, PoolBalanceRepository},
	types::{Commitment, EncryptedMemo, Nullifier},
};
use frame_support::{
	CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound,
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use pallet_relayer::RelayerInterface as _;
use pallet_zk_verifier::{UnshieldStatement, ZkVerifierPort as _};
use sp_runtime::{SaturatedConversion, traits::Zero};

/// An unshield as submitted: the proof's public values plus what the chain
/// stores for the change note.
#[derive(CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound)]
pub struct UnshieldRequest<T: Config> {
	pub merkle_root: [u8; 32],
	pub nullifier: Nullifier,
	pub asset_id: u32,
	/// Net amount the recipient receives.
	pub amount: BalanceOf<T>,
	pub recipient: T::AccountId,
	/// Relay fee, paid on top of `amount` from the spent note.
	pub fee: BalanceOf<T>,
	/// Zero for a total unshield.
	pub change_commitment: [u8; 32],
	/// Empty for a total unshield; a full memo for a partial one.
	pub change_memo: EncryptedMemo,
	/// Version whose key the proof is checked against.
	pub circuit_version: u32,
}

impl<T: Config> UnshieldRequest<T> {
	pub fn has_change(&self) -> bool {
		self.change_commitment != [0u8; 32]
	}

	/// What the proof attests to.
	pub fn statement(&self) -> Result<UnshieldStatement, Error<T>> {
		Ok(UnshieldStatement {
			merkle_root: self.merkle_root,
			nullifier: self.nullifier.0,
			amount: self.amount.saturated_into(),
			recipient: statement::recipient_bytes::<T>(&self.recipient)?,
			asset_id: self.asset_id,
			fee: self.fee.saturated_into(),
			change_commitment: self.change_commitment,
			memo_digest: statement::memo_digest(core::slice::from_ref(&self.change_memo)),
		})
	}

	/// The identity a relayer commits to (see [`fees::unshield_op_hash`]).
	pub fn op_hash(&self) -> Result<[u8; 32], Error<T>> {
		Ok(fees::unshield_op_hash(
			&self.statement()?,
			self.circuit_version,
		))
	}
}

pub struct UnshieldOperation;

impl UnshieldOperation {
	pub fn execute<T: Config>(proof: &[u8], req: UnshieldRequest<T>) -> DispatchResult {
		Self::validate(&req)?;
		let statement = req.statement()?;
		ensure_valid_proof::<T>(|| {
			T::ZkVerifier::verify_unshield_proof(proof, &statement, Some(req.circuit_version))
		})?;

		let change_leaf_index = Self::settle(&req)?;
		if !req.fee.is_zero() {
			let op_hash = fees::unshield_op_hash(&statement, req.circuit_version);
			fees::credit_relay_fee::<T>(&op_hash, req.asset_id, req.fee.saturated_into())?;
		}

		let has_change = req.has_change();
		Pallet::<T>::deposit_event(Event::Unshielded {
			nullifier: req.nullifier,
			amount: req.amount,
			recipient: req.recipient,
			change_commitment: has_change.then_some(req.change_commitment),
			change_encrypted_memo: has_change.then_some(req.change_memo),
			change_leaf_index,
		});
		Ok(())
	}

	/// Every check that does not need the proof, cheapest first. Pool admission
	/// runs it too, so nothing that passes here fails after the proof is
	/// verified; it maps each error to a rejection code.
	pub(crate) fn validate<T: Config>(req: &UnshieldRequest<T>) -> Result<(), Error<T>> {
		ensure!(
			req.fee >= T::Relayer::min_relay_fee().saturated_into(),
			Error::<T>::FeeTooLow
		);
		ensure!(
			MerkleRepository::is_known_root::<T>(&req.merkle_root),
			Error::<T>::UnknownMerkleRoot
		);
		ensure!(
			req.nullifier.is_canonical(),
			Error::<T>::InvalidPublicSignals
		);
		ensure!(
			!NullifierRepository::is_used::<T>(&req.nullifier),
			Error::<T>::NullifierAlreadyUsed
		);

		// Both `amount` and `fee` leave the pool. A zero amount is refused first,
		// so any later `InvalidAmount` is the sum overflowing.
		ensure!(!req.amount.is_zero(), Error::<T>::InvalidAmount);
		let total = req
			.amount
			.checked_add(&req.fee)
			.ok_or(Error::<T>::InvalidAmount)?;
		ensure!(
			PoolBalanceRepository::get_asset_balance::<T>(req.asset_id) >= total,
			Error::<T>::InsufficientPoolBalance
		);

		// The change note is recoverable from the chain only through its memo.
		let memo_ok = if req.has_change() {
			req.change_memo.is_valid_size()
		} else {
			req.change_memo.is_empty()
		};
		ensure!(memo_ok, Error::<T>::InvalidMemoSize);

		AssetOperation::ensure_movable::<T>(req.asset_id)?;
		// The zero account has no known key: paying it burns the withdrawal.
		ensure!(
			req.recipient != Pallet::<T>::pool_account_id()
				&& statement::recipient_bytes::<T>(&req.recipient)? != [0u8; 32],
			Error::<T>::InvalidRecipient
		);
		if req.has_change() {
			let change = Commitment::new(req.change_commitment);
			ensure!(change.is_canonical(), Error::<T>::InvalidPublicSignals);
			ensure!(
				!CommitmentRepository::exists::<T>(&change),
				Error::<T>::CommitmentAlreadyExists
			);
		}
		Ok(())
	}

	/// Pay the recipient, insert the change note, spend the nullifier. Returns
	/// the change note's leaf index.
	fn settle<T: Config>(req: &UnshieldRequest<T>) -> Result<Option<u32>, DispatchError> {
		T::Currency::transfer(
			&Pallet::<T>::pool_account_id(),
			&req.recipient,
			req.amount,
			ExistenceRequirement::AllowDeath,
		)?;
		// Only `amount` leaves the pool: the fee stays as backing for the
		// relayer's pending fee until it is claimed. Sound only because
		// `validate` required a balance of `amount + fee`.
		PoolBalanceRepository::decrease_balance::<T>(req.asset_id, req.amount);

		let change_leaf_index = if req.has_change() {
			let change = Commitment::new(req.change_commitment);
			let index = MerkleTreeService::insert_leaf::<T>(change)?;
			CommitmentRepository::store_memo::<T>(change, req.change_memo.clone());
			Some(index)
		} else {
			None
		};

		NullifierRepository::mark_as_used::<T>(
			req.nullifier,
			frame_system::Pallet::<T>::block_number(),
		);
		Ok(change_leaf_index)
	}
}
