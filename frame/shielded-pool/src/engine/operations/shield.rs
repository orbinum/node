// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shield: deposit public tokens into the pool as a new note.

use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use pallet_zk_verifier::{ShieldStatement, ZkVerifierPort as _};
use sp_runtime::{SaturatedConversion, traits::Zero};

use crate::{
	merkle::MerkleTreeService,
	operations::{assets::AssetOperation, ensure_valid_proof},
	pallet::{BalanceOf, Config, Error, Event, Pallet, ShieldBatchItem},
	storage::{AssetRepository, CommitmentRepository, PoolBalanceRepository},
	types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Proof},
};

/// A shield as submitted: the deposit and the note it creates.
#[derive(CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound)]
pub struct ShieldRequest<T: Config> {
	pub asset_id: u32,
	pub amount: BalanceOf<T>,
	pub commitment: Commitment,
	pub encrypted_memo: EncryptedMemo,
	/// Version whose key the proof is checked against.
	pub circuit_version: u32,
}

impl<T: Config> ShieldRequest<T> {
	/// A `shield_batch` entry, split into its proof and the request it proves.
	pub fn from_batch_item(item: ShieldBatchItem<T>) -> (Proof, Self) {
		let (asset_id, amount, commitment, encrypted_memo, proof, circuit_version) = item;
		(
			proof,
			Self {
				asset_id,
				amount,
				commitment,
				encrypted_memo,
				circuit_version,
			},
		)
	}

	/// What the proof attests to: the commitment opens to exactly this deposit.
	fn statement(&self) -> ShieldStatement {
		ShieldStatement {
			commitment: self.commitment.0,
			value: self.amount.saturated_into(),
			asset_id: self.asset_id,
		}
	}
}

pub struct ShieldOperation;

impl ShieldOperation {
	/// Deposits `req.amount` as the note `req.commitment`. The proof is checked
	/// before any funds move.
	pub fn execute<T: Config>(
		depositor: T::AccountId,
		proof: &[u8],
		req: ShieldRequest<T>,
	) -> DispatchResult {
		Self::validate(&req)?;
		let statement = req.statement();
		ensure_valid_proof::<T>(|| {
			T::ZkVerifier::verify_shield_proof(proof, &statement, Some(req.circuit_version))
		})?;

		let ShieldRequest {
			asset_id,
			amount,
			commitment,
			encrypted_memo,
			..
		} = req;
		T::Currency::transfer(
			&depositor,
			&Pallet::<T>::pool_account_id(),
			amount,
			ExistenceRequirement::KeepAlive,
		)?;

		let leaf_index = MerkleTreeService::insert_leaf::<T>(commitment)?;
		CommitmentRepository::store_memo::<T>(commitment, encrypted_memo.clone());
		PoolBalanceRepository::increase_balance::<T>(asset_id, amount);

		Pallet::<T>::deposit_event(Event::Shielded {
			depositor,
			amount,
			commitment,
			encrypted_memo,
			leaf_index,
		});

		Ok(())
	}

	/// Everything checkable without the proof, so a bad request costs no verification.
	fn validate<T: Config>(req: &ShieldRequest<T>) -> DispatchResult {
		AssetOperation::ensure_movable::<T>(req.asset_id)?;
		ensure!(!req.amount.is_zero(), Error::<T>::InvalidAmount);
		ensure!(
			req.encrypted_memo.0.len() == MAX_ENCRYPTED_MEMO_SIZE as usize,
			Error::<T>::InvalidMemoSize
		);
		ensure!(
			req.commitment.is_canonical(),
			Error::<T>::InvalidPublicSignals
		);
		ensure!(req.commitment.is_valid(), Error::<T>::InvalidPublicSignals);
		ensure!(
			!CommitmentRepository::exists::<T>(&req.commitment),
			Error::<T>::CommitmentAlreadyExists
		);
		Ok(())
	}

	pub fn commitment_exists<T: Config>(commitment: &Commitment) -> bool {
		CommitmentRepository::exists::<T>(commitment)
	}

	pub fn asset_exists<T: Config>(asset_id: u32) -> bool {
		AssetRepository::exists::<T>(asset_id)
	}

	pub fn is_asset_verified<T: Config>(asset_id: u32) -> bool {
		AssetRepository::get_asset::<T>(asset_id)
			.map(|asset| asset.is_verified)
			.unwrap_or(false)
	}
}
