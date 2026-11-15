// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bound spends and minted notes: the shielded pool's side of an action another
//! pallet runs with private funds.
//!
//! A bound spend is an unshield whose proof commits to an action (see
//! [`statement::bound_digest`]). It pays the action's executor in the native
//! asset, or burns a pallet-backed asset, then hands the value to
//! `T::BoundActions`. What the action gives back comes in as a note the chain
//! computes itself ([`MintOperation`]), to a one-time key the action carried, so
//! no second proof is needed and the output cannot be swapped.

use crate::{
	merkle::MerkleTreeService,
	operations::{
		assets::AssetOperation,
		ensure_valid_proof, fees, statement,
		unshield::{UnshieldOperation, UnshieldRequest},
	},
	pallet::{BoundActionOf, Config, Error, Event, Pallet},
	storage::{AssetRepository, CommitmentRepository, PoolBalanceRepository},
	types::{
		AssetBackend, BoundActions, Commitment, Funding, MINT_ATTEMPTS, MintedNote, NATIVE_ASSET_ID,
	},
};
use frame_support::{
	CloneNoBound, DebugNoBound, EqNoBound, PartialEqNoBound,
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use pallet_zk_verifier::{UnshieldStatement, ZkVerifierPort as _};
use parity_scale_codec::Encode;
use sp_runtime::{SaturatedConversion, traits::Zero};

/// A bound spend as submitted: an unshield whose recipient is the action's
/// executor, and the action its proof commits to.
#[derive(CloneNoBound, PartialEqNoBound, EqNoBound, DebugNoBound)]
pub struct BoundSpendRequest<T: Config> {
	pub spend: UnshieldRequest<T>,
	pub action: BoundActionOf<T>,
}

impl<T: Config> BoundSpendRequest<T> {
	/// What the proof attests to: the unshield statement, with `memo_hash`
	/// committing to the action as well as the change memo.
	pub fn statement(&self) -> Result<UnshieldStatement, Error<T>> {
		let mut statement = self.spend.statement()?;
		statement.memo_digest =
			statement::bound_digest::<T>(&self.action.encode(), &self.spend.change_memo);
		Ok(statement)
	}
}

pub struct BoundSpendOperation;

impl BoundSpendOperation {
	pub fn execute<T: Config>(proof: &[u8], req: BoundSpendRequest<T>) -> DispatchResult {
		let backend = Self::validate(&req)?;
		let statement = req.statement()?;
		ensure_valid_proof::<T>(|| {
			T::ZkVerifier::verify_unshield_proof(proof, &statement, Some(req.spend.circuit_version))
		})?;

		let spend = &req.spend;
		let change_leaf_index =
			UnshieldOperation::settle_spend(spend, backend == AssetBackend::Native)?;
		// The action runs on the state `validate` saw: a fee redeemed in the same
		// asset changes it, so the fee is credited after.
		<T::BoundActions as BoundActions<T::AccountId>>::execute(
			req.action,
			spend.asset_id,
			spend.amount.saturated_into(),
			spend.fee.saturated_into(),
		)?;
		if !spend.fee.is_zero() {
			fees::credit_fee::<T>(spend.asset_id, spend.fee.saturated_into())?;
		}

		let has_change = spend.has_change();
		Pallet::<T>::deposit_event(Event::BoundSpent {
			nullifier: spend.nullifier,
			asset_id: spend.asset_id,
			amount: spend.amount,
			executor: spend.recipient.clone(),
			change_commitment: has_change.then_some(spend.change_commitment),
			change_encrypted_memo: has_change.then(|| spend.change_memo.clone()),
			change_leaf_index,
		});
		Ok(())
	}

	/// Every check that does not need the proof, the action's included. Pool
	/// admission runs it too, so nothing that passes here fails after the proof
	/// is verified. Returns the backend of the spent asset.
	pub(crate) fn validate<T: Config>(
		req: &BoundSpendRequest<T>,
	) -> Result<AssetBackend, Error<T>> {
		let spend = &req.spend;
		ensure!(
			spend.fee.saturated_into::<u128>() >= fees::min_fee::<T>(spend.asset_id)?,
			Error::<T>::FeeTooLow
		);
		UnshieldOperation::validate_spend(spend)?;
		let backend = AssetOperation::ensure_spendable::<T>(spend.asset_id)?;

		let executor = <T::BoundActions as BoundActions<T::AccountId>>::executor(&req.action)
			.ok_or(Error::<T>::InvalidBoundAction)?;
		ensure!(executor == spend.recipient, Error::<T>::InvalidRecipient);
		<T::BoundActions as BoundActions<T::AccountId>>::validate(
			&req.action,
			spend.asset_id,
			spend.amount.saturated_into(),
			spend.fee.saturated_into(),
		)
		.map_err(|_| Error::<T>::InvalidBoundAction)?;
		Ok(backend)
	}
}

/// `Poseidon4(value, asset_id, owner_pk, blinding)`, as the circuits commit to a
/// note; `None` when `owner_pk` or `blinding` is not a canonical field element.
pub fn note_commitment(
	value: u128,
	asset_id: u32,
	owner_pk: &[u8; 32],
	blinding: &[u8; 32],
) -> Option<[u8; 32]> {
	use ark_bn254::Fr;
	use ark_ff::{BigInteger, PrimeField};
	use orbinum_zk_core::{FieldElement, PoseidonHasher};

	let owner = FieldElement::from_canonical_le(owner_pk)?;
	let blinding = FieldElement::from_canonical_le(blinding)?;

	#[cfg(feature = "poseidon-native")]
	let hasher = orbinum_zk_core::NativePoseidonHasher;
	#[cfg(not(feature = "poseidon-native"))]
	let hasher = orbinum_zk_core::LightPoseidonHasher;

	let hash = hasher.hash_4([
		FieldElement::new(Fr::from(value)),
		FieldElement::new(Fr::from(u64::from(asset_id))),
		owner,
		blinding,
	]);
	let bytes = hash.inner().into_bigint().to_bytes_le();
	let mut out = [0u8; 32];
	let n = bytes.len().min(32);
	out[..n].copy_from_slice(&bytes[..n]);
	Some(out)
}

pub struct MintOperation;

impl MintOperation {
	/// Inserts a note of `value` of `asset_id` owned by `owner_pk`, its secrets
	/// known to whoever chose `owner_pk` and `blinding`. A native note is paid in
	/// by an account; a pallet-backed one is issued by its own pallet.
	///
	/// No memo is stored: the action that mints the note carried both secrets,
	/// so the wallet that built it recognizes the note from `NoteMinted`. When a
	/// note of that value and key exists already, the next value down is tried
	/// (up to [`MINT_ATTEMPTS`]), so a reused key or a copied commitment never
	/// costs the owner the output.
	pub fn mint<T: Config>(
		asset_id: u32,
		value: u128,
		owner_pk: [u8; 32],
		blinding: [u8; 32],
		funding: Funding<'_, T::AccountId>,
	) -> Result<MintedNote, DispatchError> {
		ensure!(value > 0, Error::<T>::InvalidAmount);
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		match (asset.backend, &funding) {
			(AssetBackend::Native, Funding::From(_)) if asset_id == NATIVE_ASSET_ID => {}
			(AssetBackend::Pallet(id), Funding::Issued(issuer)) if id == issuer.0 => {}
			_ => return Err(Error::<T>::AssetNotSupported.into()),
		}
		// A key or blinding that is not a field element is refused as such.
		note_commitment(value, asset_id, &owner_pk, &blinding)
			.ok_or(Error::<T>::InvalidPublicSignals)?;
		let (value, commitment) = (0..MINT_ATTEMPTS)
			.filter_map(|less| value.checked_sub(less).filter(|v| *v > 0))
			.find_map(|value| {
				let commitment =
					Commitment::new(note_commitment(value, asset_id, &owner_pk, &blinding)?);
				(!CommitmentRepository::exists::<T>(&commitment)).then_some((value, commitment))
			})
			.ok_or(Error::<T>::CommitmentAlreadyExists)?;

		if let Funding::From(funder) = funding {
			T::Currency::transfer(
				funder,
				&Pallet::<T>::pool_account_id(),
				value.saturated_into(),
				ExistenceRequirement::AllowDeath,
			)?;
		}

		let leaf_index = MerkleTreeService::insert_leaf::<T>(commitment)?;
		PoolBalanceRepository::increase_balance::<T>(asset_id, value.saturated_into());
		Pallet::<T>::deposit_event(Event::NoteMinted {
			commitment,
			asset_id,
			value,
			leaf_index,
		});
		Ok(MintedNote { commitment, value })
	}
}

impl<T: Config> Pallet<T> {
	/// Mints the output note of a bound action: see [`MintOperation::mint`].
	pub fn mint_note(
		asset_id: u32,
		value: u128,
		owner_pk: [u8; 32],
		blinding: [u8; 32],
		funding: Funding<'_, T::AccountId>,
	) -> Result<MintedNote, DispatchError> {
		MintOperation::mint::<T>(asset_id, value, owner_pk, blinding, funding)
	}

	/// What a spend of `asset_id` adds when the asset is pallet-backed: its fee floor
	/// and the redemption of its fee (`fees::credit_fee`). Only the native asset is
	/// not pallet-backed among the assets a spend can move.
	pub fn pallet_asset_spend_weight(asset_id: u32) -> Weight {
		if asset_id == NATIVE_ASSET_ID {
			return Weight::zero();
		}
		<T::BoundActions as BoundActions<T::AccountId>>::redeem_fees_weight()
			.saturating_add(T::DbWeight::get().reads(6))
	}

	/// What [`Self::mint_note`] costs: a shield's work without its proof.
	pub fn mint_note_weight() -> Weight {
		use crate::WeightInfo as _;
		T::WeightInfo::shield()
	}

	/// Registers an asset its pallet issues: see
	/// [`AssetOperation::register_pallet_asset`].
	pub fn register_pallet_asset(
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		pallet_id: frame_support::PalletId,
	) -> Result<u32, DispatchError> {
		AssetOperation::register_pallet_asset::<T>(name, symbol, decimals, pallet_id)
	}
}
