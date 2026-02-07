//! Shield service
//!
//! Coordinates the shield operation across domain and infrastructure layers

use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};

use crate::{
	application::DepositInfo,
	domain::Commitment,
	infrastructure::frame_types::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
	pallet::{
		Assets, CommitmentMemos, Config, Deposits, Error, Event, MerkleTreeSize, Pallet,
		PoolBalance, PoolBalancePerAsset,
	},
};

/// Shield service coordinates depositing tokens into the shielded pool
pub struct ShieldService;

impl ShieldService {
	/// Execute shield operation
	///
	/// # Process
	/// 1. Validate asset exists and is verified
	/// 2. Validate amount meets minimum threshold
	/// 3. Validate memo size
	/// 4. Check tree capacity
	/// 5. Transfer tokens to pool
	/// 6. Insert commitment into tree
	/// 7. Store memo and deposit info
	/// 8. Update balances
	/// 9. Emit event
	pub fn execute<T: Config>(
		depositor: <T as frame_system::Config>::AccountId,
		asset_id: u32,
		amount: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		commitment: Commitment,
		encrypted_memo: EncryptedMemo,
	) -> DispatchResult {
		// 1. Validate asset exists and is verified
		let asset = Assets::<T>::get(asset_id).ok_or(Error::<T>::InvalidAssetId)?;

		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);

		// 2. Validate amount
		ensure!(
			amount >= T::MinShieldAmount::get(),
			Error::<T>::AmountTooSmall
		);

		// 3. Validate memo size
		ensure!(
			encrypted_memo.0.len() == MAX_ENCRYPTED_MEMO_SIZE as usize,
			Error::<T>::InvalidMemoSize
		);

		// 4. Check tree capacity
		let current_size = MerkleTreeSize::<T>::get();
		let max_leaves = 2u32.saturating_pow(T::MaxTreeDepth::get());
		ensure!(current_size < max_leaves, Error::<T>::MerkleTreeFull);

		// 5. Transfer tokens to the pool account
		T::Currency::transfer(
			&depositor,
			&Pallet::<T>::pool_account_id(),
			amount,
			ExistenceRequirement::KeepAlive,
		)?;

		// 6. Add commitment to the tree
		let leaf_index = Pallet::<T>::insert_leaf(commitment)?;

		// 7. Store encrypted memo
		CommitmentMemos::<T>::insert(commitment, encrypted_memo.clone());

		// 8. Update pool balances
		PoolBalance::<T>::mutate(|b| {
			if let Some(new_balance) = b.checked_add(&amount) {
				*b = new_balance;
			}
		});
		PoolBalancePerAsset::<T>::mutate(asset_id, |b| {
			if let Some(new_balance) = b.checked_add(&amount) {
				*b = new_balance;
			}
		});

		// 9. Store deposit info
		Deposits::<T>::insert(
			commitment,
			DepositInfo {
				depositor: depositor.clone(),
				amount,
				block_number: frame_system::Pallet::<T>::block_number(),
			},
		);

		// 10. Emit event
		Pallet::<T>::deposit_event(Event::Shielded {
			depositor,
			amount,
			commitment,
			encrypted_memo,
			leaf_index,
		});

		Ok(())
	}
}
