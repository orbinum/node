//! Commitment Repository - Encapsulates commitment-related storage access

use crate::{
	application::DepositInfo,
	domain::Commitment,
	infrastructure::frame_types::EncryptedMemo,
	pallet::{BalanceOf, CommitmentMemos, Config, Deposits},
};
use frame_system::pallet_prelude::BlockNumberFor;

/// Repository for commitment-related storage operations
pub struct CommitmentRepository;

impl CommitmentRepository {
	/// Get deposit info for a commitment
	pub fn get_deposit_info<T: Config>(
		commitment: &Commitment,
	) -> Option<DepositInfo<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>> {
		Deposits::<T>::get(commitment)
	}

	/// Store deposit info
	pub fn store_deposit_info<T: Config>(
		commitment: Commitment,
		info: DepositInfo<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
	) {
		Deposits::<T>::insert(commitment, info);
	}

	/// Get encrypted memo for a commitment
	pub fn get_memo<T: Config>(commitment: &Commitment) -> Option<EncryptedMemo> {
		CommitmentMemos::<T>::get(commitment)
	}

	/// Store encrypted memo
	pub fn store_memo<T: Config>(commitment: Commitment, memo: EncryptedMemo) {
		CommitmentMemos::<T>::insert(commitment, memo);
	}

	/// Check if commitment exists (has memo stored)
	pub fn exists<T: Config>(commitment: &Commitment) -> bool {
		CommitmentMemos::<T>::contains_key(commitment)
	}
}
