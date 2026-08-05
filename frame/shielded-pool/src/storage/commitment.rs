//! Commitment memo storage.
//!
//! Maps a note commitment to its encrypted memo. Membership here doubles as the
//! duplicate-commitment check, so `exists` is what keeps the same commitment
//! from being inserted into the tree twice.

use crate::{
	pallet::{CommitmentMemos, Config},
	types::{Commitment, EncryptedMemo},
};

// CommitmentRepository

pub struct CommitmentRepository;

impl CommitmentRepository {
	pub fn get_memo<T: Config>(commitment: &Commitment) -> Option<EncryptedMemo> {
		CommitmentMemos::<T>::get(commitment)
	}
	pub fn store_memo<T: Config>(commitment: Commitment, memo: EncryptedMemo) {
		CommitmentMemos::<T>::insert(commitment, memo);
	}
	pub fn exists<T: Config>(commitment: &Commitment) -> bool {
		CommitmentMemos::<T>::contains_key(commitment)
	}
}
