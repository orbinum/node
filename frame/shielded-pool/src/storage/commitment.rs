//! Commitment storage: each note's encrypted memo, and whether a commitment is
//! already in the forest.

use crate::{
	pallet::{CommitmentMemos, CommitmentToLeafIndex, Config},
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
	/// Whether `commitment` is a leaf of the forest. Read from the leaf index,
	/// which every insertion writes and nothing removes — not from the memos,
	/// which a leaf inserted without one would escape.
	pub fn exists<T: Config>(commitment: &Commitment) -> bool {
		CommitmentToLeafIndex::<T>::contains_key(commitment)
	}
}
