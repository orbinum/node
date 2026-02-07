//! Tests for encrypted_memo

use crate::domain::value_objects::EncryptedMemo;
use frame_support::parameter_types;

parameter_types! {
	pub const MaxMemoSize: u32 = 256;
}

type TestMemo = EncryptedMemo<MaxMemoSize>;

#[test]
fn encrypted_memo_creation_works() {
	let data = vec![1, 2, 3, 4, 5];
	let memo = TestMemo::new(data.clone()).unwrap();
	assert_eq!(memo.as_bytes(), &data);
}

#[test]
fn encrypted_memo_size_limit_works() {
	let too_large = vec![0u8; 257];
	let result = TestMemo::new(too_large);
	assert!(result.is_err());
}

#[test]
fn encrypted_memo_validation_works() {
	let valid = TestMemo::new(vec![1, 2, 3]).unwrap();
	assert!(valid.is_valid_size());

	let empty = TestMemo::from_bounded(frame_support::BoundedVec::default());
	assert!(!empty.is_valid_size()); // Empty is invalid
}

#[test]
fn encrypted_memo_is_empty_works() {
	let empty = TestMemo::from_bounded(frame_support::BoundedVec::default());
	assert!(empty.is_empty());

	let non_empty = TestMemo::new(vec![1]).unwrap();
	assert!(!non_empty.is_empty());
}
