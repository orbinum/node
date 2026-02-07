//! Tests for deposit_dto

use crate::application::dto::DepositInfo;

type AccountId = u64;
type Balance = u128;
type BlockNumber = u64;

#[test]
fn new_deposit_info_works() {
	let info = DepositInfo::<AccountId, Balance, BlockNumber>::new(1, 1000, 100);

	assert_eq!(*info.depositor(), 1);
	assert_eq!(*info.amount(), 1000);
	assert_eq!(*info.block_number(), 100);
}
