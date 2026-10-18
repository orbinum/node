use super::{encode_transfer, revert_reason, run};
use crate::{
	mock::{bob_account, new_test_ext, MockHandle},
	SEL_TRANSFER, SEL_TRANSFER_KEEP_ALIVE,
};

#[test]
fn selector_too_short_reverts() {
	new_test_ext().execute_with(|| {
		for len in 0..4 {
			let reason = revert_reason(run(&mut MockHandle::new(vec![0xAA; len])));
			assert_eq!(reason, "input too short: missing selector");
		}
	});
}

#[test]
fn unknown_selector_reverts() {
	new_test_ext().execute_with(|| {
		let reason = revert_reason(run(&mut MockHandle::new(vec![0xDE, 0xAD, 0xBE, 0xEF])));
		assert_eq!(reason, "unknown selector");
	});
}

#[test]
fn calldata_must_be_exactly_two_words() {
	new_test_ext().execute_with(|| {
		let full = encode_transfer(SEL_TRANSFER, bob_account().into(), 1);
		for input in [
			full[..4].to_vec(),
			full[..67].to_vec(),
			[full.clone(), vec![0]].concat(),
		] {
			let reason = revert_reason(run(&mut MockHandle::new(input)));
			assert_eq!(reason, "calldata must be selector + bytes32 + uint256");
		}
	});
}

#[test]
fn value_above_u128_reverts() {
	new_test_ext().execute_with(|| {
		for selector in [SEL_TRANSFER, SEL_TRANSFER_KEEP_ALIVE] {
			let mut input = encode_transfer(selector, bob_account().into(), 0);
			input[36] = 0x01; // a bit in the high 16 bytes of the uint256
			assert_eq!(
				revert_reason(run(&mut MockHandle::new(input))),
				"value overflows u128"
			);
		}
	});
}

#[test]
fn selectors_are_the_keccak_of_their_signatures() {
	use sp_io::hashing::keccak_256;
	assert_eq!(SEL_TRANSFER, keccak_256(b"transfer(bytes32,uint256)")[..4]);
	assert_eq!(
		SEL_TRANSFER_KEEP_ALIVE,
		keccak_256(b"transferKeepAlive(bytes32,uint256)")[..4]
	);
}
