//! Router and ABI decoders: pure decoding, no pallet state.

use super::*;

// ─── Router ──────────────────────────────────────────────────────────────────

#[test]
fn router_rejects_empty_input() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(vec![]);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn router_rejects_3_byte_selector() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(crate::calls::shield::SELECTOR[..3].to_vec());
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

#[test]
fn router_rejects_unknown_selector() {
	new_test_ext().execute_with(|| {
		let mut h = MockHandle::new(vec![0xff, 0xff, 0xff, 0xff]);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

/// An unknown selector or garbage reverts rather than burning the caller's gas.
#[test]
fn an_unknown_selector_reverts() {
	new_test_ext().execute_with(|| {
		for input in [vec![0x88, 0xd9, 0xde, 0xba], vec![0x01, 0x02]] {
			let mut h = MockHandle::new(input);
			assert!(matches!(
				ShieldedPoolPrecompile::<Test>::execute(&mut h),
				Err(PrecompileFailure::Revert { .. })
			));
		}
	});
}

/// The spend and relay-fee functions are retired: each reverts with the same
/// reason, well-formed calldata or not.
#[test]
fn retired_selectors_revert() {
	new_test_ext().execute_with(|| {
		for selector in [
			[0x63, 0xd0, 0xb9, 0xa0], // privateTransfer
			[0x4e, 0x50, 0x53, 0x48], // unshield
			[0xc9, 0xb2, 0x35, 0xff], // commitRelay
			[0x2a, 0x32, 0x74, 0xdd], // claimRelayFees
		] {
			for tail in [vec![], vec![0u8; 320]] {
				let mut input = selector.to_vec();
				input.extend_from_slice(&tail);
				let mut h = MockHandle::new(input);
				expect_error_msg(
					ShieldedPoolPrecompile::<Test>::execute(&mut h),
					"retired in spec 19: submit spends unsigned via Substrate",
				);
			}
		}
	});
}

// ─── Fixed-width decoders ────────────────────────────────────────────────────

#[test]
fn abi_read_u32_max_value() {
	let mut slot = [0u8; 32];
	slot[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
	assert_eq!(crate::abi::read_u32(&slot, 0).unwrap(), u32::MAX);
}

#[test]
fn abi_read_u32_zero() {
	assert_eq!(crate::abi::read_u32(&[0u8; 32], 0).unwrap(), 0u32);
}

#[test]
fn abi_read_u32_rejects_short_slot() {
	expect_error(lift(crate::abi::read_u32(&[0u8; 31], 0)));
}

/// A `uint32` is right-aligned in its word; every value survives the round trip.
#[test]
fn abi_read_u32_round_trips() {
	for id in [0u32, 1, 42, u32::MAX] {
		let mut slot = [0u8; 32];
		slot[28..32].copy_from_slice(&id.to_be_bytes());
		assert_eq!(
			crate::abi::read_u32(&slot, 0).unwrap(),
			id,
			"{id} must round-trip"
		);
	}
}

#[test]
fn abi_read_u32_reads_the_slot_at_its_offset() {
	let mut params = [0u8; 64];
	params[60..64].copy_from_slice(&7u32.to_be_bytes());
	assert_eq!(crate::abi::read_u32(&params, 32).unwrap(), 7);
	expect_error(lift(crate::abi::read_u32(&params, 33)));
}

#[test]
fn abi_read_bytes32_copies_all_bytes() {
	let mut params = [0u8; 64];
	for i in 0..32 {
		params[32 + i] = i as u8;
	}
	let out = crate::abi::read_bytes32(&params, 32).unwrap();
	for i in 0..32u8 {
		assert_eq!(out[i as usize], i);
	}
}

#[test]
fn abi_read_bytes32_rejects_out_of_bounds() {
	expect_error(lift(crate::abi::read_bytes32(&[0u8; 31], 0)));
}

// ─── Dynamic decoders ────────────────────────────────────────────────────────

#[test]
fn abi_decode_bytes_at_slot_works() {
	let mut params = vec![0u8; 128];
	params[31] = 32; // offset pointer
	params[63] = 3; // length
	params[64..67].copy_from_slice(b"abc");
	assert_eq!(
		crate::abi::decode_bytes_at_slot(&params, 0).unwrap(),
		b"abc"
	);
}

#[test]
fn abi_decode_bytes_at_slot_rejects_invalid_offset() {
	let mut params = vec![0u8; 64];
	params[31] = 200; // offset beyond params
	expect_error(lift(crate::abi::decode_bytes_at_slot(&params, 0)));
}

#[test]
fn abi_decode_bytes_at_slot_rejects_truncated_data() {
	// offset=32, length=100, but only 32 bytes of data follow
	let mut params = vec![0u8; 96];
	params[31] = 32;
	params[63] = 100;
	expect_error(lift(crate::abi::decode_bytes_at_slot(&params, 0)));
}

#[test]
fn abi_decode_bytes_at_slot_empty_payload() {
	// length=0 is valid; the length word is left zeroed.
	let mut params = vec![0u8; 64];
	params[31] = 32; // offset
	assert_eq!(crate::abi::decode_bytes_at_slot(&params, 0).unwrap(), b"");
}
