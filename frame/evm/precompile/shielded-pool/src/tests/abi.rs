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
fn abi_read_u256_reads_the_full_word() {
	let mut params = [0u8; 64];
	params[32..64].copy_from_slice(&[0xFF; 32]);
	assert_eq!(crate::abi::read_u256(&params, 32).unwrap(), U256::MAX);
	expect_error(lift(crate::abi::read_u256(&params, 33)));
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

#[test]
fn abi_decode_bytes32_array_works() {
	let mut params = vec![0u8; 160];
	params[31] = 32; // offset
	params[63] = 2; // count
	params[64..96].copy_from_slice(&[0xAAu8; 32]);
	params[96..128].copy_from_slice(&[0xBBu8; 32]);
	let out = crate::abi::decode_bytes32_array_at_slot(&params, 0, usize::MAX).unwrap();
	assert_eq!(out.len(), 2);
	assert_eq!(out[0], [0xAAu8; 32]);
	assert_eq!(out[1], [0xBBu8; 32]);
}

#[test]
fn abi_decode_bytes32_array_empty() {
	// count=0; the count word is left zeroed.
	let mut params = vec![0u8; 64];
	params[31] = 32; // offset
	let out = crate::abi::decode_bytes32_array_at_slot(&params, 0, usize::MAX).unwrap();
	assert!(out.is_empty());
}

#[test]
fn abi_decode_bytes32_array_rejects_truncated() {
	let mut params = vec![0u8; 96];
	params[31] = 32;
	params[63] = 3; // asks for 3×32=96 bytes but only 32 available
	expect_error(lift(crate::abi::decode_bytes32_array_at_slot(
		&params,
		0,
		usize::MAX,
	)));
}

#[test]
fn abi_decode_bytes_array_works() {
	let mut params = vec![0u8; 288];
	params[31] = 32; // outer offset
	params[63] = 2; // count
	params[95] = 64; // rel offset element 0
	params[127] = 128; // rel offset element 1
					// element 0: len=1, data=0xAA
	params[159] = 1;
	params[160] = 0xAA;
	// element 1: len=2, data=0xBB 0xCC
	params[223] = 2;
	params[224] = 0xBB;
	params[225] = 0xCC;
	let out = crate::abi::decode_bytes_array_at_slot(&params, 0, usize::MAX, usize::MAX).unwrap();
	assert_eq!(out, vec![vec![0xAAu8], vec![0xBBu8, 0xCC]]);
}

#[test]
fn abi_decode_bytes_array_rejects_invalid_rel_offset() {
	let mut params = vec![0u8; 96];
	params[31] = 32;
	params[63] = 1;
	params[95] = 200; // rel offset way out of bounds
	expect_error(lift(crate::abi::decode_bytes_array_at_slot(
		&params,
		0,
		usize::MAX,
		usize::MAX,
	)));
}

/// `bytes[]` whose pointers all alias one blob: each element would copy it
/// again. The count bound rejects it before a single byte is copied.
#[test]
fn abi_decode_bytes_array_rejects_aliased_elements_past_the_count_bound() {
	let count = 1_000usize;
	let blob_len = 4_096usize;
	// head(32) | count(32) | count pointers | blob len(32) | blob
	let blob_at = 32 * count; // relative to the data base
	let mut params = vec![0u8; 64 + 32 * count + 32 + blob_len];
	params[31] = 32; // array offset
	params[32..64].copy_from_slice(&u256_word(count));
	for i in 0..count {
		let p = 64 + 32 * i;
		params[p..p + 32].copy_from_slice(&u256_word(blob_at));
	}
	let len_at = 64 + blob_at;
	params[len_at..len_at + 32].copy_from_slice(&u256_word(blob_len));

	expect_error(lift(crate::abi::decode_bytes_array_at_slot(
		&params, 0, 2, 180,
	)));
	// Unbounded, the same calldata decodes into count × blob_len bytes.
	let unbounded =
		crate::abi::decode_bytes_array_at_slot(&params, 0, usize::MAX, usize::MAX).unwrap();
	assert_eq!(unbounded.len() * unbounded[0].len(), count * blob_len);
}

#[test]
fn abi_decode_bytes_array_rejects_an_item_past_the_length_bound() {
	let mut params = vec![0u8; 32 + 32 + 32 + 32 + 181];
	params[31] = 32; // array offset
	params[63] = 1; // count
	params[95] = 32; // element 0 relative offset
	params[96..128].copy_from_slice(&u256_word(181));
	expect_error(lift(crate::abi::decode_bytes_array_at_slot(
		&params, 0, 2, 180,
	)));
	assert!(crate::abi::decode_bytes_array_at_slot(&params, 0, 2, 181).is_ok());
}

#[test]
fn abi_decode_bytes32_array_rejects_past_the_count_bound() {
	let items = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
	let mut params = u256_word(32).to_vec();
	params.extend_from_slice(&encode_bytes32_array(&items));
	expect_error(lift(crate::abi::decode_bytes32_array_at_slot(
		&params, 0, 2,
	)));
	assert_eq!(
		crate::abi::decode_bytes32_array_at_slot(&params, 0, 3)
			.unwrap()
			.len(),
		3
	);
}
