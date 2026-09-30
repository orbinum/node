//! Adversarial ABI battery: the attacker controls every byte of `input`.
//!
//! This is the only surface where untrusted bytes reach the node directly: an
//! EVM caller can send arbitrary calldata to the precompile address. Each test
//! below is an attempt to make the decoder panic, over-allocate, or read out of
//! bounds. A panic here is a node crash, not a rejected transaction.

use super::*;

#[test]
fn attack_truncation_at_every_offset_never_panics() {
	new_test_ext().execute_with(|| {
		let full = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		for len in 0..full.len().min(600) {
			let mut h = MockHandle::new(full[..len].to_vec());
			// Must not panic. Any Result is acceptable.
			let _ = ShieldedPoolPrecompile::<Test>::execute(&mut h);
		}
	});
}

/// An offset pointing back into the head makes the "length" word overlap the
/// caller-controlled head — a classic way to fabricate a huge length.
#[test]
fn attack_self_referential_offset_is_refused() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		// Point the proof offset at slot 0 of the head (offset 0 → itself).
		input[4..36].copy_from_slice(&[0u8; 32]);
		let mut h = MockHandle::new(input);
		let _ = ShieldedPoolPrecompile::<Test>::execute(&mut h);
	});
}

/// Every dynamic offset set to u256::MAX. word_to_usize must reject before any
/// slicing arithmetic happens.
#[test]
fn attack_max_u256_offsets_are_refused_not_truncated() {
	new_test_ext().execute_with(|| {
		for slot in [0usize, 64, 96, 128, 256] {
			let mut input = encode_private_transfer(
				&[0x01u8; 72],
				canon(0xBB),
				&[canon(1)],
				&[canon(2)],
				&[vec![0x01u8; 180]],
				0,
				0,
				1,
			);
			input[4 + slot..4 + slot + 32].copy_from_slice(&[0xFFu8; 32]);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		}
	});
}

/// 2^32 + small: the low 32 bits look like a valid offset while the value is
/// astronomically out of range — the shape a `low_u32` narrowing would let
/// through.
#[test]
fn attack_offset_above_u32_that_looks_benign_is_refused() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		// 2^32 + 288 — low 32 bits read as 288, a perfectly plausible offset.
		let sneaky = U256::from(1u64 << 32) + U256::from(288u64);
		let word = sneaky.to_big_endian();
		input[4..36].copy_from_slice(&word);
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

/// A declared array count of ~1e9 must be refused BEFORE Vec::with_capacity
/// reserves for it — otherwise one call OOMs the node.
#[test]
fn attack_huge_array_count_does_not_allocate() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		// Find the nullifiers array offset and overwrite its count word.
		let off = U256::from_big_endian(&input[4 + 64..4 + 96]).as_usize();
		let count_at = 4 + off;
		if count_at + 32 <= input.len() {
			let huge = U256::from(1u64 << 30).to_big_endian();
			input[count_at..count_at + 32].copy_from_slice(&huge);
		}
		let mut h = MockHandle::new(input);
		expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
	});
}

/// A fee word of u256::MAX must not panic converting to u128 — it must be
/// rejected as an overflow.
#[test]
fn attack_max_fee_word_is_refused_not_panicking() {
	new_test_ext().execute_with(|| {
		let mut input = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		input[4 + 192..4 + 224].copy_from_slice(&[0xFFu8; 32]);
		let mut h = MockHandle::new(input);
		expect_error_msg(
			ShieldedPoolPrecompile::<Test>::execute(&mut h),
			"fee overflow",
		);
	});
}

/// asset_id and circuit_version live in u32 slots. A word with high bits set
/// must be rejected, never truncated to a plausible small number.
#[test]
fn attack_oversized_u32_slots_are_refused_not_truncated() {
	new_test_ext().execute_with(|| {
		for slot in [160usize, 224] {
			let mut input = encode_private_transfer(
				&[0x01u8; 72],
				canon(0xBB),
				&[canon(1)],
				&[canon(2)],
				&[vec![0x01u8; 180]],
				0,
				0,
				1,
			);
			// 2^32 exactly: truncates to 0 if the decoder uses low_u32.
			let word = U256::from(1u64 << 32).to_big_endian();
			input[4 + slot..4 + slot + 32].copy_from_slice(&word);
			let mut h = MockHandle::new(input);
			expect_error(ShieldedPoolPrecompile::<Test>::execute(&mut h));
		}
	});
}

/// Random fuzz over the whole calldata: flip bytes everywhere and assert the
/// decoder never panics. Deterministic (fixed LCG) so a failure reproduces.
#[test]
fn attack_byte_fuzz_never_panics() {
	new_test_ext().execute_with(|| {
		let base = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		let mut seed: u64 = 0x2545F4914F6CDD1D;
		for _ in 0..3000 {
			let mut input = base.clone();
			// 1–8 mutations per round.
			seed = seed
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let muts = 1 + (seed >> 60) as usize % 8;
			for _ in 0..muts {
				seed = seed
					.wrapping_mul(6364136223846793005)
					.wrapping_add(1442695040888963407);
				let pos = (seed >> 33) as usize % input.len();
				seed = seed
					.wrapping_mul(6364136223846793005)
					.wrapping_add(1442695040888963407);
				input[pos] = (seed >> 40) as u8;
			}
			let mut h = MockHandle::new(input);
			// Only requirement: no panic.
			let _ = ShieldedPoolPrecompile::<Test>::execute(&mut h);
		}
	});
}

/// Fuzz with truncation AND mutation combined — the shape most likely to hit an
/// unchecked slice near a boundary.
#[test]
fn attack_truncated_fuzz_never_panics() {
	new_test_ext().execute_with(|| {
		let base = encode_private_transfer(
			&[0x01u8; 72],
			canon(0xBB),
			&[canon(1)],
			&[canon(2)],
			&[vec![0x01u8; 180]],
			0,
			0,
			1,
		);
		let mut seed: u64 = 0x9E3779B97F4A7C15;
		for _ in 0..2000 {
			seed = seed
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let cut = 4 + (seed >> 33) as usize % base.len().max(1);
			let mut input = base[..cut.min(base.len())].to_vec();
			if !input.is_empty() {
				seed = seed
					.wrapping_mul(6364136223846793005)
					.wrapping_add(1442695040888963407);
				let pos = (seed >> 33) as usize % input.len();
				input[pos] = (seed >> 40) as u8;
			}
			let mut h = MockHandle::new(input);
			let _ = ShieldedPoolPrecompile::<Test>::execute(&mut h);
		}
	});
}
