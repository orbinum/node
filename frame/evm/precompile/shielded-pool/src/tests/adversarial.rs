//! Adversarial ABI battery: the attacker controls every byte of `input`.
//!
//! This is the only surface where untrusted bytes reach the node directly: an
//! EVM caller can send arbitrary calldata to the precompile address. Each test
//! below is an attempt to make the `shield` decoder panic, over-allocate, or read
//! out of bounds. A panic here is a node crash, not a rejected transaction.

use super::*;

/// Well-formed `shield` calldata, the base every attack mutates.
fn base() -> Vec<u8> {
	encode_shield(0, canon(0x0C), &[0xAB; 180])
}

/// Runs `input` with a non-zero `msg.value`, so decoding gets past the amount
/// check and reaches the offsets under attack.
fn run(input: Vec<u8>) -> Result<fp_evm::PrecompileOutput, PrecompileFailure> {
	let mut h = MockHandle::with_value(input, 1_000);
	ShieldedPoolPrecompile::<Test>::execute(&mut h)
}

#[test]
fn attack_truncation_at_every_offset_never_panics() {
	new_test_ext().execute_with(|| {
		let full = base();
		for len in 0..full.len() {
			// Must not panic. Any Result is acceptable.
			let _ = run(full[..len].to_vec());
		}
	});
}

/// An offset pointing back into the head makes the "length" word overlap the
/// caller-controlled head — a classic way to fabricate a huge length.
#[test]
fn attack_self_referential_offset_is_refused() {
	new_test_ext().execute_with(|| {
		let mut input = base();
		// Point the memo offset at slot 0 of the head: its length word is the
		// asset id, zero, so the memo decodes empty and is refused.
		input[4 + 64..4 + 96].copy_from_slice(&[0u8; 32]);
		expect_error(run(input));
	});
}

/// Every dynamic offset set to u256::MAX. word_to_usize must reject before any
/// slicing arithmetic happens.
#[test]
fn attack_max_u256_offsets_are_refused_not_truncated() {
	new_test_ext().execute_with(|| {
		for slot in [64usize, 96] {
			let mut input = base();
			input[4 + slot..4 + slot + 32].copy_from_slice(&[0xFFu8; 32]);
			expect_error(run(input));
		}
	});
}

/// 2^32 + small: the low 32 bits look like a valid offset while the value is
/// astronomically out of range — the shape a `low_u32` narrowing would let
/// through.
#[test]
fn attack_offset_above_u32_that_looks_benign_is_refused() {
	new_test_ext().execute_with(|| {
		for slot in [64usize, 96] {
			let mut input = base();
			let valid = U256::from_big_endian(&input[4 + slot..4 + slot + 32]);
			let sneaky = U256::from(1u64 << 32) + valid;
			input[4 + slot..4 + slot + 32].copy_from_slice(&sneaky.to_big_endian());
			expect_error(run(input));
		}
	});
}

/// A length word near usize::MAX must be refused before anything is copied.
#[test]
fn attack_huge_length_does_not_allocate() {
	new_test_ext().execute_with(|| {
		let mut input = base();
		let off = U256::from_big_endian(&input[4 + 96..4 + 128]).as_usize();
		let len_at = 4 + off;
		input[len_at..len_at + 32].copy_from_slice(&U256::from(1u64 << 30).to_big_endian());
		expect_error(run(input));
	});
}

/// asset_id and circuit_version live in u32 slots. A word with high bits set
/// must be rejected, never truncated to a plausible small number.
#[test]
fn attack_oversized_u32_slots_are_refused_not_truncated() {
	new_test_ext().execute_with(|| {
		for slot in [0usize, 128] {
			let mut input = base();
			// 2^32 exactly: truncates to 0 if the decoder uses low_u32.
			let word = U256::from(1u64 << 32).to_big_endian();
			input[4 + slot..4 + slot + 32].copy_from_slice(&word);
			expect_error_msg(run(input), "uint32 slot exceeds u32");
		}
	});
}

/// Random fuzz over the whole calldata: flip bytes everywhere and assert the
/// decoder never panics. Deterministic (fixed LCG) so a failure reproduces.
#[test]
fn attack_byte_fuzz_never_panics() {
	new_test_ext().execute_with(|| {
		let base = base();
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
			// Only requirement: no panic.
			let _ = run(input);
		}
	});
}

/// Fuzz with truncation AND mutation combined — the shape most likely to hit an
/// unchecked slice near a boundary.
#[test]
fn attack_truncated_fuzz_never_panics() {
	new_test_ext().execute_with(|| {
		let base = base();
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
			let _ = run(input);
		}
	});
}
