// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Adversarial tests: malformed, hostile, and boundary calldata.
//!
//! These assert the relay rejects rather than panics. Every input here is one a
//! caller can send over the unauthenticated RPC.

use crate::relay::{
	config::*,
	operations::{SELECTOR_PRIVATE_TRANSFER, SELECTOR_UNSHIELD},
	validation::*,
};

/// Well-formed base calldata for privateTransfer, long enough to pass the
/// length gates so the later checks are actually reached.
fn base_private_transfer(fee: u128) -> Vec<u8> {
	let mut d = SELECTOR_PRIVATE_TRANSFER.to_vec();
	d.resize(4 + 256, 0);
	let mut fee_word = [0u8; 32];
	fee_word[16..32].copy_from_slice(&fee.to_be_bytes());
	d[4 + 192..4 + 224].copy_from_slice(&fee_word);
	d
}

/// Every length from 0 to just past the minimum: no panic, and the boundary
/// must be exact (227 rejected, 228 reaches the selector check).
#[test]
fn attack_every_calldata_length_is_handled_without_panic() {
	for len in 0..400usize {
		let data = vec![0xAAu8; len];
		let _ = validate_relay_calldata(&data, 0, &SELECTORS_FALLBACK);
	}
	// Boundary is exact.
	assert_eq!(
		validate_relay_calldata(&vec![0u8; 227], 0, &SELECTORS_FALLBACK),
		Err("calldata too short")
	);
	// 228 bytes of zeros passes the length gate and dies on the selector.
	assert_eq!(
		validate_relay_calldata(&vec![0u8; 228], 0, &SELECTORS_FALLBACK),
		Err("unsupported selector")
	);
}

/// A valid selector with calldata between the global 228 gate and the
/// operation's own minimum must be refused by the per-op gate, not read
/// past its end.
#[test]
fn attack_length_between_global_and_per_op_minimum_is_refused() {
	for len in 228..260usize {
		let mut d = SELECTOR_PRIVATE_TRANSFER.to_vec();
		d.resize(len, 0);
		assert_eq!(
			validate_relay_calldata(&d, 0, &SELECTORS_FALLBACK),
			Err("calldata too short"),
			"privateTransfer at {len} bytes must be refused"
		);
	}
	for len in 228..324usize {
		let mut d = SELECTOR_UNSHIELD.to_vec();
		d.resize(len, 0);
		assert_eq!(
			validate_relay_calldata(&d, 0, &SELECTORS_FALLBACK),
			Err("calldata too short"),
			"unshield at {len} bytes must be refused"
		);
	}
}

/// The calldata cap must hold exactly: one byte over is refused, and the
/// oversized buffer must never be walked.
#[test]
fn attack_oversized_calldata_is_refused_at_the_exact_boundary() {
	let mut ok = base_private_transfer(0);
	ok.resize(MAX_CALLDATA_BYTES, 0);
	// At the cap: passes the size gate (fails later or succeeds, but not "too large").
	assert_ne!(
		validate_relay_calldata(&ok, 0, &SELECTORS_FALLBACK),
		Err("calldata too large")
	);

	let mut over = base_private_transfer(0);
	over.resize(MAX_CALLDATA_BYTES + 1, 0);
	assert_eq!(
		validate_relay_calldata(&over, 0, &SELECTORS_FALLBACK),
		Err("calldata too large")
	);
}

/// A fee word of all 0xFF (u256::MAX) must saturate, never panic, and must
/// COMPARE as above any minimum — a panic here is remote node death.
#[test]
fn attack_max_fee_word_saturates_and_passes_the_floor() {
	let mut d = base_private_transfer(0);
	d[4 + 192..4 + 224].copy_from_slice(&[0xFFu8; 32]);
	assert_eq!(
		validate_relay_calldata(&d, u128::MAX, &SELECTORS_FALLBACK),
		Ok(()),
		"a saturated fee must clear even the maximum floor"
	);
}

/// A fee one planck below the floor must be refused; exactly at the floor
/// must pass. Off-by-one here is free money for the attacker or a broken relay.
#[test]
fn attack_fee_floor_boundary_is_exact() {
	let floor = 1_000_000_000_000_000u128;
	assert_eq!(
		validate_relay_calldata(
			&base_private_transfer(floor - 1),
			floor,
			&SELECTORS_FALLBACK
		),
		Err("fee below minimum")
	);
	assert_eq!(
		validate_relay_calldata(&base_private_transfer(floor), floor, &SELECTORS_FALLBACK),
		Ok(())
	);
}

/// An empty whitelist must reject everything — a governance misconfiguration
/// must fail closed, never open.
#[test]
fn attack_empty_whitelist_fails_closed() {
	assert_eq!(
		validate_relay_calldata(&base_private_transfer(0), 0, &[]),
		Err("unsupported selector")
	);
}

/// A selector the governance whitelist allows but the node does not
/// implement must be refused, not dispatched to a wrong decoder.
#[test]
fn attack_whitelisted_but_unimplemented_selector_is_refused() {
	let mut d = base_private_transfer(0);
	d[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
	assert_eq!(
		validate_relay_calldata(&d, 0, &[[0xDE, 0xAD, 0xBE, 0xEF]]),
		Err("unsupported selector"),
		"a selector with no registered operation must fail closed"
	);
}

/// The gas floor must saturate rather than overflow: base_fee near u128::MAX
/// multiplied by 2×gas_limit would wrap and produce a floor of ~0, letting
/// every transfer through for free.
#[test]
fn attack_gas_floor_saturates_instead_of_wrapping() {
	let floor = compute_effective_min_fee(1, u128::MAX);
	assert_eq!(
		floor,
		u128::MAX,
		"a wrapped multiplication would collapse the floor to near zero"
	);
	// And a realistic value still behaves.
	let normal = compute_effective_min_fee(1_000_000_000_000_000, 1_000_000_000);
	assert!(normal >= 1_000_000_000_000_000);
}

/// Deterministic byte fuzz over the whole calldata: the only requirement is
/// that no input, however malformed, panics the validator.
#[test]
fn attack_calldata_fuzz_never_panics() {
	let base = base_private_transfer(1_000_000_000_000_000);
	let mut seed: u64 = 0xDEADBEEFCAFEBABE;
	for _ in 0..20_000 {
		let mut data = base.clone();
		seed = seed
			.wrapping_mul(6364136223846793005)
			.wrapping_add(1442695040888963407);
		let muts = 1 + (seed >> 60) as usize % 12;
		for _ in 0..muts {
			seed = seed
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let pos = (seed >> 33) as usize % data.len();
			seed = seed
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			data[pos] = (seed >> 40) as u8;
		}
		// Sometimes truncate too.
		seed = seed
			.wrapping_mul(6364136223846793005)
			.wrapping_add(1442695040888963407);
		if seed % 3 == 0 {
			let cut = (seed >> 33) as usize % data.len().max(1);
			data.truncate(cut);
		}
		let _ = validate_relay_calldata(&data, 1_000_000_000_000_000, &SELECTORS_FALLBACK);
	}
}

/// Fuzz the fee slot specifically with full-width random words — this is the
/// field that historically panicked via `U256::as_u128()`.
#[test]
fn attack_fee_slot_fuzz_never_panics() {
	let mut seed: u64 = 0x1234_5678_9ABC_DEF0;
	for _ in 0..20_000 {
		let mut d = base_private_transfer(0);
		for byte in d[4 + 192..4 + 224].iter_mut() {
			seed = seed
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			*byte = (seed >> 40) as u8;
		}
		let _ = validate_relay_calldata(&d, 1_000_000_000_000_000, &SELECTORS_FALLBACK);
	}
}
