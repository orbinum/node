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
		if seed.is_multiple_of(3) {
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

// ─────────────────────────────────────────────────────────────────────────────
// Whitelist integrity
//
// `allowed_selectors` comes from governance storage over a Runtime API. These
// cover what happens when that list is itself hostile or malformed, which the
// node cannot prevent — only survive.
// ─────────────────────────────────────────────────────────────────────────────

/// A whitelist entry for an operation the node does not implement must not
/// promote the call: the selector matches the whitelist but no decoder claims
/// it, so `default_operations()` finds nothing and the call is refused.
///
/// This is the forward-compatibility path — governance enabling an operation
/// before the node ships it. Failing open here would relay calldata whose fee
/// slot has never been located, i.e. an unpriced call.
#[test]
fn attack_whitelist_full_of_unimplemented_selectors_fails_closed() {
	let hostile: Vec<[u8; 4]> = (0u8..64).map(|i| [i, i, i, i]).collect();
	for sel in &hostile {
		let mut data = base_private_transfer(u128::MAX);
		data[..4].copy_from_slice(sel);
		assert_eq!(
			validate_relay_calldata(&data, 1, &hostile),
			Err("unsupported selector"),
			"selector {sel:?} is whitelisted but unimplemented — must not relay"
		);
	}
}

/// A whitelist containing a real selector many times over must behave exactly
/// as if it appeared once. Guards the `contains` lookup against a governance
/// list padded to provoke quadratic scanning or an early-exit mistake.
#[test]
fn attack_whitelist_with_duplicate_entries_behaves_identically() {
	let padded = vec![SELECTOR_PRIVATE_TRANSFER; 4096];
	let data = base_private_transfer(u128::MAX);
	assert_eq!(validate_relay_calldata(&data, 1, &padded), Ok(()));
	assert_eq!(
		validate_relay_calldata(&data, u128::MAX, &padded),
		Ok(()),
		"a saturated fee word clears any floor, duplicates or not"
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// Fee floor arithmetic
//
// `compute_effective_min_fee` multiplies runtime-sourced values. Wrapping here
// would invert the comparison and let a zero-fee call through.
// ─────────────────────────────────────────────────────────────────────────────

/// The 2× gas floor must saturate, never wrap. A wrapped product would come out
/// *small*, and a small floor is one an attacker can clear with a nominal fee
/// while the relay pays real gas.
#[test]
fn attack_gas_floor_never_wraps_below_governance_minimum() {
	for base_fee in [
		u128::MAX,
		u128::MAX / 2,
		u128::MAX / RELAY_GAS_LIMIT as u128,
		1 << 127,
	] {
		let floor = compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, base_fee);
		assert!(
			floor >= MIN_RELAY_FEE_FALLBACK,
			"floor {floor} fell below governance minimum at base_fee={base_fee}"
		);
	}
}

/// Governance setting `min_fee_planck` to zero must not disable the gas floor:
/// the relay still has to earn back the gas it spends.
#[test]
fn attack_zero_governance_fee_still_charges_the_gas_floor() {
	let floor = compute_effective_min_fee(0, 1_000_000_000);
	assert_eq!(floor, 2 * RELAY_GAS_LIMIT as u128 * 1_000_000_000);
	assert!(
		floor > 0,
		"a zero governance fee must not mean a free relay"
	);

	// And with no gas price either, the floor is genuinely zero — documenting
	// that the free-relay case requires BOTH to be zero.
	assert_eq!(compute_effective_min_fee(0, 0), 0);
}

/// A fee exactly one planck below the floor is refused; exactly at it passes.
/// Pins the comparison as `<` rather than `<=`, at a boundary an attacker
/// controls precisely.
#[test]
fn attack_fee_one_below_floor_is_refused() {
	let floor = 1_000_000u128;
	let at = base_private_transfer(floor);
	let below = base_private_transfer(floor - 1);

	assert_eq!(
		validate_relay_calldata(&at, floor, &SELECTORS_FALLBACK),
		Ok(())
	);
	assert_eq!(
		validate_relay_calldata(&below, floor, &SELECTORS_FALLBACK),
		Err("fee below minimum")
	);
}

// ─────────────────────────────────────────────────────────────────────────────
// Selector confusion
//
// The two operations share a head up to slot 6 but diverge past it. A call
// must be measured against the length of the operation it claims to be.
// ─────────────────────────────────────────────────────────────────────────────

/// privateTransfer-length calldata (260) carrying the unshield selector must be
/// refused: unshield needs 324. Otherwise the shorter layout would be read
/// against the longer one's expectations.
#[test]
fn attack_unshield_selector_on_private_transfer_length_is_refused() {
	let mut data = base_private_transfer(u128::MAX);
	data[..4].copy_from_slice(&SELECTOR_UNSHIELD);
	assert_eq!(data.len(), 260);
	assert_eq!(
		validate_relay_calldata(&data, 1, &SELECTORS_FALLBACK),
		Err("calldata too short"),
		"260 bytes is valid for privateTransfer but 64 short for unshield"
	);
}

/// The fee slot must be read from the same offset regardless of which selector
/// is claimed — both layouts agree up to slot 6, and that agreement is what
/// makes a single `fee_at_slot_6` correct.
#[test]
fn attack_fee_slot_is_stable_across_both_selectors() {
	let fee = 12_345_678u128;
	let mut pt = base_private_transfer(fee);
	let mut un = pt.clone();
	un.resize(324, 0);
	un[..4].copy_from_slice(&SELECTOR_UNSHIELD);
	pt[..4].copy_from_slice(&SELECTOR_PRIVATE_TRANSFER);

	// Both must accept at exactly `fee` and refuse at `fee + 1`.
	for data in [&pt, &un] {
		assert_eq!(
			validate_relay_calldata(data, fee, &SELECTORS_FALLBACK),
			Ok(())
		);
		assert_eq!(
			validate_relay_calldata(data, fee + 1, &SELECTORS_FALLBACK),
			Err("fee below minimum")
		);
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Size boundary
// ─────────────────────────────────────────────────────────────────────────────

/// Calldata at exactly the cap is accepted, one byte over is refused, and
/// neither allocates proportionally to the claimed size. Pins `>` rather than
/// `>=` at the one boundary an attacker pays nothing to probe.
#[test]
fn attack_calldata_cap_boundary_is_exact() {
	let mut at_cap = base_private_transfer(u128::MAX);
	at_cap.resize(MAX_CALLDATA_BYTES, 0);
	assert_eq!(
		validate_relay_calldata(&at_cap, 1, &SELECTORS_FALLBACK),
		Ok(()),
		"exactly at the cap must be accepted"
	);

	let mut over = at_cap.clone();
	over.push(0);
	assert_eq!(
		validate_relay_calldata(&over, 1, &SELECTORS_FALLBACK),
		Err("calldata too large")
	);
}

/// The size check must come before any per-operation work: an oversized body
/// is refused for its size even when its selector is unknown, so a huge
/// unknown-selector call cannot be used to force extra scanning.
#[test]
fn attack_oversized_unknown_selector_is_refused_on_size_first() {
	let mut data = vec![0xFFu8; MAX_CALLDATA_BYTES + 1];
	data[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
	assert_eq!(
		validate_relay_calldata(&data, 1, &SELECTORS_FALLBACK),
		Err("calldata too large")
	);
}
