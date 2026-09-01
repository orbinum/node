// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Unit tests for the pure validation functions — no runtime, no async.
//!
//! Covers every branch of `validate_relay_calldata` and every fee-floor case.

use ethereum_types::U256;
use fp_evm::ExitReason;

use crate::relay::{
	config::*,
	operations::{SELECTOR_PRIVATE_TRANSFER, SELECTOR_UNSHIELD},
	validation::*,
};

/// Build minimal valid calldata for the given selector and fee.
///
/// Head layout (first 228 bytes; the buffer is padded to the largest op's head):
/// ```text
///  [0..4]     selector
///  [4..36]    slot 0  — proof offset: 0xE0 (= 7×32 = 224, past all head slots)
///  [36..68]   slot 1  — bytes32 zeroes (root)
///  [68..100]  slot 2  — bytes32 zeroes (nullifier / nullifiers offset)
///  [100..132] slot 3  — uint32  zeroes (assetId / commitments offset)
///  [132..164] slot 4  — uint256 zeroes (amount / memos offset)
///  [164..196] slot 5  — bytes32 zeroes (recipient / assetId)
///  [196..228] slot 6  — uint256 fee
/// ```
fn build_calldata(selector: [u8; 4], fee_wei: u128) -> Vec<u8> {
	// unshield's head is 10 slots (4 + 320 = 324 bytes); privateTransfer's is
	// 8 slots (260). Build the larger of the two — extra zero head slots are
	// harmless, the fee stays at slot 6 either way.
	let mut data = vec![0u8; 324];
	data[..4].copy_from_slice(&selector);
	// Proof-bytes offset: 7×32 = 224 = 0xE0 (big-endian U256 → only last byte set)
	data[35] = 0xE0;
	// Fee at slot 6 = data[196..228]
	data[196..228].copy_from_slice(&U256::from(fee_wei).to_big_endian());
	data
}

// ── Length checks ──────────────────────────────────────────────────────

#[test]
fn rejects_empty_calldata() {
	assert_eq!(
		validate_relay_calldata(&[], MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("calldata too short")
	);
}

#[test]
fn rejects_calldata_227_bytes() {
	assert_eq!(
		validate_relay_calldata(&[0u8; 227], MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("calldata too short")
	);
}

#[test]
fn rejects_calldata_196_bytes_old_wrong_limit() {
	// Ensure the old (incorrect) limit of 196 is no longer accepted
	let data = vec![0u8; 196];
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("calldata too short")
	);
}

// ── Selector checks ────────────────────────────────────────────────────

/// The whitelist re-exports the decoder's constants, so the two cannot
/// disagree. What still needs proving is that those constants are keccak of
/// the signatures the client encodes against — a decoder renamed in lockstep
/// with this file would satisfy equality while rejecting every real call.
#[test]
fn selectors_are_keccak_of_the_abi_signatures() {
	let pt = sp_io::hashing::keccak_256(
		b"privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32)",
	);
	let un = sp_io::hashing::keccak_256(
		b"unshield(bytes,bytes32,bytes32,uint32,uint256,bytes32,uint256,bytes32,bytes,uint32)",
	);
	assert_eq!(pt[..4], SELECTOR_PRIVATE_TRANSFER);
	assert_eq!(un[..4], SELECTOR_UNSHIELD);
}

/// The runtime fallback list must agree with the client fallback list.
#[test]
fn fallback_selectors_contain_both_operations() {
	assert!(SELECTORS_FALLBACK.contains(&SELECTOR_UNSHIELD));
	assert!(SELECTORS_FALLBACK.contains(&SELECTOR_PRIVATE_TRANSFER));
}

/// privateTransfer calldata shorter than its 8-slot head (260 bytes) is
/// rejected even though it clears the global 228-byte minimum.
#[test]
fn rejects_private_transfer_calldata_between_228_and_260() {
	let mut data = build_calldata(SELECTOR_PRIVATE_TRANSFER, MIN_RELAY_FEE_FALLBACK);
	data.truncate(259);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("calldata too short")
	);
}

#[test]
fn rejects_unknown_selector() {
	let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
	data[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("unsupported selector")
	);
}

#[test]
fn rejects_shield_selector() {
	// shield = 0x781442b9 — NOT in relay whitelist
	let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
	data[..4].copy_from_slice(&[0x78, 0x14, 0x42, 0xb9]);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("unsupported selector")
	);
}

// ── Fee checks ─────────────────────────────────────────────────────────

#[test]
fn rejects_zero_fee() {
	let data = build_calldata(SELECTOR_UNSHIELD, 0);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("fee below minimum")
	);
}

#[test]
fn rejects_fee_one_wei_below_minimum() {
	let data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK - 1);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("fee below minimum")
	);
}

#[test]
fn rejects_fee_one_wei_below_minimum_private_transfer() {
	let data = build_calldata(SELECTOR_PRIVATE_TRANSFER, MIN_RELAY_FEE_FALLBACK - 1);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("fee below minimum")
	);
}

// ── Valid calldata ─────────────────────────────────────────────────────

#[test]
fn accepts_unshield_with_exact_minimum_fee() {
	let data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Ok(())
	);
}

#[test]
fn accepts_private_transfer_with_exact_minimum_fee() {
	let data = build_calldata(SELECTOR_PRIVATE_TRANSFER, MIN_RELAY_FEE_FALLBACK);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Ok(())
	);
}

#[test]
fn accepts_large_fee() {
	let data = build_calldata(SELECTOR_UNSHIELD, u128::MAX);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Ok(())
	);
}

#[test]
fn accepts_calldata_longer_than_228_bytes() {
	let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
	// Append tail bytes (proof data and dynamic arrays)
	data.extend_from_slice(&[0xaa; 128]);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Ok(())
	);
}

// ── Fee is read from the correct position ──────────────────────────────

#[test]
fn fee_at_slot_5_is_not_read_as_fee() {
	// Put a value >= MIN_RELAY_FEE_FALLBACK in slot 5 (data[164..196]) but zero in slot 6
	let mut data = build_calldata(SELECTOR_UNSHIELD, 0);
	// Overwrite slot 5 with MIN_RELAY_FEE_FALLBACK (this is recipient in unshield — NOT the fee)
	data[164..196].copy_from_slice(&U256::from(MIN_RELAY_FEE_FALLBACK).to_big_endian());
	// Fee (slot 6, data[196..228]) is still zero → should reject
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("fee below minimum")
	);
}

#[test]
fn fee_at_slot_6_is_correctly_read() {
	// Slot 5 = zero, slot 6 = MIN_RELAY_FEE_FALLBACK → should accept
	let data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Ok(())
	);
}

// ── Calldata size upper bound ──────────────────────────────────────────

#[test]
fn rejects_calldata_above_max_size() {
	let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
	data.resize(MAX_CALLDATA_BYTES + 1, 0u8);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Err("calldata too large")
	);
}

#[test]
fn accepts_calldata_at_exact_max_size() {
	let mut data = build_calldata(SELECTOR_UNSHIELD, MIN_RELAY_FEE_FALLBACK);
	data.resize(MAX_CALLDATA_BYTES, 0u8);
	assert_eq!(
		validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
		Ok(())
	);
}

// ── compute_effective_min_fee ──────────────────────────────────────────

/// At zero base_fee the governance floor must win.
#[test]
fn effective_min_fee_zero_base_fee_returns_governance_floor() {
	assert_eq!(
		compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, 0),
		MIN_RELAY_FEE_FALLBACK
	);
}

/// At 10 gwei the 2× gas floor (40_000_000_000_000_000) must beat governance (0.001 ORB).
#[test]
fn effective_min_fee_gas_floor_dominates_at_10_gwei() {
	let base_fee = 10_000_000_000u128; // 10 gwei
	let expected = (RELAY_GAS_LIMIT as u128) * 2 * base_fee;
	assert!(
		expected > MIN_RELAY_FEE_FALLBACK,
		"test precondition: gas floor must exceed governance"
	);
	assert_eq!(
		compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, base_fee),
		expected
	);
}

/// At 1 wei base_fee the gas floor (4_000_000) is far below governance (0.001 ORB).
#[test]
fn effective_min_fee_governance_floor_dominates_at_negligible_base_fee() {
	let base_fee = 1u128;
	let gas_floor = (RELAY_GAS_LIMIT as u128) * 2 * base_fee;
	assert!(
		MIN_RELAY_FEE_FALLBACK > gas_floor,
		"test precondition: governance must exceed gas floor"
	);
	assert_eq!(
		compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, base_fee),
		MIN_RELAY_FEE_FALLBACK
	);
}

/// The crossover point is at base_fee = governance / (gas_limit × 2) = 250_000_000 (0.25 gwei).
/// Below this threshold governance wins; at or above, the gas floor wins.
#[test]
fn effective_min_fee_crossover_at_250_mwei() {
	// threshold = 1_000_000_000_000_000 / (2_000_000 × 2) = 250_000_000
	let threshold = MIN_RELAY_FEE_FALLBACK / (RELAY_GAS_LIMIT as u128 * 2);
	// At threshold: 2×gas == governance, max returns governance.
	let at = compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, threshold);
	// One wei above: 2×gas > governance.
	let above = compute_effective_min_fee(MIN_RELAY_FEE_FALLBACK, threshold + 1);
	assert_eq!(at, MIN_RELAY_FEE_FALLBACK);
	assert!(above > MIN_RELAY_FEE_FALLBACK);
}

/// A governance floor higher than the gas floor must win regardless of base_fee.
#[test]
fn effective_min_fee_custom_high_governance_beats_gas_floor() {
	let governance = 100_000_000_000_000_000u128; // 0.1 ORB
	let base_fee = 1_000_000_000u128; // 1 gwei
	let gas_floor = (RELAY_GAS_LIMIT as u128) * 2 * base_fee;
	assert!(
		governance > gas_floor,
		"test precondition: governance must exceed gas floor"
	);
	assert_eq!(compute_effective_min_fee(governance, base_fee), governance);
}

/// Saturating arithmetic must not panic on u128::MAX inputs.
#[test]
fn effective_min_fee_saturates_without_panic() {
	let result = compute_effective_min_fee(u128::MAX, u128::MAX);
	assert_eq!(result, u128::MAX);
}

/// The calldata fee must be validated against `effective_min_fee`, not raw `min_fee_planck`.
/// Simulates the scenario where the gas floor is the active minimum.
#[test]
fn validate_calldata_rejects_fee_below_gas_floor_even_above_governance() {
	let governance = MIN_RELAY_FEE_FALLBACK;
	let base_fee = 10_000_000_000u128; // 10 gwei
	let gas_floor = (RELAY_GAS_LIMIT as u128) * 2 * base_fee; // 40_000_000_000_000_000
	assert!(gas_floor > governance);
	let effective = compute_effective_min_fee(governance, base_fee);
	// A fee that clears governance but not the gas floor is rejected.
	let below_gas_floor = gas_floor - 1;
	let data = build_calldata(SELECTOR_UNSHIELD, below_gas_floor);
	assert_eq!(
		validate_relay_calldata(&data, effective, &SELECTORS_FALLBACK),
		Err("fee below minimum")
	);
}

/// Fee that exactly equals the gas floor (when it dominates) must be accepted.
#[test]
fn validate_calldata_accepts_exact_gas_floor() {
	let governance = MIN_RELAY_FEE_FALLBACK;
	let base_fee = 10_000_000_000u128; // 10 gwei
	let effective = compute_effective_min_fee(governance, base_fee);
	let data = build_calldata(SELECTOR_UNSHIELD, effective);
	assert_eq!(
		validate_relay_calldata(&data, effective, &SELECTORS_FALLBACK),
		Ok(())
	);
}

// ── check_dry_run_exit ─────────────────────────────────────────────────

/// A successful EVM execution must pass the dry-run check.
#[test]
fn dry_run_exit_succeed_returns_ok() {
	use evm::ExitSucceed;
	assert!(check_dry_run_exit(&ExitReason::Succeed(ExitSucceed::Returned)).is_ok());
	assert!(check_dry_run_exit(&ExitReason::Succeed(ExitSucceed::Stopped)).is_ok());
	assert!(check_dry_run_exit(&ExitReason::Succeed(ExitSucceed::Suicided)).is_ok());
}

/// A revert (invalid ZK proof, double-spend nullifier, etc.) must be rejected.
#[test]
fn dry_run_exit_revert_returns_err() {
	use evm::ExitRevert;
	let result = check_dry_run_exit(&ExitReason::Revert(ExitRevert::Reverted));
	assert!(result.is_err());
	let msg = result.unwrap_err();
	assert!(
		msg.contains("calldata would fail on-chain"),
		"expected 'calldata would fail on-chain' in: {msg}"
	);
	assert!(msg.contains("Revert"), "expected 'Revert' in: {msg}");
}

/// An EVM error (OutOfGas, etc.) must be rejected.
#[test]
fn dry_run_exit_error_out_of_gas_returns_err() {
	use evm::ExitError;
	let result = check_dry_run_exit(&ExitReason::Error(ExitError::OutOfGas));
	assert!(result.is_err());
	let msg = result.unwrap_err();
	assert!(msg.contains("calldata would fail on-chain"), "{msg}");
	assert!(msg.contains("OutOfGas"), "expected 'OutOfGas' in: {msg}");
}

/// A call-too-deep EVM error (stack overflow) must be rejected.
#[test]
fn dry_run_exit_error_call_too_deep_returns_err() {
	use evm::ExitError;
	let result = check_dry_run_exit(&ExitReason::Error(ExitError::CallTooDeep));
	assert!(result.is_err());
	assert!(result.unwrap_err().contains("CallTooDeep"));
}

/// A fatal EVM error must be rejected.
#[test]
fn dry_run_exit_fatal_returns_err() {
	use evm::ExitFatal;
	let result = check_dry_run_exit(&ExitReason::Fatal(ExitFatal::NotSupported));
	assert!(result.is_err());
	let msg = result.unwrap_err();
	assert!(msg.contains("calldata would fail on-chain"), "{msg}");
	assert!(msg.contains("Fatal"), "expected 'Fatal' in: {msg}");
}

/// The error message must embed the exit reason so callers can surface it to users.
#[test]
fn dry_run_exit_error_message_includes_reason() {
	use evm::ExitError;
	let reason = ExitReason::Error(ExitError::OutOfFund);
	let err = check_dry_run_exit(&reason).unwrap_err();
	// The message should contain both the prefix and the specific variant.
	assert!(err.starts_with("calldata would fail on-chain:"), "{err}");
	assert!(err.contains("OutOfFund"), "{err}");
}
