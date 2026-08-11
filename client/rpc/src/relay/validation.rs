// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Pure calldata validation — no runtime or async dependencies.
//!
//! All functions here are synchronous and fully unit-testable without spinning up
//! a Substrate node.  The tests at the bottom of this file cover every validation
//! branch and fee-floor scenario.

use fp_evm::ExitReason;

use super::operations::default_operations;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum fee per gas paid by the relay tx (10 gwei).
/// Used when building the EIP-1559 transaction.
pub(crate) const MAX_FEE_PER_GAS_WEI: u64 = 10_000_000_000;

/// Gas limit used for relay transactions.
pub(crate) const RELAY_GAS_LIMIT: u64 = 2_000_000;

/// Last-resort fallback minimum fee used ONLY when the Runtime API call fails entirely.
///
/// The authoritative value lives in `pallet-relayer::MinRelayFee` storage and is
/// modifiable by governance via `set_min_relay_fee`. This constant is never used in
/// normal operation — it only kicks in if the node runs a pre-API runtime that does
/// not expose `relay_config()`.
///
/// Set to the same default as `pallet-relayer::DefaultMinRelayFee` (0.001 ORB) so all
/// three sources are identical out of the box.
pub(crate) const MIN_RELAY_FEE_FALLBACK: u128 = 1_000_000_000_000_000; // 0.001 ORB in planck

/// Static fallback selector whitelist for when the Runtime API is unavailable.
///
/// Built from the operation constants rather than re-typed, so this list cannot
/// drift from what `default_operations` actually dispatches on.
pub(crate) const SELECTORS_FALLBACK: [[u8; 4]; 2] = [
	super::operations::SELECTOR_UNSHIELD,
	super::operations::SELECTOR_PRIVATE_TRANSFER,
];

/// Maximum calldata size accepted by the relay (32 KB).
///
/// A realistic shielded-pool calldata is ~2–5 KB (256 B Groth16 proof + ABI head + Merkle path).
/// This cap prevents DoS: an attacker could craft calldata that passes selector/fee checks
/// but carries megabytes of data the relayer would have to pay calldata gas for.
pub(crate) const MAX_CALLDATA_BYTES: usize = 32_768;

/// ShieldedPool precompile: 0x0000000000000000000000000000000000000801
pub(crate) const SHIELDED_POOL_PRECOMPILE: [u8; 20] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x01,
];

// ---------------------------------------------------------------------------
// Pure validation functions
// ---------------------------------------------------------------------------

/// Computes the effective minimum fee the user must include in their calldata.
///
/// The relay must earn at least twice what it spends on EVM gas, so the floor is:
///   `2 × RELAY_GAS_LIMIT × base_fee_per_gas`
///
/// The governance-set `min_fee_planck` is the absolute lower bound; the 2× gas floor
/// applies on top whenever network gas prices are high enough to make it exceed governance.
/// Both values are in planck (= wei in Orbinum's 1:1 mapping).
pub(crate) fn compute_effective_min_fee(min_fee_planck: u128, base_fee_wei: u128) -> u128 {
	let two_x_gas_floor = (RELAY_GAS_LIMIT as u128)
		.saturating_mul(2)
		.saturating_mul(base_fee_wei);
	min_fee_planck.max(two_x_gas_floor)
}

/// Validates relay calldata against a runtime-provided minimum fee and selector whitelist.
///
/// `min_fee_wei`       — from `ShieldedPoolRuntimeApi::relay_config().min_fee_planck`
///                       (or `MIN_RELAY_FEE_FALLBACK` if the API is unavailable).
/// `allowed_selectors` — from `relay_config().allowed_selectors`.
///
/// Both `unshield` and `privateTransfer` agree up to slot 6, which is all this
/// function reads:
/// ```text
///  bytes [0..4]     selector
///  bytes [4..36]    slot 0  — offset pointer for proof (bytes/dynamic)
///  bytes [36..68]   slot 1  — bytes32  root
///  bytes [68..100]  slot 2  — bytes32  nullifier  / bytes32[] nullifiers offset
///  bytes [100..132] slot 3  — uint32   asset_id   / bytes32[] commits offset
///  bytes [132..164] slot 4  — uint256  amount     / bytes[]   memos offset
///  bytes [164..196] slot 5  — bytes32  recipient  / uint32    asset_id
///  bytes [196..228] slot 6  — uint256  fee        ← checked here
/// ```
/// Past slot 6 the layouts diverge, so the 228-byte minimum above is only a
/// cheap first gate: each operation declares its own `min_calldata_len()`
/// (unshield 324, privateTransfer 292), checked after selector dispatch.
pub(crate) fn validate_relay_calldata(
	data: &[u8],
	min_fee_wei: u128,
	allowed_selectors: &[[u8; 4]],
) -> Result<(), &'static str> {
	// Global minimum: selector (4 B) + 6 ABI head slots (6 × 32 B) = 228 B.
	if data.len() < 228 {
		return Err("calldata too short");
	}
	if data.len() > MAX_CALLDATA_BYTES {
		return Err("calldata too large");
	}

	let selector: [u8; 4] = data[..4].try_into().unwrap();
	if !allowed_selectors.contains(&selector) {
		return Err("unsupported selector");
	}

	// Capa 3: dispatch to the registered RelayableOperation for per-op fee extraction.
	// If the governance whitelist contains a selector the node does not implement,
	// the relay rejects it — requiring a node update to support new operations.
	let op = default_operations()
		.into_iter()
		.find(|op| op.selector() == selector)
		.ok_or("unsupported selector")?;

	log::trace!(target: "orbinum-relay", "validating {} calldata ({} bytes)", op.name(), data.len());

	if data.len() < op.min_calldata_len() {
		return Err("calldata too short");
	}

	if op.extract_fee(data) < min_fee_wei {
		return Err("fee below minimum");
	}

	Ok(())
}

/// Interprets the `exit_reason` from an EVM dry-run and returns whether the call
/// would succeed on-chain.
///
/// Returns `Ok(())` only when `exit_reason` is `ExitReason::Succeed(_)`.
/// All other outcomes (revert, error, fatal) return `Err` with a human-readable
/// description so callers can surface it to the user without paying gas.
pub(crate) fn check_dry_run_exit(exit_reason: &ExitReason) -> Result<(), String> {
	match exit_reason {
		ExitReason::Succeed(_) => Ok(()),
		other => Err(format!("calldata would fail on-chain: {other:?}")),
	}
}

// ---------------------------------------------------------------------------
// Unit tests — pure validation logic, no runtime required
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use ethereum_types::U256;

	use super::super::operations::{SELECTOR_PRIVATE_TRANSFER, SELECTOR_UNSHIELD};
	use super::*;

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
		// 9 slots (292). Build the larger of the two — extra zero head slots are
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

	/// The whitelist must carry the selectors the precompile actually decodes.
	///
	/// This is the ME-8 guard. It compares against the DECODER's own constants,
	/// not against a signature string copied into this file — two copies of a
	/// signature can drift together and a test on each side would still pass.
	/// The failure is silent: a wrong selector is merely "unsupported", so the
	/// rejection tests stay green while relaying stops working entirely.
	#[test]
	fn whitelist_selectors_match_the_precompile_decoder() {
		use pallet_evm_precompile_shielded_pool::selectors;

		assert_eq!(SELECTOR_PRIVATE_TRANSFER, selectors::PRIVATE_TRANSFER);
		assert_eq!(SELECTOR_UNSHIELD, selectors::UNSHIELD);
	}

	/// And both are genuine keccak output, not bytes that happen to agree.
	#[test]
	fn selectors_are_keccak_of_the_abi_signatures() {
		let pt = sp_core::hashing::keccak_256(
			b"privateTransfer(bytes,bytes32,bytes32[],bytes32[],bytes[],uint32,uint256,uint32,bytes)",
		);
		let un = sp_core::hashing::keccak_256(
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

	/// privateTransfer calldata shorter than its 9-slot head (292 bytes) is
	/// rejected even though it clears the global 228-byte minimum.
	#[test]
	fn rejects_private_transfer_calldata_between_228_and_292() {
		let mut data = build_calldata(SELECTOR_PRIVATE_TRANSFER, MIN_RELAY_FEE_FALLBACK);
		data.truncate(291);
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

	/// A fee word above `u128::MAX` must be rejected, not panic.
	///
	/// Regression: `U256::as_u128` panics on anything wider than 128 bits, and
	/// this calldata arrives from an unauthenticated RPC call — 32 crafted bytes
	/// were enough to take down the handler, repeatably and for free.
	#[test]
	fn huge_fee_saturates_instead_of_panicking() {
		let mut data = build_calldata(SELECTOR_PRIVATE_TRANSFER, 0);
		// Set a byte in the HIGH 128 bits of the fee slot (data[196..228]).
		data[196 + 15] = 0x01;

		// Saturates to u128::MAX, so it clears the floor here and is left for
		// the dry-run to reject — the same outcome as any other absurd fee.
		assert_eq!(
			validate_relay_calldata(&data, MIN_RELAY_FEE_FALLBACK, &SELECTORS_FALLBACK),
			Ok(())
		);
	}

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
}

// ---------------------------------------------------------------------------
// Adversarial battery — the relay is reachable UNAUTHENTICATED over RPC
// ---------------------------------------------------------------------------
//
// `validate_relay_calldata` is the first code in the node to touch bytes that
// an anonymous internet caller fully controls. A panic here is a remote node
// crash, not a rejected request. These tests try to cause one.

#[cfg(test)]
mod adversarial {
	use super::*;
	use crate::relay::operations::{SELECTOR_PRIVATE_TRANSFER, SELECTOR_UNSHIELD};

	/// Well-formed base calldata for privateTransfer, long enough to pass the
	/// length gates so the later checks are actually reached.
	fn base_private_transfer(fee: u128) -> Vec<u8> {
		let mut d = SELECTOR_PRIVATE_TRANSFER.to_vec();
		d.resize(4 + 288, 0);
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
		for len in 228..292usize {
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
}
