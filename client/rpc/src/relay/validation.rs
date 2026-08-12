// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Pure calldata validation — no runtime, no async, no I/O.
//!
//! This is the relay's admission gate: everything it can decide about a request
//! by looking at the bytes alone. Anything needing chain state (the dry run, the
//! nonce, the signature) lives in [`super::rpc`], and the limits these functions
//! enforce live in [`super::config`].
//!
//! Being free of those dependencies is what makes the hostile cases in
//! `tests/adversarial.rs` cheap to write: no node, no async runtime, just bytes.

use fp_evm::ExitReason;

use super::{
	config::{MAX_CALLDATA_BYTES, RELAY_GAS_LIMIT},
	operations::default_operations,
};

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
/// (unshield 324, privateTransfer 260), checked after selector dispatch.
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
