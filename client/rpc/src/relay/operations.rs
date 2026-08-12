// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Capa 3 — Generic `RelayableOperation` trait and built-in implementations.
//!
//! Each operation describes how to validate calldata for a specific on-chain call:
//! its ABI selector, the minimum calldata length required, and where to find the
//! embedded relay fee.  Adding support for a new relayable precompile call only
//! requires implementing this trait and registering the struct in
//! [`default_operations`].

use ethereum_types::U256;

/// Selectors the relay accepts, re-exported from the precompile that decodes
/// them. Aliases rather than literals: the whitelist and the decoder cannot
/// disagree if there is only one definition. A hand-kept copy drifting from the
/// decoder fails silently — a wrong selector is merely "unsupported", so the
/// rejection tests stay green while the accept path stops working.
pub(crate) use pallet_evm_precompile_shielded_pool::selectors::{
	PRIVATE_TRANSFER as SELECTOR_PRIVATE_TRANSFER, UNSHIELD as SELECTOR_UNSHIELD,
};

/// Describes how to validate calldata for a specific relayable on-chain operation.
///
/// Implementing this trait for a new operation allows the relay to accept it
/// without modifying [`validate_relay_calldata`] — Capa 3 of the relay architecture.
///
/// [`validate_relay_calldata`]: super::validation::validate_relay_calldata
pub(crate) trait RelayableOperation: Send + Sync {
	/// 4-byte ABI selector identifying this operation.
	fn selector(&self) -> [u8; 4];

	/// Human-readable name (used in log messages and RPC responses).
	fn name(&self) -> &'static str;

	/// Minimum required calldata length (bytes) for this operation's ABI layout.
	fn min_calldata_len(&self) -> usize;

	/// Extract the relay fee (planck/wei) from validated calldata.
	///
	/// Only called after `data.len() >= min_calldata_len()` is confirmed.
	fn extract_fee(&self, calldata: &[u8]) -> u128;
}

/// Reads the relay fee from ABI slot 6 (`calldata[196..228]`), the position both
/// operations share.
///
/// Saturates instead of panicking on a value above `u128::MAX`. Calldata reaches
/// this from an unauthenticated RPC call, and `U256::as_u128` panics outright on
/// anything wider — one crafted 32-byte word would take down the handler.
/// Saturating is safe because the result is only ever compared against the fee
/// floor: an absurd fee clears it here and is then rejected by the EVM dry-run,
/// which is what would have happened anyway.
///
/// The slice is bounds-checked by the caller's `min_calldata_len()` gate (260 or
/// 324, both well past 228).
fn fee_at_slot_6(calldata: &[u8]) -> u128 {
	let Ok(bytes) = <[u8; 32]>::try_from(&calldata[196..228]) else {
		return 0; // unreachable behind the length gate; a zero fee fails the floor
	};
	U256::from_big_endian(&bytes)
		.try_into()
		.unwrap_or(u128::MAX)
}

/// `unshield(proof, root, nullifier, asset_id, amount, recipient, fee,
/// change_commitment, change_encrypted_memo, circuit_version)` — `0x4e505348`
///
/// Fee is in ABI slot 6: `calldata[196..228]`. The head is 10 slots (320 bytes)
/// plus the 4-byte selector = 324 minimum.
pub(crate) struct UnshieldOp;

impl RelayableOperation for UnshieldOp {
	fn selector(&self) -> [u8; 4] {
		SELECTOR_UNSHIELD
	}

	fn name(&self) -> &'static str {
		"unshield"
	}

	fn min_calldata_len(&self) -> usize {
		324
	}

	fn extract_fee(&self, calldata: &[u8]) -> u128 {
		fee_at_slot_6(calldata)
	}
}

/// `privateTransfer(proof, root, nullifiers, commitments, memos, asset_id, fee,
/// circuit_version)` — `0x66ed2cd4`
///
/// Fee is in ABI slot 6: `calldata[196..228]`. The head is 8 slots (256 bytes)
/// plus the 4-byte selector = 260 minimum.
pub(crate) struct PrivateTransferOp;

impl RelayableOperation for PrivateTransferOp {
	fn selector(&self) -> [u8; 4] {
		SELECTOR_PRIVATE_TRANSFER
	}

	fn name(&self) -> &'static str {
		"privateTransfer"
	}

	fn min_calldata_len(&self) -> usize {
		260
	}

	fn extract_fee(&self, calldata: &[u8]) -> u128 {
		fee_at_slot_6(calldata)
	}
}

/// All operations the relay supports out of the box.
///
/// New operations can be registered by adding them here and implementing
/// [`RelayableOperation`].  The governance `AllowedSelectors` whitelist acts as
/// an additional filter — only operations whose selectors are in the whitelist
/// are accepted at runtime.
pub(crate) fn default_operations() -> Vec<Box<dyn RelayableOperation>> {
	vec![Box::new(UnshieldOp), Box::new(PrivateTransferOp)]
}
