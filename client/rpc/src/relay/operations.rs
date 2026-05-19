// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Capa 3 — Generic `RelayableOperation` trait and built-in implementations.
//!
//! Each operation describes how to validate calldata for a specific on-chain call:
//! its ABI selector, the minimum calldata length required, and where to find the
//! embedded relay fee.  Adding support for a new relayable precompile call only
//! requires implementing this trait and registering the struct in
//! [`default_operations`].

use ethereum_types::U256;

/// 4-byte ABI selector for `unshield(...)`.
pub(crate) const SELECTOR_UNSHIELD: [u8; 4] = [0x47, 0xfc, 0x44, 0xa2];

/// 4-byte ABI selector for `privateTransfer(...)`.
pub(crate) const SELECTOR_PRIVATE_TRANSFER: [u8; 4] = [0x8c, 0x0f, 0x5d, 0x24];

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

/// `unshield(proof, root, nullifier, asset_id, amount, recipient, fee)` — `0x47fc44a2`
///
/// Fee is in ABI slot 6: `calldata[196..228]`.
pub(crate) struct UnshieldOp;

impl RelayableOperation for UnshieldOp {
	fn selector(&self) -> [u8; 4] {
		SELECTOR_UNSHIELD
	}

	fn name(&self) -> &'static str {
		"unshield"
	}

	fn min_calldata_len(&self) -> usize {
		228
	}

	fn extract_fee(&self, calldata: &[u8]) -> u128 {
		let bytes: [u8; 32] = calldata[196..228].try_into().unwrap();
		U256::from_big_endian(&bytes).as_u128()
	}
}

/// `privateTransfer(proof, root, nullifiers, commitments, memos, asset_id, fee)` — `0x8c0f5d24`
///
/// Fee is in ABI slot 6: `calldata[196..228]`.
pub(crate) struct PrivateTransferOp;

impl RelayableOperation for PrivateTransferOp {
	fn selector(&self) -> [u8; 4] {
		SELECTOR_PRIVATE_TRANSFER
	}

	fn name(&self) -> &'static str {
		"privateTransfer"
	}

	fn min_calldata_len(&self) -> usize {
		228
	}

	fn extract_fee(&self, calldata: &[u8]) -> u128 {
		let bytes: [u8; 32] = calldata[196..228].try_into().unwrap();
		U256::from_big_endian(&bytes).as_u128()
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
