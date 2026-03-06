//! Error codes and constructors for the `pallet-account-mapping` RPC server.
//!
//! Centralising the codes here prevents magic values from scattering across
//! the RPC `lib.rs` and makes them easy to change without touching business logic.

use jsonrpsee::types::ErrorObjectOwned;

/// Pallet-specific JSON-RPC error codes.
///
/// Reserved range: 4000–4099 (conflict-free with standard JSON-RPC 2.0 errors
/// and with other pallets that use the 4100+ range).
pub mod code {
	/// Invalid H160 input (malformed hex or incorrect length).
	pub const INVALID_H160: i32 = 4000;
	/// Invalid AccountId32 input (malformed hex or incorrect length).
	pub const INVALID_ACCOUNT_ID: i32 = 4001;
	/// Generic Runtime API error (failure when calling the runtime).
	pub const RUNTIME_ERROR: i32 = 4002;
	/// The provided alias has an invalid format.
	pub const INVALID_ALIAS: i32 = 4003;
	/// The external chain address has an invalid format.
	pub const INVALID_CHAIN_ADDRESS: i32 = 4004;
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed error constructors
// ─────────────────────────────────────────────────────────────────────────────

pub fn invalid_h160(detail: impl core::fmt::Display) -> ErrorObjectOwned {
	ErrorObjectOwned::owned(
		code::INVALID_H160,
		format!("Invalid H160 address: {detail}"),
		None::<()>,
	)
}

pub fn invalid_account_id(detail: impl core::fmt::Display) -> ErrorObjectOwned {
	ErrorObjectOwned::owned(
		code::INVALID_ACCOUNT_ID,
		format!("Invalid AccountId32: {detail}"),
		None::<()>,
	)
}

pub fn runtime_error(detail: impl core::fmt::Display) -> ErrorObjectOwned {
	ErrorObjectOwned::owned(
		code::RUNTIME_ERROR,
		format!("Runtime API error: {detail}"),
		None::<()>,
	)
}

pub fn invalid_alias(detail: impl core::fmt::Display) -> ErrorObjectOwned {
	ErrorObjectOwned::owned(
		code::INVALID_ALIAS,
		format!("Invalid alias: {detail}"),
		None::<()>,
	)
}

pub fn invalid_chain_address(detail: impl core::fmt::Display) -> ErrorObjectOwned {
	ErrorObjectOwned::owned(
		code::INVALID_CHAIN_ADDRESS,
		format!("Invalid chain address: {detail}"),
		None::<()>,
	)
}
