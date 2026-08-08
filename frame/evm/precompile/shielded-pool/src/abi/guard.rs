//! Bounds- and overflow-checked arithmetic over attacker-chosen calldata.
//!
//! Offsets, lengths and counts all come from calldata, so every `+`/`*` on them
//! is checked: release builds do not enable `overflow-checks`, and a wrapped sum
//! passes the very bounds check meant to reject it. This module is the only place
//! that arithmetic lives, and the only place that reads a 256-bit word as a `usize`.

use fp_evm::{ExitError, PrecompileFailure};
use sp_core::U256;

/// Constructs a `PrecompileFailure::Error` with the given message.
pub(super) fn abi_error(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}

/// Checked `a + b`, mapping overflow to an ABI error labelled `what`.
pub(super) fn checked_add(
	a: usize,
	b: usize,
	what: &'static str,
) -> Result<usize, PrecompileFailure> {
	a.checked_add(b).ok_or_else(|| abi_error(what))
}

/// Checked `a * b`, mapping overflow to an ABI error labelled `what`.
pub(super) fn checked_mul(
	a: usize,
	b: usize,
	what: &'static str,
) -> Result<usize, PrecompileFailure> {
	a.checked_mul(b).ok_or_else(|| abi_error(what))
}

/// The range `start..start + span`, verified to fit inside a buffer of `params_len`
/// without wrapping. `what` labels the error on both the overflow and the
/// out-of-bounds path.
pub(super) fn checked_range(
	start: usize,
	span: usize,
	params_len: usize,
	what: &'static str,
) -> Result<core::ops::Range<usize>, PrecompileFailure> {
	let end = start.checked_add(span).ok_or_else(|| abi_error(what))?;
	if end > params_len {
		return Err(abi_error(what));
	}
	Ok(start..end)
}

/// Reads a 256-bit ABI word as a `usize`, rejecting anything that does not fit.
///
/// ABI offsets and lengths are `uint256`. Narrowing one with `low_u32` keeps the
/// bottom 32 bits and silently discards the rest, so `2^32 + 8` reads back as
/// `8` and `2^32` as `0` — the caller then bounds-checks a value the sender
/// never wrote, and indexes somewhere else entirely.
///
/// `usize` is 32-bit under Wasm and 64-bit natively, so `try_into` also keeps
/// the two from disagreeing about which calldata is acceptable.
pub(super) fn word_to_usize(word: U256, what: &'static str) -> Result<usize, PrecompileFailure> {
	if word > U256::from(usize::MAX) {
		return Err(abi_error(what));
	}
	usize::try_from(word).map_err(|_| abi_error(what))
}
