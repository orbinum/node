//! The only way to reach this precompile: a direct, non-static, valueless call.

use crate::revert;
use fp_evm::{PrecompileFailure, PrecompileHandle};

/// A transfer debits `context.caller`. Under DELEGATECALL or CALLCODE that is the
/// delegating contract's caller, so any contract a user called could spend the
/// user's ORB; under STATICCALL nothing may change state; value sent here would
/// be stranded in this precompile's account. Each is refused.
pub(crate) fn ensure_direct_call(handle: &impl PrecompileHandle) -> Result<(), PrecompileFailure> {
	if handle.is_static() {
		return Err(revert("static calls are not allowed"));
	}
	if handle.code_address() != handle.context().address {
		return Err(revert("delegated calls are not allowed"));
	}
	if !handle.context().apparent_value.is_zero() {
		return Err(revert("not payable"));
	}
	Ok(())
}
