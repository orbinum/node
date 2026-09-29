//! Fixed-width ABI decoders: `uint32`, `uint256` and `bytes32`.

use fp_evm::PrecompileFailure;
use sp_core::U256;

use super::guard::checked_range;
use crate::revert;

/// Reads the `uint32` at `params[slot_start..slot_start+32]` (big-endian,
/// right-aligned).
///
/// A word wider than `u32` is rejected rather than truncated: the ABI declares
/// the argument as `uint32`, so a caller sending more has encoded something the
/// callee never agreed to, and silently keeping the low bits turns a malformed
/// call into a plausible one with a different value.
pub fn read_u32(params: &[u8], slot_start: usize) -> Result<u32, PrecompileFailure> {
	let range = checked_range(slot_start, 32, params.len(), "uint32 slot")?;
	let word = U256::from_big_endian(&params[range]);
	if word > U256::from(u32::MAX) {
		return Err(revert("uint32 slot exceeds u32"));
	}
	Ok(word.low_u32())
}

/// Reads the `uint256` at `params[slot_start..slot_start+32]`.
pub fn read_u256(params: &[u8], slot_start: usize) -> Result<U256, PrecompileFailure> {
	let range = checked_range(slot_start, 32, params.len(), "uint256 slot")?;
	Ok(U256::from_big_endian(&params[range]))
}

/// Reads the 32-byte value at `params[slot_start..slot_start+32]` verbatim.
pub fn read_bytes32(params: &[u8], slot_start: usize) -> Result<[u8; 32], PrecompileFailure> {
	let range = checked_range(slot_start, 32, params.len(), "bytes32 slot")?;
	params[range]
		.try_into()
		.map_err(|_| revert("bytes32 copy failed"))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A 32-byte big-endian ABI word holding `v`.
	fn word(v: U256) -> [u8; 32] {
		v.to_big_endian()
	}

	/// The ABI declares `uint32`, so a wider word is a call the callee never
	/// agreed to — keeping the low bits would turn it into a different, valid
	/// looking argument.
	#[test]
	fn a_uint32_slot_wider_than_u32_is_refused() {
		let sneaky = U256::from(1u64 << 32) + U256::from(7u64);
		assert_eq!(sneaky.low_u32(), 7);
		assert!(read_u32(&word(sneaky), 0).is_err());

		// u32::MAX itself still decodes.
		assert_eq!(read_u32(&word(U256::from(u32::MAX)), 0).unwrap(), u32::MAX);
	}
}
