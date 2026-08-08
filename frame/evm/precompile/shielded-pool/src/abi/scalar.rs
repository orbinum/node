//! Fixed-width ABI decoders: `uint32` and `bytes32`.

use fp_evm::PrecompileFailure;
use sp_core::U256;

use super::guard::{abi_error, checked_range};

/// Decodes a `uint32` from a 32-byte ABI slot (big-endian, right-aligned).
///
/// A word wider than `u32` is rejected rather than truncated: the ABI declares
/// the argument as `uint32`, so a caller sending more has encoded something the
/// callee never agreed to, and silently keeping the low bits turns a malformed
/// call into a plausible one with a different value.
pub fn decode_u32(slot: &[u8]) -> Result<u32, PrecompileFailure> {
	if slot.len() < 32 {
		return Err(abi_error("uint32 slot too short"));
	}
	let word = U256::from_big_endian(&slot[0..32]);
	if word > U256::from(u32::MAX) {
		return Err(abi_error("uint32 slot exceeds u32"));
	}
	Ok(word.low_u32())
}

/// Reads the 32-byte value at `params[slot_start..slot_start+32]` verbatim.
pub fn read_bytes32(params: &[u8], slot_start: usize) -> Result<[u8; 32], PrecompileFailure> {
	let range = checked_range(slot_start, 32, params.len(), "bytes32 slot")?;
	params[range]
		.try_into()
		.map_err(|_| abi_error("bytes32 copy failed"))
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
		assert!(decode_u32(&word(sneaky)).is_err());

		// u32::MAX itself still decodes.
		assert_eq!(decode_u32(&word(U256::from(u32::MAX))).unwrap(), u32::MAX);
	}
}
