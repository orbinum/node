//! Dynamic ABI decoder: `bytes`.
//!
//! Reads an offset pointer from the head, then a length word at that
//! offset, then the data region — every step bounds-checked through [`super::guard`].

use alloc::vec::Vec;

use fp_evm::PrecompileFailure;
use sp_core::U256;

use super::guard::{checked_add, checked_range, word_to_usize};

/// Decodes a dynamic `bytes` value.
///
/// `slot_start` is the byte offset inside `params` where the 32-byte offset
/// pointer for the bytes value lives (standard ABI head encoding).
pub fn decode_bytes_at_slot(
	params: &[u8],
	slot_start: usize,
) -> Result<Vec<u8>, PrecompileFailure> {
	let offset = read_offset(params, slot_start)?;
	let length = read_length(params, offset)?;
	// The length word sits at `offset`, so the data starts 32 bytes later.
	let data_start = checked_add(offset, 32, "bytes offset overflows")?;
	let range = checked_range(data_start, length, params.len(), "bytes data")?;
	Ok(params[range].to_vec())
}

/// Reads an ABI offset from a 32-byte slot at `slot_start` in `params`.
fn read_offset(params: &[u8], slot_start: usize) -> Result<usize, PrecompileFailure> {
	let range = checked_range(slot_start, 32, params.len(), "offset slot")?;
	word_to_usize(
		U256::from_big_endian(&params[range]),
		"offset does not fit in usize",
	)
}

/// Reads an ABI length word from `params[offset..offset+32]`.
fn read_length(params: &[u8], offset: usize) -> Result<usize, PrecompileFailure> {
	let range = checked_range(offset, 32, params.len(), "length word")?;
	word_to_usize(
		U256::from_big_endian(&params[range]),
		"length does not fit in usize",
	)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A 32-byte big-endian ABI word holding `v`.
	fn word(v: U256) -> [u8; 32] {
		v.to_big_endian()
	}

	/// Head slot pointing at `offset`, followed by padding out to `total` bytes.
	fn with_offset(offset: U256, total: usize) -> Vec<u8> {
		let mut p = word(offset).to_vec();
		p.resize(total.max(32), 0);
		p
	}

	// ─── Truncation ──────────────────────────────────────────────────────────

	/// The attack `low_u32` allowed: a word whose low 32 bits look benign while
	/// the value itself is astronomically out of range. `2^32 + 8` read back as
	/// `8`, so the bounds check validated an offset nobody sent.
	#[test]
	fn an_offset_above_u32_is_refused_not_truncated() {
		let sneaky = U256::from(1u64 << 32) + U256::from(8u64);
		assert_eq!(
			sneaky.low_u32(),
			8,
			"the low bits must look valid, or this proves nothing"
		);

		let params = with_offset(sneaky, 128);
		assert!(decode_bytes_at_slot(&params, 0).is_err());
	}

	/// `2^32` truncates to zero, which points the reader at the head itself.
	#[test]
	fn an_offset_of_exactly_two_to_the_32_is_refused() {
		let sneaky = U256::from(1u64 << 32);
		assert_eq!(sneaky.low_u32(), 0);

		let params = with_offset(sneaky, 128);
		assert!(decode_bytes_at_slot(&params, 0).is_err());
	}

	// ─── Overflow ────────────────────────────────────────────────────────────

	/// `data_start + length` on plain arithmetic wraps for a huge length, and the
	/// wrapped sum passes the bounds check it was meant to fail. Release builds
	/// do not enable overflow-checks, so it would wrap silently.
	#[test]
	fn a_length_that_would_wrap_the_bounds_check_is_refused() {
		let mut params = word(U256::from(32u64)).to_vec(); // offset -> 32
		params.extend_from_slice(&word(U256::from(usize::MAX))); // length
		params.resize(128, 0);

		assert!(decode_bytes_at_slot(&params, 0).is_err());
	}

	// ─── Well-formed input still decodes ─────────────────────────────────────

	/// The guards must not reject real calldata, or they trade one bug for a
	/// worse one.
	#[test]
	fn a_well_formed_bytes_value_still_decodes() {
		let payload = [0xABu8; 5];
		let mut params = word(U256::from(32u64)).to_vec(); // offset
		params.extend_from_slice(&word(U256::from(payload.len()))); // length
		params.extend_from_slice(&payload);
		params.resize(96, 0); // pad to a 32-byte boundary

		assert_eq!(decode_bytes_at_slot(&params, 0).unwrap(), payload.to_vec());
	}
}
