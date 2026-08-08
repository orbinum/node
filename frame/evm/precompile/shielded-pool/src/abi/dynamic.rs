//! Dynamic ABI decoders: `bytes`, `bytes32[]`, `bytes[]`.
//!
//! Each reads an offset pointer from the head, then a length/count word at that
//! offset, then the data region — every step bounds-checked through [`super::guard`].

use alloc::vec::Vec;

use fp_evm::PrecompileFailure;
use sp_core::U256;

use super::guard::{abi_error, checked_add, checked_mul, checked_range, word_to_usize};

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

/// Decodes a `bytes32[]` whose offset pointer lives at `slot_start` in `params`.
pub fn decode_bytes32_array_at_slot(
	params: &[u8],
	slot_start: usize,
) -> Result<Vec<[u8; 32]>, PrecompileFailure> {
	let offset = read_offset(params, slot_start)?;
	let count = read_length(params, offset)?;
	let data_start = checked_add(offset, 32, "bytes32[] offset overflows")?;
	// `count * 32` is the whole span. Bounds-checking it here rejects an oversized
	// array before `with_capacity` reserves for a count that comes from calldata.
	let span = checked_mul(count, 32, "bytes32[] count overflows")?;
	let range = checked_range(data_start, span, params.len(), "bytes32[]")?;
	let data_start = range.start;
	let mut items = Vec::with_capacity(count);
	for i in 0..count {
		let s = data_start + i * 32; // bounded by the checked span above
		let elem: [u8; 32] = params[s..s + 32]
			.try_into()
			.map_err(|_| abi_error("bytes32[] element copy failed"))?;
		items.push(elem);
	}
	Ok(items)
}

/// Decodes a `bytes[]` whose offset pointer lives at `slot_start` in `params`.
pub fn decode_bytes_array_at_slot(
	params: &[u8],
	slot_start: usize,
) -> Result<Vec<Vec<u8>>, PrecompileFailure> {
	let array_offset = read_offset(params, slot_start)?;
	let count = read_length(params, array_offset)?;
	// Each element has a relative offset pointer from the start of the array-data
	// region (= array_offset + 32, right after the length word).
	let data_base = checked_add(array_offset, 32, "bytes[] offset overflows")?;

	// Each element needs a 32-byte pointer. Bounds-checking the pointer table here
	// keeps a declared count of 2^30 from reserving gigabytes in `with_capacity`
	// on input that could never decode.
	let pointers = checked_mul(count, 32, "bytes[] count overflows")?;
	checked_range(data_base, pointers, params.len(), "bytes[] pointer table")?;

	let mut result = Vec::with_capacity(count);
	for i in 0..count {
		let rel_offset_pos = data_base + i * 32; // bounded by the pointer table above
		let rel_offset = word_to_usize(
			U256::from_big_endian(&params[rel_offset_pos..rel_offset_pos + 32]),
			"bytes[] element offset does not fit in usize",
		)?;
		let abs_offset = checked_add(data_base, rel_offset, "bytes[] element offset overflows")?;
		let elem_len = read_length(params, abs_offset)?;
		let elem_start = checked_add(abs_offset, 32, "bytes[] element start overflows")?;
		let range = checked_range(elem_start, elem_len, params.len(), "bytes[] element data")?;
		result.push(params[range].to_vec());
	}
	Ok(result)
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

	/// `count * 32` wraps the same way. 2^59 elements multiplies past usize on a
	/// 64-bit host and lands back inside the buffer.
	#[test]
	fn an_element_count_that_would_wrap_is_refused() {
		let mut params = word(U256::from(32u64)).to_vec();
		params.extend_from_slice(&word(U256::from(1u64 << 59)));
		params.resize(256, 0);

		assert!(decode_bytes32_array_at_slot(&params, 0).is_err());
	}

	/// An element count far past what the buffer can hold must be refused
	/// *before* `Vec::with_capacity` reserves for it.
	#[test]
	fn an_element_count_larger_than_the_buffer_is_refused_early() {
		let mut params = word(U256::from(32u64)).to_vec();
		params.extend_from_slice(&word(U256::from(1u64 << 30))); // ~1e9 elements
		params.resize(256, 0);

		assert!(decode_bytes_array_at_slot(&params, 0).is_err());
		assert!(decode_bytes32_array_at_slot(&params, 0).is_err());
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

	#[test]
	fn a_well_formed_bytes32_array_still_decodes() {
		let mut params = word(U256::from(32u64)).to_vec(); // offset
		params.extend_from_slice(&word(U256::from(2u64))); // count
		params.extend_from_slice(&[0x11u8; 32]);
		params.extend_from_slice(&[0x22u8; 32]);

		let out = decode_bytes32_array_at_slot(&params, 0).unwrap();
		assert_eq!(out, alloc::vec![[0x11u8; 32], [0x22u8; 32]]);
	}

	/// An empty dynamic array is valid ABI and must survive the count checks.
	#[test]
	fn an_empty_array_still_decodes() {
		let mut params = word(U256::from(32u64)).to_vec();
		params.extend_from_slice(&word(U256::zero()));

		assert!(decode_bytes32_array_at_slot(&params, 0).unwrap().is_empty());
		assert!(decode_bytes_array_at_slot(&params, 0).unwrap().is_empty());
	}
}
