//! Pure ABI decoding helpers for the shielded-pool precompile.
//!
//! All functions are stateless free functions — no FRAME generics, no pallet types.
//! They operate directly on raw ABI-encoded byte slices and return typed Rust values.

use alloc::vec::Vec;

use fp_evm::{ExitError, PrecompileFailure};
use sp_core::U256;

// ─────────────────────────────────────────────────────────────────────────────
// Scalar decoders
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes a `uint32` from a 32-byte ABI slot (big-endian, right-aligned).
pub fn decode_u32(slot: &[u8]) -> Result<u32, PrecompileFailure> {
	if slot.len() < 32 {
		return Err(abi_error("uint32 slot too short"));
	}
	Ok(U256::from_big_endian(&slot[0..32]).low_u32())
}

/// Reads the 32-byte value at `params[slot_start..slot_start+32]` verbatim.
pub fn read_bytes32(params: &[u8], slot_start: usize) -> Result<[u8; 32], PrecompileFailure> {
	if slot_start + 32 > params.len() {
		return Err(abi_error("bytes32 slot out of bounds"));
	}
	params[slot_start..slot_start + 32]
		.try_into()
		.map_err(|_| abi_error("bytes32 copy failed"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic-type decoders
// ─────────────────────────────────────────────────────────────────────────────

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
	let data_start = offset + 32;
	if data_start + length > params.len() {
		return Err(abi_error("bytes data out of bounds"));
	}
	Ok(params[data_start..data_start + length].to_vec())
}

/// Decodes a `bytes32[]` whose offset pointer lives at `slot_start` in `params`.
pub fn decode_bytes32_array_at_slot(
	params: &[u8],
	slot_start: usize,
) -> Result<Vec<[u8; 32]>, PrecompileFailure> {
	let offset = read_offset(params, slot_start)?;
	let count = read_length(params, offset)?;
	let data_start = offset + 32;
	if data_start + count * 32 > params.len() {
		return Err(abi_error("bytes32[] data out of bounds"));
	}
	let mut items = Vec::with_capacity(count);
	for i in 0..count {
		let s = data_start + i * 32;
		let elem: [u8; 32] = params[s..s + 32].try_into().unwrap();
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
	// Each element has a relative offset pointer from the start of the array-data region
	// (= array_offset + 32, which is right after the length word).
	let data_base = array_offset + 32;

	let mut result = Vec::with_capacity(count);
	for i in 0..count {
		let rel_offset_pos = data_base + i * 32;
		if rel_offset_pos + 32 > params.len() {
			return Err(abi_error("bytes[] element offset out of bounds"));
		}
		let rel_offset =
			U256::from_big_endian(&params[rel_offset_pos..rel_offset_pos + 32]).low_u32() as usize;
		let abs_offset = data_base + rel_offset;
		let elem_len = read_length(params, abs_offset)?;
		let elem_start = abs_offset + 32;
		if elem_start + elem_len > params.len() {
			return Err(abi_error("bytes[] element data out of bounds"));
		}
		result.push(params[elem_start..elem_start + elem_len].to_vec());
	}
	Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Reads an ABI offset (usize) from a 32-byte slot at `slot_start` in `params`.
fn read_offset(params: &[u8], slot_start: usize) -> Result<usize, PrecompileFailure> {
	if slot_start + 32 > params.len() {
		return Err(abi_error("slot out of bounds"));
	}
	Ok(U256::from_big_endian(&params[slot_start..slot_start + 32]).low_u32() as usize)
}

/// Reads an ABI length word (usize) from `params[offset..offset+32]`.
fn read_length(params: &[u8], offset: usize) -> Result<usize, PrecompileFailure> {
	if offset + 32 > params.len() {
		return Err(abi_error("length word out of bounds"));
	}
	Ok(U256::from_big_endian(&params[offset..offset + 32]).low_u32() as usize)
}

/// Constructs a `PrecompileFailure::Error` with the given message.
fn abi_error(msg: &'static str) -> PrecompileFailure {
	PrecompileFailure::Error {
		exit_status: ExitError::Other(msg.into()),
	}
}
