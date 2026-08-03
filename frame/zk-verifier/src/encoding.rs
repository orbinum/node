//! Public input encoding for each supported circuit.
//!
//! Converts typed domain parameters into the raw `Vec<[u8; 32]>` format
//! expected by [`crate::verifier::verify`]. Each function handles the
//! field-element packing rules for one circuit type.

extern crate alloc;

use alloc::vec::Vec;

/// Encode transfer (2-in / 2-out) public inputs.
///
/// Order: `merkle_root | nullifiers[..] | commitments[..] | asset_id | fee`
pub fn encode_transfer(
	merkle_root: &[u8; 32],
	nullifiers: &[[u8; 32]],
	commitments: &[[u8; 32]],
	asset_id: u32,
	fee: u128,
) -> Vec<[u8; 32]> {
	let mut raw = Vec::with_capacity(1 + nullifiers.len() + commitments.len() + 2);
	raw.push(*merkle_root);
	raw.extend_from_slice(nullifiers);
	raw.extend_from_slice(commitments);

	let mut asset_bytes = [0u8; 32];
	asset_bytes[..4].copy_from_slice(&asset_id.to_le_bytes());
	raw.push(asset_bytes);

	let mut fee_bytes = [0u8; 32];
	fee_bytes[..16].copy_from_slice(&fee.to_le_bytes());
	raw.push(fee_bytes);

	raw
}

/// Encode unshield (pool withdrawal) public inputs.
///
/// Order: `merkle_root | nullifier | amount | recipient | asset_id | fee | change_commitment`
///
/// `recipient` is passed as-is (LE field element, same convention used by the
/// TypeScript SDK: `bytesToBigintLE(accountId32Bytes)`).
pub fn encode_unshield(
	merkle_root: &[u8; 32],
	nullifier: &[u8; 32],
	amount: u128,
	recipient: &[u8; 32],
	asset_id: u32,
	fee: u128,
	change_commitment: &[u8; 32],
) -> Vec<[u8; 32]> {
	let mut amount_bytes = [0u8; 32];
	amount_bytes[..16].copy_from_slice(&amount.to_le_bytes());

	let mut asset_bytes = [0u8; 32];
	asset_bytes[..4].copy_from_slice(&asset_id.to_le_bytes());

	let mut fee_bytes = [0u8; 32];
	fee_bytes[..16].copy_from_slice(&fee.to_le_bytes());

	alloc::vec![
		*merkle_root,
		*nullifier,
		amount_bytes,
		*recipient,
		asset_bytes,
		fee_bytes,
		*change_commitment,
	]
}

/// Encode value proof public inputs (CircuitId 6).
///
/// Expands the compact 76-byte on-chain layout into 4 BN254 field elements:
/// `commitment(32) | value_u64_le(8→32) | asset_id_u32_le(4→32) | owner_hash(32)`
pub fn encode_value_proof(public_signals: &[u8; 76]) -> Vec<[u8; 32]> {
	let mut commitment = [0u8; 32];
	commitment.copy_from_slice(&public_signals[0..32]);

	let mut value = [0u8; 32];
	value[..8].copy_from_slice(&public_signals[32..40]);

	let mut asset_id = [0u8; 32];
	asset_id[..4].copy_from_slice(&public_signals[40..44]);

	let mut owner_hash = [0u8; 32];
	owner_hash.copy_from_slice(&public_signals[44..76]);

	alloc::vec![commitment, value, asset_id, owner_hash]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encode_transfer_correct_length() {
		let root = [0x01u8; 32];
		let nullifiers = [[0x02u8; 32], [0x03u8; 32]];
		let commitments = [[0x04u8; 32], [0x05u8; 32]];
		let raw = encode_transfer(&root, &nullifiers, &commitments, 1, 500);
		// 1 (root) + 2 (nullifiers) + 2 (commitments) + 1 (asset_id) + 1 (fee) = 7
		assert_eq!(raw.len(), 7);
		assert_eq!(raw[0], root);
		assert_eq!(&raw[1..3], &nullifiers);
		assert_eq!(&raw[3..5], &commitments);
	}

	#[test]
	fn encode_unshield_correct_length() {
		let raw = encode_unshield(&[1u8; 32], &[2u8; 32], 100, &[3u8; 32], 1, 5, &[6u8; 32]);
		assert_eq!(raw.len(), 7);
	}

	#[test]
	fn encode_unshield_change_commitment_appended() {
		let change = [0xABu8; 32];
		let raw = encode_unshield(&[0u8; 32], &[0u8; 32], 0, &[0u8; 32], 0, 0, &change);
		assert_eq!(raw[6], change);
	}

	#[test]
	fn encode_unshield_zero_change_commitment() {
		let raw = encode_unshield(&[0u8; 32], &[0u8; 32], 0, &[0u8; 32], 0, 0, &[0u8; 32]);
		assert_eq!(raw[6], [0u8; 32]);
	}

	#[test]
	fn encode_unshield_recipient_reversed() {
		let mut recipient = [0u8; 32];
		recipient[31] = 0xFF;
		let raw = encode_unshield(&[0u8; 32], &[0u8; 32], 0, &recipient, 0, 0, &[0u8; 32]);
		// recipient is passed as-is (LE format), so last byte should be 0xFF
		assert_eq!(raw[3][31], 0xFF);
	}

	#[test]
	fn encode_value_proof_correct_length() {
		let signals = [0u8; 76];
		let raw = encode_value_proof(&signals);
		assert_eq!(raw.len(), 4);
	}

	#[test]
	fn encode_value_proof_commitment_field() {
		let mut signals = [0u8; 76];
		signals[0..32].copy_from_slice(&[0xAAu8; 32]);
		let raw = encode_value_proof(&signals);
		assert_eq!(raw[0], [0xAAu8; 32]);
	}

	#[test]
	fn encode_value_proof_value_field_zero_padded() {
		let mut signals = [0u8; 76];
		signals[32..40].copy_from_slice(&100u64.to_le_bytes());
		let raw = encode_value_proof(&signals);
		assert_eq!(&raw[1][..8], &100u64.to_le_bytes());
		assert_eq!(&raw[1][8..], &[0u8; 24]);
	}

	#[test]
	fn encode_value_proof_asset_id_field_zero_padded() {
		let mut signals = [0u8; 76];
		signals[40..44].copy_from_slice(&42u32.to_le_bytes());
		let raw = encode_value_proof(&signals);
		assert_eq!(&raw[2][..4], &42u32.to_le_bytes());
		assert_eq!(&raw[2][4..], &[0u8; 28]);
	}

	#[test]
	fn encode_value_proof_owner_hash_field() {
		let mut signals = [0u8; 76];
		signals[44..76].copy_from_slice(&[0xBBu8; 32]);
		let raw = encode_value_proof(&signals);
		assert_eq!(raw[3], [0xBBu8; 32]);
	}
}
