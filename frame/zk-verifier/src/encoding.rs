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

/// Encode private-link dispatch public inputs.
///
/// Order: `commitment | call_hash_fe`
pub fn encode_private_link(commitment: &[u8; 32], call_hash_fe: &[u8; 32]) -> Vec<[u8; 32]> {
	alloc::vec![*commitment, *call_hash_fe]
}

/// Decode 76-byte selective disclosure public signals into 4 field elements.
///
/// Layout: `commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]`
pub fn decode_disclosure_signals(
	signals: &[u8],
) -> Result<Vec<[u8; 32]>, sp_runtime::DispatchError> {
	if signals.len() != 76 {
		return Err(sp_runtime::DispatchError::Other(
			"Invalid disclosure signals length (expected 76 bytes)",
		));
	}

	let mut commitment = [0u8; 32];
	commitment.copy_from_slice(&signals[0..32]);

	let mut value = [0u8; 32];
	value[..8].copy_from_slice(&signals[32..40]);

	let mut asset_id = [0u8; 32];
	asset_id[..4].copy_from_slice(&signals[40..44]);

	let mut owner_hash = [0u8; 32];
	owner_hash.copy_from_slice(&signals[44..76]);

	Ok(alloc::vec![commitment, value, asset_id, owner_hash])
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
	fn encode_private_link_correct_length() {
		let raw = encode_private_link(&[1u8; 32], &[2u8; 32]);
		assert_eq!(raw.len(), 2);
	}

	#[test]
	fn decode_disclosure_signals_valid() {
		let mut signals = [0u8; 76];
		signals[0] = 0xAA;
		signals[32] = 0xBB;
		signals[40] = 0xCC;
		signals[44] = 0xDD;
		let result = decode_disclosure_signals(&signals).unwrap();
		assert_eq!(result.len(), 4);
		assert_eq!(result[0][0], 0xAA);
		assert_eq!(result[1][0], 0xBB);
		assert_eq!(result[2][0], 0xCC);
		assert_eq!(result[3][0], 0xDD);
	}

	#[test]
	fn decode_disclosure_signals_wrong_length() {
		assert!(decode_disclosure_signals(&[0u8; 75]).is_err());
		assert!(decode_disclosure_signals(&[0u8; 77]).is_err());
		assert!(decode_disclosure_signals(&[]).is_err());
	}
}
