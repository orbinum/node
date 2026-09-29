//! Public-input encoding: a circuit's statement to the field elements its
//! verifying key expects.
//!
//! The one place that knows each circuit's input order and how a domain value
//! becomes a BN254 field element (32 bytes, little-endian, canonical). The
//! [`InputLayout`] comes from the key being verified against, so a v1 and a
//! memo-bound key each get the inputs they were built for.

use crate::port::{TransferStatement, UnshieldStatement};
use alloc::vec::Vec;
use orbinum_zk_verifier::{InputLayout, to_field_le};

/// Transfer inputs, in circuit order:
/// `merkle_root | nullifiers.. | commitments.. | asset_id | fee [| memo_hash]`.
pub fn encode_transfer(s: &TransferStatement, layout: InputLayout) -> Vec<[u8; 32]> {
	let mut raw = Vec::with_capacity(4 + s.nullifiers.len() + s.commitments.len());
	raw.push(s.merkle_root);
	raw.extend_from_slice(&s.nullifiers);
	raw.extend_from_slice(&s.commitments);
	raw.push(u32_field(s.asset_id));
	raw.push(u128_field(s.fee));
	if layout == InputLayout::MemoBound {
		raw.push(to_field_le(&s.memo_digest));
	}
	raw
}

/// Unshield inputs, in circuit order:
/// `merkle_root | nullifier | amount | recipient | asset_id | fee | change_commitment [| memo_hash]`.
///
/// `recipient` is an AccountId32, wider than the field. The base layout takes
/// it mod r, which maps `R` and `R ± r` to the same input — a copier could
/// redirect the withdrawal to an alias nobody controls. The memo-bound layout
/// hashes it first, so an alias would need a blake2 collision.
pub fn encode_unshield(s: &UnshieldStatement, layout: InputLayout) -> Vec<[u8; 32]> {
	let (recipient, memo_hash) = match layout {
		InputLayout::Base => (to_field_le(&s.recipient), None),
		InputLayout::MemoBound => (
			to_field_le(&sp_io::hashing::blake2_256(&s.recipient)),
			Some(to_field_le(&s.memo_digest)),
		),
	};
	let mut raw = alloc::vec![
		s.merkle_root,
		s.nullifier,
		u128_field(s.amount),
		recipient,
		u32_field(s.asset_id),
		u128_field(s.fee),
		s.change_commitment,
	];
	raw.extend(memo_hash);
	raw
}

fn u32_field(v: u32) -> [u8; 32] {
	let mut out = [0u8; 32];
	out[..4].copy_from_slice(&v.to_le_bytes());
	out
}

fn u128_field(v: u128) -> [u8; 32] {
	let mut out = [0u8; 32];
	out[..16].copy_from_slice(&v.to_le_bytes());
	out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use orbinum_zk_verifier::{MEMO_HASH_INPUTS, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS};

	const NULLIFIERS: [[u8; 32]; 2] = [[0x02; 32], [0x03; 32]];
	const COMMITMENTS: [[u8; 32]; 2] = [[0x04; 32], [0x05; 32]];

	fn transfer() -> TransferStatement {
		TransferStatement {
			merkle_root: [0x01; 32],
			nullifiers: NULLIFIERS.to_vec(),
			commitments: COMMITMENTS.to_vec(),
			asset_id: 7,
			fee: 500,
			memo_digest: [0xEE; 32],
		}
	}

	fn unshield() -> UnshieldStatement {
		UnshieldStatement {
			merkle_root: [0x01; 32],
			nullifier: [0x02; 32],
			amount: 100,
			recipient: [0xFF; 32],
			asset_id: 7,
			fee: 5,
			change_commitment: [0x06; 32],
			memo_digest: [0xEE; 32],
		}
	}

	/// `R + r`: a different AccountId32 that is the same field element as `R`.
	fn alias(recipient: [u8; 32]) -> [u8; 32] {
		// BN254 r, little-endian.
		const R: [u8; 32] = [
			0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8,
			0x33, 0x28, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1,
			0x72, 0x4e, 0x64, 0x30,
		];
		let mut out = [0u8; 32];
		let mut carry = 0u16;
		for i in 0..32 {
			let sum = recipient[i] as u16 + R[i] as u16 + carry;
			out[i] = sum as u8;
			carry = sum >> 8;
		}
		assert_eq!(carry, 0, "recipient + r must fit in 32 bytes");
		out
	}

	#[test]
	fn transfer_follows_circuit_order() {
		let raw = encode_transfer(&transfer(), InputLayout::Base);
		assert_eq!(raw.len(), TRANSFER_PUBLIC_INPUTS);
		assert_eq!(raw[0], [0x01; 32]);
		assert_eq!(&raw[1..3], &NULLIFIERS);
		assert_eq!(&raw[3..5], &COMMITMENTS);
		assert_eq!(raw[5], u32_field(7));
		assert_eq!(raw[6], u128_field(500));
	}

	#[test]
	fn memo_bound_transfer_appends_the_reduced_memo_digest() {
		let base = encode_transfer(&transfer(), InputLayout::Base);
		let bound = encode_transfer(&transfer(), InputLayout::MemoBound);
		assert_eq!(bound.len(), TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS);
		assert_eq!(&bound[..TRANSFER_PUBLIC_INPUTS], &base[..]);
		assert_eq!(bound[TRANSFER_PUBLIC_INPUTS], to_field_le(&[0xEE; 32]));
	}

	#[test]
	fn memo_digest_only_matters_when_bound() {
		let other = TransferStatement {
			memo_digest: [0x11; 32],
			..transfer()
		};
		assert_eq!(
			encode_transfer(&transfer(), InputLayout::Base),
			encode_transfer(&other, InputLayout::Base)
		);
		assert_ne!(
			encode_transfer(&transfer(), InputLayout::MemoBound),
			encode_transfer(&other, InputLayout::MemoBound)
		);
	}

	#[test]
	fn unshield_follows_circuit_order() {
		let raw = encode_unshield(&unshield(), InputLayout::Base);
		assert_eq!(raw.len(), UNSHIELD_PUBLIC_INPUTS);
		assert_eq!(raw[0], [0x01; 32]);
		assert_eq!(raw[1], [0x02; 32]);
		assert_eq!(raw[2], u128_field(100));
		assert_eq!(raw[3], to_field_le(&[0xFF; 32]));
		assert_eq!(raw[4], u32_field(7));
		assert_eq!(raw[5], u128_field(5));
		assert_eq!(raw[6], [0x06; 32]);
	}

	#[test]
	fn memo_bound_unshield_hashes_the_recipient_and_appends_the_memo_digest() {
		let raw = encode_unshield(&unshield(), InputLayout::MemoBound);
		assert_eq!(raw.len(), UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS);
		assert_eq!(
			raw[3],
			to_field_le(&sp_io::hashing::blake2_256(&[0xFF; 32]))
		);
		assert_eq!(raw[UNSHIELD_PUBLIC_INPUTS], to_field_le(&[0xEE; 32]));
	}

	#[test]
	fn a_recipient_alias_encodes_the_same_only_in_the_base_layout() {
		let recipient = [0x01; 32];
		let aliased = UnshieldStatement {
			recipient: alias(recipient),
			..unshield()
		};
		let original = UnshieldStatement {
			recipient,
			..unshield()
		};
		assert_ne!(original.recipient, aliased.recipient);
		assert_eq!(
			encode_unshield(&original, InputLayout::Base),
			encode_unshield(&aliased, InputLayout::Base),
			"v1 cannot tell R from R + r"
		);
		assert_ne!(
			encode_unshield(&original, InputLayout::MemoBound),
			encode_unshield(&aliased, InputLayout::MemoBound)
		);
	}

	/// Shared with `@orbinum/protocol` (`addressToFieldElement(_, 2)`) and
	/// `@orbinum/wallet-sdk`: a client that disagrees proves another recipient.
	#[test]
	fn memo_bound_recipient_matches_the_cross_repo_vectors() {
		fn hex(bytes: [u8; 32]) -> String {
			bytes.iter().map(|b| format!("{b:02x}")).collect()
		}
		let recipient = |r| {
			encode_unshield(
				&UnshieldStatement {
					recipient: r,
					..unshield()
				},
				InputLayout::MemoBound,
			)[3]
		};
		assert_eq!(
			hex(recipient([0x01; 32])),
			"f30cea08db61944ea2c1fe5eb553bb5c3f55301bb3506c6f0051c5676608061c"
		);
		assert_eq!(
			hex(recipient([0xFF; 32])),
			"de0211a000397909c6c8b94fd72f023a5b2d8ca896c7ac8c3624784f491ecd12"
		);
	}

	#[test]
	fn every_input_is_canonical() {
		let max = UnshieldStatement {
			recipient: [0xFF; 32],
			memo_digest: [0xFF; 32],
			amount: u128::MAX,
			fee: u128::MAX,
			..unshield()
		};
		for layout in [InputLayout::Base, InputLayout::MemoBound] {
			let raw = encode_unshield(&max, layout);
			assert!(
				orbinum_zk_verifier::PublicInputs::new(raw)
					.to_field_elements()
					.is_ok(),
				"{layout:?}"
			);
		}
	}
}
