//! Public-input encoding: a circuit's statement to the field elements its
//! verifying key expects.
//!
//! The one place that knows each circuit's input order and how a domain value
//! becomes a BN254 field element (32 bytes, little-endian, canonical). The
//! [`InputLayout`] comes from the key being verified against, so a memo-bound
//! and a cross-tree key each get the inputs they were built for. A base spend
//! key gets none: it binds no memo, and the verifier never admits it.

use crate::port::{ShieldStatement, TransferStatement, UnshieldStatement};
use alloc::vec::Vec;
use orbinum_zk_verifier::{InputLayout, to_field_le};

/// Transfer inputs, in circuit order:
/// `merkle_root | nullifiers.. | commitments.. | asset_id | fee | memo_hash`, or
/// for the cross-tree layout `merkle_roots[0] | merkle_roots[1] | ..` in place of
/// the single root.
///
/// `None` when the key cannot attest to the statement: a key with one root
/// cannot attest to two, so the proof fails without a pairing.
pub fn encode_transfer(s: &TransferStatement, layout: InputLayout) -> Option<Vec<[u8; 32]>> {
	let [root0, root1] = s.merkle_roots;
	let mut raw = Vec::with_capacity(5 + s.nullifiers.len() + s.commitments.len());
	match layout {
		InputLayout::CrossTree => raw.extend_from_slice(&s.merkle_roots),
		InputLayout::MemoBound if root0 == root1 => raw.push(root0),
		InputLayout::MemoBound | InputLayout::Base => return None,
	}
	raw.extend_from_slice(&s.nullifiers);
	raw.extend_from_slice(&s.commitments);
	raw.push(u32_field(s.asset_id));
	raw.push(u128_field(s.fee));
	raw.push(to_field_le(&s.memo_digest));
	Some(raw)
}

/// Unshield inputs, in circuit order:
/// `merkle_root | nullifier | amount | recipient | asset_id | fee | change_commitment | memo_hash`.
///
/// `recipient` is an AccountId32, wider than the field, so it is hashed first:
/// taken mod r, `R` and `R ± r` would be the same input, and a copier could
/// redirect the withdrawal to an alias nobody controls.
///
/// `None` for any layout but the memo-bound one: an unshield spends one note,
/// so no cross-tree key can exist for it (`input_layout`).
pub fn encode_unshield(s: &UnshieldStatement, layout: InputLayout) -> Option<Vec<[u8; 32]>> {
	if layout != InputLayout::MemoBound {
		return None;
	}
	Some(alloc::vec![
		s.merkle_root,
		s.nullifier,
		u128_field(s.amount),
		to_field_le(&sp_io::hashing::blake2_256(&s.recipient)),
		u32_field(s.asset_id),
		u128_field(s.fee),
		s.change_commitment,
		to_field_le(&s.memo_digest),
	])
}

/// Shield inputs, in circuit order: `commitment | value | asset_id`.
pub fn encode_shield(s: &ShieldStatement) -> Vec<[u8; 32]> {
	alloc::vec![s.commitment, u128_field(s.value), u32_field(s.asset_id)]
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
	use orbinum_zk_verifier::{
		CROSS_TREE_INPUTS, MEMO_HASH_INPUTS, TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS,
	};

	const NULLIFIERS: [[u8; 32]; 2] = [[0x02; 32], [0x03; 32]];
	const COMMITMENTS: [[u8; 32]; 2] = [[0x04; 32], [0x05; 32]];

	fn transfer() -> TransferStatement {
		TransferStatement {
			merkle_roots: [[0x01; 32]; 2],
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

	/// `x + r`, little-endian: different bytes, the same field element as `x`.
	fn field_twin(x: [u8; 32]) -> [u8; 32] {
		// BN254 r, little-endian.
		const R: [u8; 32] = [
			0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8,
			0x33, 0x28, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1,
			0x72, 0x4e, 0x64, 0x30,
		];
		let mut out = [0u8; 32];
		let mut carry = 0u16;
		for i in 0..32 {
			let sum = u16::from(x[i]) + u16::from(R[i]) + carry;
			out[i] = sum as u8;
			carry = sum >> 8;
		}
		assert_eq!(carry, 0, "x + r must fit in 32 bytes");
		assert_eq!(to_field_le(&out), to_field_le(&x), "same field element");
		out
	}

	#[test]
	fn transfer_follows_circuit_order() {
		let raw = encode_transfer(&transfer(), InputLayout::MemoBound).unwrap();
		assert_eq!(raw.len(), TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS);
		assert_eq!(raw[0], [0x01; 32]);
		assert_eq!(&raw[1..3], &NULLIFIERS);
		assert_eq!(&raw[3..5], &COMMITMENTS);
		assert_eq!(raw[5], u32_field(7));
		assert_eq!(raw[6], u128_field(500));
		assert_eq!(raw[7], to_field_le(&[0xEE; 32]));
	}

	#[test]
	fn a_base_spend_key_gets_no_encoding() {
		assert!(encode_transfer(&transfer(), InputLayout::Base).is_none());
		assert!(encode_unshield(&unshield(), InputLayout::Base).is_none());
	}

	#[test]
	fn cross_tree_transfer_puts_one_root_per_input_first() {
		let s = TransferStatement {
			merkle_roots: [[0x01; 32], [0x09; 32]],
			..transfer()
		};
		let raw = encode_transfer(&s, InputLayout::CrossTree).unwrap();
		assert_eq!(
			raw.len(),
			TRANSFER_PUBLIC_INPUTS + MEMO_HASH_INPUTS + CROSS_TREE_INPUTS
		);
		assert_eq!(raw[0], [0x01; 32]);
		assert_eq!(raw[1], [0x09; 32]);
		assert_eq!(&raw[2..4], &NULLIFIERS);
		assert_eq!(&raw[4..6], &COMMITMENTS);
		assert_eq!(raw[6], u32_field(7));
		assert_eq!(raw[7], u128_field(500));
		assert_eq!(raw[8], to_field_le(&[0xEE; 32]));
	}

	#[test]
	fn a_single_root_key_cannot_attest_to_two_roots() {
		let s = TransferStatement {
			merkle_roots: [[0x01; 32], [0x09; 32]],
			..transfer()
		};
		assert!(encode_transfer(&s, InputLayout::MemoBound).is_none());
	}

	#[test]
	fn an_unshield_has_no_cross_tree_encoding() {
		assert!(encode_unshield(&unshield(), InputLayout::CrossTree).is_none());
	}

	/// `memo_digest` is a blake2 output, so it is reduced mod r rather than
	/// refused: a 256-bit twin would need a blake2 preimage. Two digests that are
	/// twins encode the same; two that differ in the field encode differently.
	#[test]
	fn memo_digest_twins_encode_the_same_and_distinct_digests_differ() {
		let digest = [0x11; 32];
		let twin = field_twin(digest);
		let encode = |memo_digest| {
			encode_transfer(
				&TransferStatement {
					memo_digest,
					..transfer()
				},
				InputLayout::MemoBound,
			)
			.unwrap()
		};
		assert_eq!(encode(digest), encode(twin));
		assert_ne!(encode(digest), encode([0x12; 32]));
	}

	#[test]
	fn unshield_follows_circuit_order_with_a_hashed_recipient() {
		let raw = encode_unshield(&unshield(), InputLayout::MemoBound).unwrap();
		assert_eq!(raw.len(), UNSHIELD_PUBLIC_INPUTS + MEMO_HASH_INPUTS);
		assert_eq!(raw[0], [0x01; 32]);
		assert_eq!(raw[1], [0x02; 32]);
		assert_eq!(raw[2], u128_field(100));
		assert_eq!(
			raw[3],
			to_field_le(&sp_io::hashing::blake2_256(&[0xFF; 32]))
		);
		assert_eq!(raw[4], u32_field(7));
		assert_eq!(raw[5], u128_field(5));
		assert_eq!(raw[6], [0x06; 32]);
		assert_eq!(raw[7], to_field_le(&[0xEE; 32]));
	}

	/// `R + r` is the same field element as `R`; hashed first, it is another input.
	#[test]
	fn a_recipient_alias_encodes_differently() {
		let recipient = [0x01; 32];
		let aliased = UnshieldStatement {
			recipient: field_twin(recipient),
			..unshield()
		};
		let original = UnshieldStatement {
			recipient,
			..unshield()
		};
		assert_ne!(original.recipient, aliased.recipient);
		assert_ne!(
			encode_unshield(&original, InputLayout::MemoBound).unwrap(),
			encode_unshield(&aliased, InputLayout::MemoBound).unwrap()
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
			)
			.unwrap()[3]
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
		let raw = encode_unshield(&max, InputLayout::MemoBound).unwrap();
		assert!(
			orbinum_zk_verifier::PublicInputs::new(raw)
				.to_field_elements()
				.is_ok()
		);
	}

	#[test]
	fn shield_encodes_commitment_value_and_asset_in_circuit_order() {
		let s = ShieldStatement {
			commitment: [0x09; 32],
			value: u128::MAX,
			asset_id: 7,
		};
		let raw = encode_shield(&s);
		assert_eq!(raw.len(), orbinum_zk_verifier::SHIELD_PUBLIC_INPUTS);
		assert_eq!(raw[0], [0x09; 32]);
		// u128 little-endian in the low 16 bytes; the high half stays zero.
		assert_eq!(raw[1][..16], [0xFF; 16]);
		assert_eq!(raw[1][16..], [0; 16]);
		assert_eq!(raw[2], u32_field(7));
	}

	// ── shield against a real proof ───────────────────────────────────────────

	/// A real shield proof of `@orbinum/circuits` 0.16.0 (`fixtures/shield.input.json`:
	/// a 1000-unit note of asset 0), checked through `encode_shield` against the
	/// published key (`vk_hash 0x4835d34f…5cb7`). The pallet's own verifier is
	/// stubbed under `cfg(test)`, so this is where the encoding meets the circuit.
	mod shield_real_proof {
		use super::*;
		use orbinum_zk_verifier::{
			Groth16Verifier, PublicInputs, SnarkjsProofPoints, VerifyingKey,
			parse_proof_from_snarkjs,
		};

		const VK: &[u8] = include_bytes!("test_fixtures/shield_vk.bin");

		/// `Poseidon4(1000, 0, ownerPk, blinding)`, little-endian.
		const COMMITMENT: [u8; 32] = [
			0x69, 0x75, 0xce, 0xc7, 0x9d, 0xcd, 0x25, 0x7a, 0xc6, 0x99, 0x18, 0x2b, 0x9f, 0xc6,
			0x2d, 0xf6, 0x92, 0x3e, 0x50, 0xc7, 0x51, 0x82, 0xff, 0x0b, 0x69, 0x1f, 0xb1, 0x8c,
			0x16, 0xe2, 0x88, 0x17,
		];

		fn verifies(statement: ShieldStatement) -> bool {
			let proof = parse_proof_from_snarkjs(SnarkjsProofPoints {
				a_x: "20582419949357486020948756662654742944819106688442895228932566507097686181492",
				a_y: "11046279096408876553973745195746033188489133537652590673138219726350432190690",
				b_x0: "838573338912504267236782093804520743622125922969862721536857124431906106618",
				b_x1: "2429257530267642355656915667588525092022338138648113768996919794768393138344",
				b_y0: "8916514610009504152135293951898251181004123961747103831149158072089283668368",
				b_y1: "19652615522895145510932891878583235492762167007808681662006766972958083269857",
				c_x: "21486029233340201890864616292482025659316043756526048371921004920306878820982",
				c_y: "10093061124683382138290144938555180922737004347330625633977406280723892224584",
			})
			.unwrap();
			let inputs = PublicInputs::new(encode_shield(&statement));
			Groth16Verifier::verify(&VerifyingKey::new(VK.to_vec()), &inputs, &proof).is_ok()
		}

		fn deposit(value: u128, asset_id: u32) -> ShieldStatement {
			ShieldStatement {
				commitment: COMMITMENT,
				value,
				asset_id,
			}
		}

		#[test]
		fn verifies_the_deposit_the_note_encodes() {
			assert!(verifies(deposit(1000, 0)));
		}

		#[test]
		fn rejects_a_smaller_deposit_for_the_same_note() {
			assert!(!verifies(deposit(1, 0)));
		}

		#[test]
		fn rejects_another_asset() {
			assert!(!verifies(deposit(1000, 5)));
		}

		/// The same field element, as `commitment + r`: a verifier that reduced
		/// inputs mod r would accept it, and the commitment would then have two
		/// encodings. The pallet refuses it as non-canonical before verifying;
		/// this shows the verifier refuses it too.
		#[test]
		fn rejects_a_non_canonical_encoding_of_the_commitment() {
			let shifted = super::field_twin(COMMITMENT);
			assert!(!verifies(ShieldStatement {
				commitment: shifted,
				value: 1000,
				asset_id: 0
			}));
		}

		#[test]
		fn rejects_another_commitment() {
			let mut other = deposit(1000, 0);
			other.commitment[0] ^= 1;
			assert!(!verifies(other));
		}
	}
}
