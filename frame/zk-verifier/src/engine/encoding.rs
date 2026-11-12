// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Public-input encoding: a circuit's statement to the field elements its
//! verifying key expects.
//!
//! The one place that knows each circuit's input order and how a domain value
//! becomes a BN254 field element (32 bytes, little-endian, canonical). The
//! [`InputLayout`] comes from the key being verified against, so a memo-bound
//! and a cross-tree key each get the inputs they were built for. A base spend
//! key gets none: it binds no memo, and the verifier never admits it.

use crate::types::{ShieldStatement, TransferStatement, UnshieldStatement};
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

pub(crate) fn u32_field(v: u32) -> [u8; 32] {
	let mut out = [0u8; 32];
	out[..4].copy_from_slice(&v.to_le_bytes());
	out
}

pub(crate) fn u128_field(v: u128) -> [u8; 32] {
	let mut out = [0u8; 32];
	out[..16].copy_from_slice(&v.to_le_bytes());
	out
}
