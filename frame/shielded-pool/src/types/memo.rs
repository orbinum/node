// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Encrypted memo attached to a commitment.
//!
//! Fixed at exactly `MAX_ENCRYPTED_MEMO_SIZE` bytes with a fixed field layout,
//! which is what lets the accessors slice it by offset. Those accessors are
//! defensive anyway — they return an empty slice rather than panicking if the
//! invariant is ever violated, since a panic here would be reachable from a
//! dispatchable.

use frame_support::{BoundedVec, pallet_prelude::*};
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

// EncryptedMemo (concrete, FRAME-compatible — used in storage & extrinsics)

/// Max encrypted memo size: `nonce(12) + ciphertext(120) + MAC(16) + ephPk(32) = 180`.
pub const MAX_ENCRYPTED_MEMO_SIZE: u32 = 180;

/// Position of the format byte: the memo's second nonce byte.
///
/// The nonce is public, so the chain reads it without any key:
///
/// | nonce bytes | content                                             |
/// |-------------|-----------------------------------------------------|
/// | `0`         | view tag (opaque to the chain)                      |
/// | `1`         | format: `MEMO_FORMAT_TAGGED` or `MEMO_FORMAT_HANDSHAKE` |
/// | `2..10`     | detection tag (opaque to the chain)                 |
/// | `10..12`    | random                                              |
pub const MEMO_FORMAT_BYTE_INDEX: usize = 1;
/// A note found by lookup: its owner predicts its ephemeral key or its tag, so a
/// wallet that does not predict it can skip the trial ECDH.
pub const MEMO_FORMAT_TAGGED: u8 = 0x01;
/// A note found by trial ECDH, as every memo before the format existed: the
/// first payment between two parties, which opens their tagged channel.
pub const MEMO_FORMAT_HANDSHAKE: u8 = 0x02;

/// The format a memo declares in its format byte: how its owner finds it.
///
/// Any other byte is undeclared (a memo from a wallet that predates the format,
/// or a format this runtime does not know): a new format needs a runtime
/// upgrade before the chain accepts it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoFormat {
	/// [`MEMO_FORMAT_TAGGED`].
	Tagged,
	/// [`MEMO_FORMAT_HANDSHAKE`].
	Handshake,
}

impl MemoFormat {
	/// The format `byte` declares, if any.
	pub const fn from_byte(byte: u8) -> Option<Self> {
		match byte {
			MEMO_FORMAT_TAGGED => Some(Self::Tagged),
			MEMO_FORMAT_HANDSHAKE => Some(Self::Handshake),
			_ => None,
		}
	}

	/// The byte that declares this format.
	pub const fn byte(self) -> u8 {
		match self {
			Self::Tagged => MEMO_FORMAT_TAGGED,
			Self::Handshake => MEMO_FORMAT_HANDSHAKE,
		}
	}
}

/// Encrypted memo attached to a commitment (ChaCha20-Poly1305).
#[derive(
	Clone,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Debug,
	Default
)]
pub struct EncryptedMemo(pub BoundedVec<u8, ConstU32<MAX_ENCRYPTED_MEMO_SIZE>>);

impl EncryptedMemo {
	pub fn new(data: Vec<u8>) -> Result<Self, &'static str> {
		BoundedVec::try_from(data)
			.map(Self)
			.map_err(|_| "Memo size exceeds maximum")
	}
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}
	/// Whether this is a full memo: exactly `MAX_ENCRYPTED_MEMO_SIZE` bytes, the
	/// only size a note's secrets are sealed into. Anything shorter cannot be
	/// opened, so the note it describes would be unrecoverable from the chain.
	pub fn is_valid_size(&self) -> bool {
		self.0.len() == MAX_ENCRYPTED_MEMO_SIZE as usize
	}
	/// The format a full memo declares, or None when it declares none. A memo
	/// that is not full size has no format either: it is no memo a wallet can
	/// open, whatever its second byte holds. Reads public bytes only; whether
	/// the declaration is honest depends on keys the chain never sees.
	pub fn format(&self) -> Option<MemoFormat> {
		if !self.is_valid_size() {
			return None;
		}
		self.0
			.get(MEMO_FORMAT_BYTE_INDEX)
			.copied()
			.and_then(MemoFormat::from_byte)
	}
	pub fn len(&self) -> usize {
		self.0.len()
	}
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
		if bytes.len() != MAX_ENCRYPTED_MEMO_SIZE as usize {
			return Err("Invalid memo size");
		}
		Self::new(bytes.to_vec())
	}
	pub fn nonce(&self) -> &[u8] {
		// Invariant: EncryptedMemo is always exactly MAX_ENCRYPTED_MEMO_SIZE bytes after
		// construction. from_bytes() enforces this; the else branch is unreachable in practice.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 12 {
			&self.0[..12]
		} else {
			&[]
		}
	}
	pub fn ciphertext(&self) -> &[u8] {
		// Invariant: see nonce(). ciphertext occupies bytes 12..132.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 132 {
			&self.0[12..132]
		} else {
			&[]
		}
	}
	/// The Poly1305 MAC, not the detection tag in the nonce (see
	/// [`MEMO_FORMAT_BYTE_INDEX`]).
	pub fn tag(&self) -> &[u8] {
		// Layout: nonce(0..12) | ciphertext(12..132) | tag/MAC(132..148) | ephPk(148..180)
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 148 {
			&self.0[132..148]
		} else {
			&[]
		}
	}
	pub fn eph_pk(&self) -> &[u8] {
		// Ephemeral BabyJubJub public key (packed, LE) occupies bytes 148..180.
		debug_assert_eq!(
			self.0.len(),
			MAX_ENCRYPTED_MEMO_SIZE as usize,
			"EncryptedMemo invariant violated: expected {} bytes, got {}",
			MAX_ENCRYPTED_MEMO_SIZE,
			self.0.len()
		);
		if self.0.len() >= 180 {
			&self.0[148..180]
		} else {
			&[]
		}
	}
}
