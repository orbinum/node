//! How values are written in the signed text: lowercase `0x` hex, accounts, ORB
//! amounts and `key: value` lines. Pure functions; clients reproduce them byte
//! for byte.

use crate::{evm::account::EVM_ACCOUNT_MARKER, AccountId};
use alloc::vec::Vec;

const ORB_DECIMALS: u32 = 18;
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// `0x` followed by lowercase hex.
pub(super) fn hex(bytes: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(2 + 2 * bytes.len());
	out.extend_from_slice(b"0x");
	for b in bytes {
		out.push(DIGITS[(b >> 4) as usize]);
		out.push(DIGITS[(b & 0x0f) as usize]);
	}
	out
}

/// An account: an EVM account (`[address | 0x00×12]`) as its 20-byte address,
/// the way its owner knows it, and any other as its 32 bytes. The lengths
/// differ, so an account that shares an EVM address's first 20 bytes never
/// looks like it.
pub(super) fn account(who: &AccountId) -> Vec<u8> {
	let raw: &[u8] = who.as_ref();
	match raw.split_at(20) {
		(address, marker) if marker == EVM_ACCOUNT_MARKER => hex(address),
		_ => hex(raw),
	}
}

/// A 32-byte value's first and last eight bytes as lowercase hex around an ellipsis
/// (`0x1c1c1c1c1c1c1c1c…1c1c1c1c1c1c1c1c`): 128 bits, beyond a second-preimage search
/// for a value that shows the same.
pub(super) fn fingerprint(bytes: &[u8; 32]) -> Vec<u8> {
	let mut out = hex(&bytes[..8]);
	out.extend_from_slice("…".as_bytes());
	out.extend_from_slice(&hex(&bytes[24..])[2..]);
	out
}

/// [`fingerprint`] of `blake2_256(bytes)`, for values of any length.
pub(super) fn hash_fingerprint(bytes: &[u8]) -> Vec<u8> {
	fingerprint(&sp_io::hashing::blake2_256(bytes))
}

/// `amount` in ORB: the whole part, then the fraction without trailing zeros
/// (`1.5 ORB`, `2 ORB`, `0.000000000000000001 ORB`).
pub(super) fn orb(amount: u128) -> Vec<u8> {
	let mut out = units(amount);
	out.extend_from_slice(b" ORB");
	out
}

/// `amount` with ORB's 18 decimals and no unit (`1.5`, `2`), for quantities in
/// ORB's scale that are not ORB, such as pool points.
pub(super) fn units(amount: u128) -> Vec<u8> {
	let unit = 10u128.pow(ORB_DECIMALS);
	let mut out = decimal(amount / unit);
	let mut fraction = amount % unit;
	if fraction != 0 {
		let mut digits = [b'0'; ORB_DECIMALS as usize];
		for d in digits.iter_mut().rev() {
			*d = b'0' + (fraction % 10) as u8;
			fraction /= 10;
		}
		let end = digits.iter().rposition(|d| *d != b'0').map_or(0, |i| i + 1);
		out.push(b'.');
		out.extend_from_slice(&digits[..end]);
	}
	out
}

/// A `Perbill` as a percentage without trailing zeros (`12.5%`, `0%`, `100%`).
pub(super) fn percent(parts: u32) -> Vec<u8> {
	// Perbill is parts per 10^9, so a percent is 10^7 parts.
	let mut out = decimal((parts / 10_000_000) as u128);
	let mut fraction = parts % 10_000_000;
	if fraction != 0 {
		let mut digits = [b'0'; 7];
		for d in digits.iter_mut().rev() {
			*d = b'0' + (fraction % 10) as u8;
			fraction /= 10;
		}
		let end = digits.iter().rposition(|d| *d != b'0').map_or(0, |i| i + 1);
		out.push(b'.');
		out.extend_from_slice(&digits[..end]);
	}
	out.push(b'%');
	out
}

/// Appends `\n{key}: {value}`.
pub(super) fn line(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
	out.push(b'\n');
	out.extend_from_slice(key);
	out.extend_from_slice(b": ");
	out.extend_from_slice(value);
}

pub(super) fn decimal(mut n: u128) -> Vec<u8> {
	let mut out = Vec::new();
	loop {
		out.push(b'0' + (n % 10) as u8);
		n /= 10;
		if n == 0 {
			break;
		}
	}
	out.reverse();
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hex_is_lowercase_with_a_prefix() {
		assert_eq!(hex(&[]), b"0x");
		assert_eq!(hex(&[0x00, 0xab, 0xff, 0x0f]), b"0x00abff0f");
	}

	#[test]
	fn fingerprint_shows_16_bytes() {
		let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
		assert_eq!(
			fingerprint(&bytes),
			"0x0001020304050607…18191a1b1c1d1e1f".as_bytes()
		);
		let hash = sp_io::hashing::blake2_256(b"memo");
		assert_eq!(hash_fingerprint(b"memo"), fingerprint(&hash));
	}

	#[test]
	fn orb_amounts_drop_trailing_zeros() {
		let cases: [(u128, &str); 7] = [
			(0, "0 ORB"),
			(1, "0.000000000000000001 ORB"),
			(10_000_000_000_000_000, "0.01 ORB"),
			(1_500_000_000_000_000_000, "1.5 ORB"),
			(2_000_000_000_000_000_000, "2 ORB"),
			(1_000_000_000_000_000_001, "1.000000000000000001 ORB"),
			(u128::MAX, "340282366920938463463.374607431768211455 ORB"),
		];
		for (amount, text) in cases {
			assert_eq!(orb(amount), text.as_bytes(), "{amount}");
		}
	}

	#[test]
	fn units_are_orb_without_the_unit() {
		assert_eq!(units(0), b"0");
		assert_eq!(units(1_500_000_000_000_000_000), b"1.5");
		assert_eq!(units(1), b"0.000000000000000001");
	}

	#[test]
	fn percents_drop_trailing_zeros() {
		let cases: [(u32, &str); 5] = [
			(0, "0%"),
			(1, "0.0000001%"),
			(125_000_000, "12.5%"),
			(200_000_000, "20%"),
			(1_000_000_000, "100%"),
		];
		for (parts, text) in cases {
			assert_eq!(percent(parts), text.as_bytes(), "{parts}");
		}
	}

	#[test]
	fn a_line_starts_with_a_newline() {
		let mut out = b"action: X".to_vec();
		line(&mut out, b"amount", b"1 ORB");
		assert_eq!(out, b"action: X\namount: 1 ORB");
	}
}
