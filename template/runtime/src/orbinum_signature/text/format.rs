//! How values are written in the signed text: lowercase `0x` hex, ORB amounts and
//! `key: value` lines. Pure functions; clients reproduce them byte for byte.

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

/// `amount` in ORB: the whole part, then the fraction without trailing zeros
/// (`1.5 ORB`, `2 ORB`, `0.000000000000000001 ORB`).
pub(super) fn orb(amount: u128) -> Vec<u8> {
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
	out.extend_from_slice(b" ORB");
	out
}

/// Appends `\n{key}: {value}`.
pub(super) fn line(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
	out.push(b'\n');
	out.extend_from_slice(key);
	out.extend_from_slice(b": ");
	out.extend_from_slice(value);
}

fn decimal(mut n: u128) -> Vec<u8> {
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
	fn a_line_starts_with_a_newline() {
		let mut out = b"action: X".to_vec();
		line(&mut out, b"amount", b"1 ORB");
		assert_eq!(out, b"action: X\namount: 1 ORB");
	}
}
