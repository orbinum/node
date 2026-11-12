// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `major.minor.patch` version a node declares.

use core::fmt;
use scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// A `major.minor.patch` node version. Ordering is lexicographic over the
/// fields, which is semver precedence for release versions.
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	Debug
)]
// Published in the metadata under its former module, `author_version::version`.
#[scale_info(replace_segment("types", "author_version"))]
pub struct NodeVersion {
	pub major: u16,
	pub minor: u16,
	pub patch: u16,
}

impl NodeVersion {
	pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
		Self {
			major,
			minor,
			patch,
		}
	}

	/// Parses `major.minor.patch`, ignoring any `-pre` or `+build` suffix. Each
	/// part must be a non-empty decimal that fits in a `u16`.
	///
	/// `const`, so a node can parse its own crate version at compile time and a
	/// version that does not fit fails the build rather than the running node.
	pub const fn parse(version: &str) -> Option<Self> {
		let bytes = version.as_bytes();
		let mut parts = [0u16; 3];
		let (mut part, mut value, mut digits, mut i) = (0usize, 0u32, 0usize, 0usize);
		while i < bytes.len() {
			match bytes[i] {
				b @ b'0'..=b'9' => {
					// `value` <= u16::MAX here, so this cannot overflow a u32.
					value = value * 10 + (b - b'0') as u32;
					if value > u16::MAX as u32 {
						return None;
					}
					digits += 1;
				}
				b'.' if digits > 0 && part < 2 => {
					parts[part] = value as u16;
					(part, value, digits) = (part + 1, 0, 0);
				}
				b'-' | b'+' => break,
				_ => return None,
			}
			i += 1;
		}
		if digits == 0 || part != 2 {
			return None;
		}
		parts[2] = value as u16;
		Some(Self::new(parts[0], parts[1], parts[2]))
	}
}

impl fmt::Display for NodeVersion {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
	}
}
