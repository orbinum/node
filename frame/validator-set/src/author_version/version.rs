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

#[cfg(test)]
mod tests {
	use super::NodeVersion;

	const V: fn(u16, u16, u16) -> NodeVersion = NodeVersion::new;

	#[test]
	fn parses_release_and_suffixed_versions() {
		assert_eq!(NodeVersion::parse("0.3.0"), Some(V(0, 3, 0)));
		assert_eq!(NodeVersion::parse("1.12.7-rc.1"), Some(V(1, 12, 7)));
		assert_eq!(NodeVersion::parse("2.0.1+sha.abc"), Some(V(2, 0, 1)));
		assert_eq!(
			NodeVersion::parse("65535.0.65535"),
			Some(V(65535, 0, 65535))
		);
	}

	#[test]
	fn rejects_malformed_versions() {
		for bad in [
			"",
			"1",
			"1.2",
			"1.2.3.4",
			"a.b.c",
			"1.2.x",
			"1..2",
			".1.2",
			"1.2.",
			"70000.0.0",
			"1.65536.0",
			"-1.2.3",
			" 1.2.3",
		] {
			assert_eq!(NodeVersion::parse(bad), None, "{bad:?}");
		}
	}

	#[test]
	fn parses_at_compile_time() {
		const PARSED: Option<NodeVersion> = NodeVersion::parse("1.2.3");
		assert_eq!(PARSED, Some(V(1, 2, 3)));
	}

	#[test]
	fn orders_by_major_then_minor_then_patch() {
		assert!(V(0, 3, 0) < V(0, 3, 1));
		assert!(V(0, 3, 9) < V(0, 4, 0));
		assert!(V(0, 9, 9) < V(1, 0, 0));
		assert_eq!(V(1, 2, 3), V(1, 2, 3));
	}

	#[test]
	fn displays_as_major_minor_patch() {
		assert_eq!(V(0, 4, 12).to_string(), "0.4.12");
	}
}
