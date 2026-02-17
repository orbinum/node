//! BlockHash value object - Block hash

use core::fmt;

/// Block hash (32 bytes).
///
/// Value object representing a blockchain block hash.
/// Used to identify specific blocks during queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
	/// Creates a `BlockHash` from raw bytes.
	pub fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns hash bytes.
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// Returns the bytes as a slice.
	pub fn as_slice(&self) -> &[u8] {
		&self.0
	}

	/// Creates from slice (must be exactly 32 bytes).
	pub fn from_slice(bytes: &[u8]) -> Option<Self> {
		if bytes.len() == 32 {
			let mut arr = [0u8; 32];
			arr.copy_from_slice(bytes);
			Some(Self(arr))
		} else {
			None
		}
	}
}

impl From<[u8; 32]> for BlockHash {
	fn from(bytes: [u8; 32]) -> Self {
		Self::new(bytes)
	}
}

impl AsRef<[u8]> for BlockHash {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl fmt::Display for BlockHash {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "0x{}", hex::encode(self.0))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_and_read_block_hash() {
		let bytes = [0xabu8; 32];
		let hash = BlockHash::new(bytes);

		assert_eq!(hash.as_bytes(), &bytes);
		assert_eq!(hash.as_slice(), &bytes);
	}

	#[test]
	fn should_create_from_valid_slice_and_reject_invalid_length() {
		let valid = [1u8; 32];
		let invalid = [1u8; 31];

		assert_eq!(BlockHash::from_slice(&valid), Some(BlockHash::new(valid)));
		assert_eq!(BlockHash::from_slice(&invalid), None);
	}

	#[test]
	fn should_support_from_array_and_as_ref() {
		let bytes = [7u8; 32];
		let hash: BlockHash = bytes.into();

		assert_eq!(hash.as_ref(), &bytes);
	}

	#[test]
	fn should_format_as_prefixed_hex_string() {
		let hash = BlockHash::new([0u8; 32]);
		let formatted = hash.to_string();

		assert!(formatted.starts_with("0x"));
		assert_eq!(formatted.len(), 66);
		assert_eq!(formatted, format!("0x{}", "00".repeat(32)));
	}
}
