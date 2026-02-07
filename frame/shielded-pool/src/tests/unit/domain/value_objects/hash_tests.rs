//! Tests for hash

use crate::domain::value_objects::Hash;

#[test]
fn hash_has_correct_size() {
	let hash: Hash = [0u8; 32];
	assert_eq!(hash.len(), 32);
}
