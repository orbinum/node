//! NullifierStatusResponse DTO - Nullifier status response

use serde::{Deserialize, Serialize};

/// Response DTO for nullifier status.
///
/// Indicates whether a nullifier has already been spent or is still available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierStatusResponse {
	/// Nullifier in hex format.
	pub nullifier: String,
	/// `true` if the nullifier is spent, `false` if available.
	pub is_spent: bool,
}

impl NullifierStatusResponse {
	/// Creates a new `NullifierStatusResponse`.
	pub fn new(nullifier: String, is_spent: bool) -> Self {
		Self {
			nullifier,
			is_spent,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn should_create_nullifier_status_response() {
		let response = NullifierStatusResponse::new("0xdeadbeef".to_string(), true);

		assert_eq!(response.nullifier, "0xdeadbeef");
		assert!(response.is_spent);
	}

	#[test]
	fn should_support_expected_traits() {
		fn assert_serialize<T: Serialize>() {}
		fn assert_deserialize<T: for<'de> Deserialize<'de>>() {}
		fn assert_clone<T: Clone>() {}
		fn assert_debug<T: core::fmt::Debug>() {}
		fn assert_eq_trait<T: Eq>() {}

		assert_serialize::<NullifierStatusResponse>();
		assert_deserialize::<NullifierStatusResponse>();
		assert_clone::<NullifierStatusResponse>();
		assert_debug::<NullifierStatusResponse>();
		assert_eq_trait::<NullifierStatusResponse>();
	}
}
