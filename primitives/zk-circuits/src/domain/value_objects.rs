//! Domain Value Objects
//!
//! Core value objects for ZK circuits.

use ark_bn254::Fr as Bn254Fr;

/// Circuit witness value (secret input)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessValue(pub Bn254Fr);

impl WitnessValue {
	/// Create from u64
	pub fn from_u64(value: u64) -> Self {
		Self(Bn254Fr::from(value))
	}

	/// Get inner field element
	pub fn inner(&self) -> Bn254Fr {
		self.0
	}
}

impl From<Bn254Fr> for WitnessValue {
	fn from(fr: Bn254Fr) -> Self {
		Self(fr)
	}
}

impl From<u64> for WitnessValue {
	fn from(value: u64) -> Self {
		Self::from_u64(value)
	}
}

/// Circuit public input value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicInput(pub Bn254Fr);

impl PublicInput {
	/// Create from u64
	pub fn from_u64(value: u64) -> Self {
		Self(Bn254Fr::from(value))
	}

	/// Get inner field element
	pub fn inner(&self) -> Bn254Fr {
		self.0
	}
}

impl From<Bn254Fr> for PublicInput {
	fn from(fr: Bn254Fr) -> Self {
		Self(fr)
	}
}

impl From<u64> for PublicInput {
	fn from(value: u64) -> Self {
		Self::from_u64(value)
	}
}

/// Merkle tree depth (domain constraint)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeDepth(pub usize);

impl TreeDepth {
	/// Standard depth for shielded pool
	pub const STANDARD: Self = Self(20);

	/// Maximum allowed depth
	pub const MAX: Self = Self(32);

	/// Create new depth with validation
	pub fn new(depth: usize) -> Result<Self, &'static str> {
		if depth == 0 {
			return Err("Tree depth must be positive");
		}
		if depth > Self::MAX.0 {
			return Err("Tree depth exceeds maximum");
		}
		Ok(Self(depth))
	}

	/// Get depth value
	pub fn value(&self) -> usize {
		self.0
	}
}

impl Default for TreeDepth {
	fn default() -> Self {
		Self::STANDARD
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::format;

	// ===== WitnessValue Tests =====

	#[test]
	fn test_witness_value() {
		let val = WitnessValue::from_u64(42);
		assert_eq!(val.inner(), Bn254Fr::from(42u64));
	}

	#[test]
	fn test_witness_value_from_u64() {
		let val = WitnessValue::from_u64(100);
		assert_eq!(val.inner(), Bn254Fr::from(100u64));
		assert_eq!(val.0, Bn254Fr::from(100u64));
	}

	#[test]
	fn test_witness_value_from_u64_zero() {
		let val = WitnessValue::from_u64(0);
		assert_eq!(val.inner(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_witness_value_from_u64_max() {
		let val = WitnessValue::from_u64(u64::MAX);
		assert_eq!(val.inner(), Bn254Fr::from(u64::MAX));
	}

	#[test]
	fn test_witness_value_inner() {
		let fr = Bn254Fr::from(999u64);
		let val = WitnessValue(fr);
		assert_eq!(val.inner(), fr);
	}

	#[test]
	fn test_witness_value_from_bn254fr() {
		let fr = Bn254Fr::from(123u64);
		let val: WitnessValue = fr.into();
		assert_eq!(val.inner(), fr);
	}

	#[test]
	fn test_witness_value_from_u64_trait() {
		let val: WitnessValue = 456u64.into();
		assert_eq!(val.inner(), Bn254Fr::from(456u64));
	}

	#[test]
	fn test_witness_value_clone() {
		let val1 = WitnessValue::from_u64(42);
		let val2 = val1;
		assert_eq!(val1, val2);
		assert_eq!(val1.inner(), val2.inner());
	}

	#[test]
	fn test_witness_value_copy() {
		let val1 = WitnessValue::from_u64(42);
		let val2 = val1; // Copy, not move
		assert_eq!(val1, val2);
	}

	#[test]
	fn test_witness_value_equality() {
		let val1 = WitnessValue::from_u64(100);
		let val2 = WitnessValue::from_u64(100);
		assert_eq!(val1, val2);
	}

	#[test]
	fn test_witness_value_inequality() {
		let val1 = WitnessValue::from_u64(100);
		let val2 = WitnessValue::from_u64(200);
		assert_ne!(val1, val2);
	}

	#[test]
	fn test_witness_value_debug() {
		let val = WitnessValue::from_u64(42);
		let debug_str = format!("{val:?}");
		assert!(debug_str.contains("WitnessValue"));
	}

	// ===== PublicInput Tests =====

	#[test]
	fn test_public_input() {
		let val = PublicInput::from_u64(100);
		assert_eq!(val.inner(), Bn254Fr::from(100u64));
	}

	#[test]
	fn test_public_input_from_u64() {
		let val = PublicInput::from_u64(200);
		assert_eq!(val.inner(), Bn254Fr::from(200u64));
		assert_eq!(val.0, Bn254Fr::from(200u64));
	}

	#[test]
	fn test_public_input_from_u64_zero() {
		let val = PublicInput::from_u64(0);
		assert_eq!(val.inner(), Bn254Fr::from(0u64));
	}

	#[test]
	fn test_public_input_from_u64_max() {
		let val = PublicInput::from_u64(u64::MAX);
		assert_eq!(val.inner(), Bn254Fr::from(u64::MAX));
	}

	#[test]
	fn test_public_input_inner() {
		let fr = Bn254Fr::from(777u64);
		let val = PublicInput(fr);
		assert_eq!(val.inner(), fr);
	}

	#[test]
	fn test_public_input_from_bn254fr() {
		let fr = Bn254Fr::from(321u64);
		let val: PublicInput = fr.into();
		assert_eq!(val.inner(), fr);
	}

	#[test]
	fn test_public_input_from_u64_trait() {
		let val: PublicInput = 654u64.into();
		assert_eq!(val.inner(), Bn254Fr::from(654u64));
	}

	#[test]
	fn test_public_input_clone() {
		let val1 = PublicInput::from_u64(42);
		let val2 = val1;
		assert_eq!(val1, val2);
		assert_eq!(val1.inner(), val2.inner());
	}

	#[test]
	fn test_public_input_copy() {
		let val1 = PublicInput::from_u64(42);
		let val2 = val1; // Copy, not move
		assert_eq!(val1, val2);
	}

	#[test]
	fn test_public_input_equality() {
		let val1 = PublicInput::from_u64(300);
		let val2 = PublicInput::from_u64(300);
		assert_eq!(val1, val2);
	}

	#[test]
	fn test_public_input_inequality() {
		let val1 = PublicInput::from_u64(300);
		let val2 = PublicInput::from_u64(400);
		assert_ne!(val1, val2);
	}

	#[test]
	fn test_public_input_debug() {
		let val = PublicInput::from_u64(42);
		let debug_str = format!("{val:?}");
		assert!(debug_str.contains("PublicInput"));
	}

	// ===== TreeDepth Tests =====

	#[test]
	fn test_tree_depth_validation() {
		assert!(TreeDepth::new(0).is_err());
		assert!(TreeDepth::new(20).is_ok());
		assert!(TreeDepth::new(33).is_err());
	}

	#[test]
	fn test_tree_depth_default() {
		assert_eq!(TreeDepth::default().value(), 20);
	}

	#[test]
	fn test_tree_depth_new_valid() {
		let depth = TreeDepth::new(15).unwrap();
		assert_eq!(depth.value(), 15);
		assert_eq!(depth.0, 15);
	}

	#[test]
	fn test_tree_depth_new_zero_error() {
		let result = TreeDepth::new(0);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Tree depth must be positive");
	}

	#[test]
	fn test_tree_depth_new_exceeds_max_error() {
		let result = TreeDepth::new(33);
		assert!(result.is_err());
		assert_eq!(result.unwrap_err(), "Tree depth exceeds maximum");
	}

	#[test]
	fn test_tree_depth_new_max_boundary() {
		let result = TreeDepth::new(32);
		assert!(result.is_ok());
		assert_eq!(result.unwrap().value(), 32);
	}

	#[test]
	fn test_tree_depth_new_min_boundary() {
		let result = TreeDepth::new(1);
		assert!(result.is_ok());
		assert_eq!(result.unwrap().value(), 1);
	}

	#[test]
	fn test_tree_depth_standard_constant() {
		assert_eq!(TreeDepth::STANDARD.value(), 20);
	}

	#[test]
	fn test_tree_depth_max_constant() {
		assert_eq!(TreeDepth::MAX.value(), 32);
	}

	#[test]
	fn test_tree_depth_value() {
		let depth = TreeDepth::new(25).unwrap();
		assert_eq!(depth.value(), 25);
	}

	#[test]
	fn test_tree_depth_clone() {
		let depth1 = TreeDepth::new(20).unwrap();
		let depth2 = depth1;
		assert_eq!(depth1, depth2);
		assert_eq!(depth1.value(), depth2.value());
	}

	#[test]
	fn test_tree_depth_copy() {
		let depth1 = TreeDepth::new(20).unwrap();
		let depth2 = depth1; // Copy, not move
		assert_eq!(depth1, depth2);
	}

	#[test]
	fn test_tree_depth_equality() {
		let depth1 = TreeDepth::new(20).unwrap();
		let depth2 = TreeDepth::new(20).unwrap();
		assert_eq!(depth1, depth2);
	}

	#[test]
	fn test_tree_depth_inequality() {
		let depth1 = TreeDepth::new(20).unwrap();
		let depth2 = TreeDepth::new(25).unwrap();
		assert_ne!(depth1, depth2);
	}

	#[test]
	fn test_tree_depth_debug() {
		let depth = TreeDepth::new(20).unwrap();
		let debug_str = format!("{depth:?}");
		assert!(debug_str.contains("TreeDepth"));
	}

	#[test]
	fn test_tree_depth_default_equals_standard() {
		let default = TreeDepth::default();
		let standard = TreeDepth::STANDARD;
		assert_eq!(default, standard);
	}

	// ===== Cross-Type Tests =====

	#[test]
	fn test_witness_and_public_input_independence() {
		let witness = WitnessValue::from_u64(100);
		let public = PublicInput::from_u64(100);

		// Both wrap the same value but are different types
		assert_eq!(witness.inner(), public.inner());
	}

	#[test]
	fn test_all_value_objects_from_same_u64() {
		let val = 42u64;
		let witness = WitnessValue::from_u64(val);
		let public = PublicInput::from_u64(val);

		assert_eq!(witness.inner(), Bn254Fr::from(val));
		assert_eq!(public.inner(), Bn254Fr::from(val));
		assert_eq!(witness.inner(), public.inner());
	}

	#[test]
	fn test_tree_depth_with_value_objects() {
		let depth = TreeDepth::new(20).unwrap();
		let witness = WitnessValue::from_u64(depth.value() as u64);

		assert_eq!(witness.inner(), Bn254Fr::from(20u64));
	}
}
