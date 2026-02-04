//! Circuit Validator Service
//!
//! Domain service for validating circuit constraints and witness data.

use crate::domain::value_objects::TreeDepth;

/// Circuit validation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
	/// Merkle path length mismatch
	InvalidPathLength { expected: usize, got: usize },
	/// Asset mismatch in transfer
	AssetMismatch { input: u64, output: u64 },
	/// Value conservation violation
	ValueImbalance { inputs: u64, outputs: u64 },
	/// Invalid nullifier (already spent)
	DuplicateNullifier,
}

/// Domain service for circuit validation
pub struct CircuitValidator;

impl CircuitValidator {
	/// Validate merkle path length matches tree depth
	pub fn validate_path_length(
		path_length: usize,
		tree_depth: TreeDepth,
	) -> Result<(), ValidationError> {
		if path_length != tree_depth.value() {
			return Err(ValidationError::InvalidPathLength {
				expected: tree_depth.value(),
				got: path_length,
			});
		}
		Ok(())
	}

	/// Validate asset consistency in transfer
	pub fn validate_asset_consistency(
		input_asset: u64,
		output_asset: u64,
	) -> Result<(), ValidationError> {
		if input_asset != output_asset {
			return Err(ValidationError::AssetMismatch {
				input: input_asset,
				output: output_asset,
			});
		}
		Ok(())
	}

	/// Validate value conservation (inputs == outputs)
	pub fn validate_value_balance(
		input_values: &[u64],
		output_values: &[u64],
	) -> Result<(), ValidationError> {
		let total_in: u64 = input_values.iter().sum();
		let total_out: u64 = output_values.iter().sum();

		if total_in != total_out {
			return Err(ValidationError::ValueImbalance {
				inputs: total_in,
				outputs: total_out,
			});
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	extern crate alloc;
	use alloc::format;

	// ===== ValidationError Tests =====

	#[test]
	fn test_validation_error_invalid_path_length() {
		let error = ValidationError::InvalidPathLength {
			expected: 20,
			got: 10,
		};

		match error {
			ValidationError::InvalidPathLength { expected, got } => {
				assert_eq!(expected, 20);
				assert_eq!(got, 10);
			}
			_ => panic!("Wrong error variant"),
		}
	}

	#[test]
	fn test_validation_error_asset_mismatch() {
		let error = ValidationError::AssetMismatch {
			input: 1,
			output: 2,
		};

		match error {
			ValidationError::AssetMismatch { input, output } => {
				assert_eq!(input, 1);
				assert_eq!(output, 2);
			}
			_ => panic!("Wrong error variant"),
		}
	}

	#[test]
	fn test_validation_error_value_imbalance() {
		let error = ValidationError::ValueImbalance {
			inputs: 100,
			outputs: 50,
		};

		match error {
			ValidationError::ValueImbalance { inputs, outputs } => {
				assert_eq!(inputs, 100);
				assert_eq!(outputs, 50);
			}
			_ => panic!("Wrong error variant"),
		}
	}

	#[test]
	fn test_validation_error_duplicate_nullifier() {
		let error = ValidationError::DuplicateNullifier;

		match error {
			ValidationError::DuplicateNullifier => {}
			_ => panic!("Wrong error variant"),
		}
	}

	#[test]
	fn test_validation_error_clone() {
		let error1 = ValidationError::AssetMismatch {
			input: 1,
			output: 2,
		};
		let error2 = error1.clone();

		assert_eq!(error1, error2);
	}

	#[test]
	fn test_validation_error_debug() {
		let error = ValidationError::InvalidPathLength {
			expected: 20,
			got: 10,
		};
		let debug_str = format!("{error:?}");

		assert!(debug_str.contains("InvalidPathLength"));
		assert!(debug_str.contains("20"));
		assert!(debug_str.contains("10"));
	}

	#[test]
	fn test_validation_error_equality() {
		let error1 = ValidationError::ValueImbalance {
			inputs: 100,
			outputs: 50,
		};
		let error2 = ValidationError::ValueImbalance {
			inputs: 100,
			outputs: 50,
		};

		assert_eq!(error1, error2);
	}

	#[test]
	fn test_validation_error_inequality() {
		let error1 = ValidationError::ValueImbalance {
			inputs: 100,
			outputs: 50,
		};
		let error2 = ValidationError::ValueImbalance {
			inputs: 200,
			outputs: 100,
		};

		assert_ne!(error1, error2);
	}

	// ===== validate_path_length Tests =====

	#[test]
	fn test_validate_path_length() {
		let depth = TreeDepth::STANDARD;
		assert!(CircuitValidator::validate_path_length(20, depth).is_ok());
		assert!(CircuitValidator::validate_path_length(10, depth).is_err());
	}

	#[test]
	fn test_validate_path_length_standard() {
		let depth = TreeDepth::STANDARD;
		let result = CircuitValidator::validate_path_length(20, depth);

		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_path_length_mismatch() {
		let depth = TreeDepth::STANDARD;
		let result = CircuitValidator::validate_path_length(15, depth);

		assert!(result.is_err());
		match result.unwrap_err() {
			ValidationError::InvalidPathLength { expected, got } => {
				assert_eq!(expected, 20);
				assert_eq!(got, 15);
			}
			_ => panic!("Wrong error type"),
		}
	}

	#[test]
	fn test_validate_path_length_zero() {
		let depth = TreeDepth::STANDARD;
		let result = CircuitValidator::validate_path_length(0, depth);

		assert!(result.is_err());
	}

	#[test]
	fn test_validate_path_length_too_large() {
		let depth = TreeDepth::STANDARD;
		let result = CircuitValidator::validate_path_length(100, depth);

		assert!(result.is_err());
	}

	#[test]
	fn test_validate_path_length_shallow() {
		let depth = TreeDepth::new(10).unwrap();
		let result = CircuitValidator::validate_path_length(10, depth);

		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_path_length_deep() {
		let depth = TreeDepth::MAX;
		let result = CircuitValidator::validate_path_length(32, depth);

		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_path_length_custom() {
		let depth = TreeDepth::new(25).unwrap();
		let result = CircuitValidator::validate_path_length(25, depth);

		assert!(result.is_ok());
	}

	// ===== validate_asset_consistency Tests =====

	#[test]
	fn test_validate_asset_consistency() {
		assert!(CircuitValidator::validate_asset_consistency(1, 1).is_ok());
		assert!(CircuitValidator::validate_asset_consistency(1, 2).is_err());
	}

	#[test]
	fn test_validate_asset_consistency_same_asset() {
		let result = CircuitValidator::validate_asset_consistency(1, 1);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_asset_consistency_mismatch() {
		let result = CircuitValidator::validate_asset_consistency(1, 2);

		assert!(result.is_err());
		match result.unwrap_err() {
			ValidationError::AssetMismatch { input, output } => {
				assert_eq!(input, 1);
				assert_eq!(output, 2);
			}
			_ => panic!("Wrong error type"),
		}
	}

	#[test]
	fn test_validate_asset_consistency_zero_assets() {
		let result = CircuitValidator::validate_asset_consistency(0, 0);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_asset_consistency_large_values() {
		let result = CircuitValidator::validate_asset_consistency(u64::MAX, u64::MAX);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_asset_consistency_different_large_values() {
		let result = CircuitValidator::validate_asset_consistency(u64::MAX, u64::MAX - 1);
		assert!(result.is_err());
	}

	#[test]
	fn test_validate_asset_consistency_multiple_calls() {
		let result1 = CircuitValidator::validate_asset_consistency(5, 5);
		let result2 = CircuitValidator::validate_asset_consistency(5, 5);

		assert!(result1.is_ok());
		assert!(result2.is_ok());
	}

	// ===== validate_value_balance Tests =====

	#[test]
	fn test_validate_value_balance() {
		assert!(CircuitValidator::validate_value_balance(&[100, 50], &[150]).is_ok());
		assert!(CircuitValidator::validate_value_balance(&[100], &[50]).is_err());
	}

	#[test]
	fn test_validate_value_balance_equal() {
		let result = CircuitValidator::validate_value_balance(&[100, 50], &[150]);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_value_balance_single_values() {
		let result = CircuitValidator::validate_value_balance(&[100], &[100]);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_value_balance_imbalance() {
		let result = CircuitValidator::validate_value_balance(&[100], &[50]);

		assert!(result.is_err());
		match result.unwrap_err() {
			ValidationError::ValueImbalance { inputs, outputs } => {
				assert_eq!(inputs, 100);
				assert_eq!(outputs, 50);
			}
			_ => panic!("Wrong error type"),
		}
	}

	#[test]
	fn test_validate_value_balance_empty_inputs() {
		let result = CircuitValidator::validate_value_balance(&[], &[]);
		assert!(result.is_ok()); // 0 == 0
	}

	#[test]
	fn test_validate_value_balance_empty_inputs_nonzero_outputs() {
		let result = CircuitValidator::validate_value_balance(&[], &[100]);
		assert!(result.is_err());
	}

	#[test]
	fn test_validate_value_balance_nonzero_inputs_empty_outputs() {
		let result = CircuitValidator::validate_value_balance(&[100], &[]);
		assert!(result.is_err());
	}

	#[test]
	fn test_validate_value_balance_multiple_inputs_single_output() {
		let result = CircuitValidator::validate_value_balance(&[30, 40, 30], &[100]);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_value_balance_single_input_multiple_outputs() {
		let result = CircuitValidator::validate_value_balance(&[100], &[30, 40, 30]);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_value_balance_multiple_both() {
		let result = CircuitValidator::validate_value_balance(&[50, 50, 50], &[100, 50]);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_value_balance_zero_values() {
		let result = CircuitValidator::validate_value_balance(&[0, 0], &[0]);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_value_balance_large_values() {
		let result = CircuitValidator::validate_value_balance(
			&[u64::MAX / 2, u64::MAX / 2],
			&[u64::MAX - 1],
		);
		assert!(result.is_ok());
	}

	#[test]
	fn test_validate_value_balance_inputs_greater() {
		let result = CircuitValidator::validate_value_balance(&[100, 100], &[50]);

		assert!(result.is_err());
		match result.unwrap_err() {
			ValidationError::ValueImbalance { inputs, outputs } => {
				assert_eq!(inputs, 200);
				assert_eq!(outputs, 50);
			}
			_ => panic!("Wrong error type"),
		}
	}

	#[test]
	fn test_validate_value_balance_outputs_greater() {
		let result = CircuitValidator::validate_value_balance(&[50], &[100, 100]);

		assert!(result.is_err());
		match result.unwrap_err() {
			ValidationError::ValueImbalance { inputs, outputs } => {
				assert_eq!(inputs, 50);
				assert_eq!(outputs, 200);
			}
			_ => panic!("Wrong error type"),
		}
	}

	// ===== Integration Tests =====

	#[test]
	fn test_multiple_validations_all_pass() {
		let path_result = CircuitValidator::validate_path_length(20, TreeDepth::STANDARD);
		let asset_result = CircuitValidator::validate_asset_consistency(1, 1);
		let value_result = CircuitValidator::validate_value_balance(&[100], &[100]);

		assert!(path_result.is_ok());
		assert!(asset_result.is_ok());
		assert!(value_result.is_ok());
	}

	#[test]
	fn test_multiple_validations_one_fails() {
		let path_result = CircuitValidator::validate_path_length(20, TreeDepth::STANDARD);
		let asset_result = CircuitValidator::validate_asset_consistency(1, 2);
		let value_result = CircuitValidator::validate_value_balance(&[100], &[100]);

		assert!(path_result.is_ok());
		assert!(asset_result.is_err());
		assert!(value_result.is_ok());
	}

	#[test]
	fn test_validation_error_messages_unique() {
		let error1 = ValidationError::InvalidPathLength {
			expected: 20,
			got: 10,
		};
		let error2 = ValidationError::AssetMismatch {
			input: 1,
			output: 2,
		};
		let error3 = ValidationError::ValueImbalance {
			inputs: 100,
			outputs: 50,
		};
		let error4 = ValidationError::DuplicateNullifier;

		let debug1 = format!("{error1:?}");
		let debug2 = format!("{error2:?}");
		let debug3 = format!("{error3:?}");
		let debug4 = format!("{error4:?}");

		assert!(debug1.contains("InvalidPathLength"));
		assert!(debug2.contains("AssetMismatch"));
		assert!(debug3.contains("ValueImbalance"));
		assert!(debug4.contains("DuplicateNullifier"));
	}
}
