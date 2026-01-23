//! Integration tests for core errors

use fp_zk_primitives::core::error::PrimitiveError;

#[test]
fn test_primitive_error_variants() {
	let errors = vec![
		PrimitiveError::InvalidFieldElement,
		PrimitiveError::MerkleProofVerificationFailed,
		PrimitiveError::InvalidNoteData,
		PrimitiveError::PoseidonHashFailed,
		PrimitiveError::InvalidPathLength,
		PrimitiveError::TreeDepthExceeded,
	];

	// All variants should be unique
	for (i, error1) in errors.iter().enumerate() {
		for (j, error2) in errors.iter().enumerate() {
			if i == j {
				assert_eq!(error1, error2);
			} else {
				assert_ne!(error1, error2);
			}
		}
	}
}

#[test]
fn test_invalid_field_element_error() {
	let error = PrimitiveError::InvalidFieldElement;
	assert_eq!(error.as_str(), "Invalid field element");
}

#[test]
fn test_merkle_proof_verification_failed_error() {
	let error = PrimitiveError::MerkleProofVerificationFailed;
	assert_eq!(error.as_str(), "Merkle proof verification failed");
}

#[test]
fn test_invalid_note_data_error() {
	let error = PrimitiveError::InvalidNoteData;
	assert_eq!(error.as_str(), "Invalid note data");
}

#[test]
fn test_poseidon_hash_failed_error() {
	let error = PrimitiveError::PoseidonHashFailed;
	assert_eq!(error.as_str(), "Poseidon hash failed");
}

#[test]
fn test_invalid_path_length_error() {
	let error = PrimitiveError::InvalidPathLength;
	assert_eq!(error.as_str(), "Invalid path length");
}

#[test]
fn test_tree_depth_exceeded_error() {
	let error = PrimitiveError::TreeDepthExceeded;
	assert_eq!(error.as_str(), "Tree depth exceeded maximum");
}

#[test]
fn test_error_clone() {
	let error1 = PrimitiveError::InvalidFieldElement;
	let error2 = error1.clone();
	assert_eq!(error1, error2);
}

#[test]
fn test_error_debug() {
	let error = PrimitiveError::InvalidFieldElement;
	let debug_str = format!("{:?}", error);
	assert!(debug_str.contains("InvalidFieldElement"));
}

#[cfg(feature = "std")]
#[test]
fn test_error_display() {
	let error = PrimitiveError::InvalidFieldElement;
	let display_str = format!("{}", error);
	assert_eq!(display_str, "Invalid field element");
}

#[cfg(feature = "std")]
#[test]
fn test_error_display_all_variants() {
	let errors = vec![
		(PrimitiveError::InvalidFieldElement, "Invalid field element"),
		(
			PrimitiveError::MerkleProofVerificationFailed,
			"Merkle proof verification failed",
		),
		(PrimitiveError::InvalidNoteData, "Invalid note data"),
		(PrimitiveError::PoseidonHashFailed, "Poseidon hash failed"),
		(PrimitiveError::InvalidPathLength, "Invalid path length"),
		(
			PrimitiveError::TreeDepthExceeded,
			"Tree depth exceeded maximum",
		),
	];

	for (error, expected) in errors {
		assert_eq!(format!("{}", error), expected);
		assert_eq!(error.as_str(), expected);
	}
}

#[cfg(feature = "std")]
#[test]
fn test_error_trait() {
	use std::error::Error;

	let error: &dyn Error = &PrimitiveError::InvalidFieldElement;
	let display_str = format!("{}", error);
	assert_eq!(display_str, "Invalid field element");
}

#[test]
fn test_error_equality() {
	let error1 = PrimitiveError::InvalidFieldElement;
	let error2 = PrimitiveError::InvalidFieldElement;
	let error3 = PrimitiveError::MerkleProofVerificationFailed;

	assert_eq!(error1, error2);
	assert_ne!(error1, error3);
}

#[test]
fn test_error_as_str_not_empty() {
	let errors = vec![
		PrimitiveError::InvalidFieldElement,
		PrimitiveError::MerkleProofVerificationFailed,
		PrimitiveError::InvalidNoteData,
		PrimitiveError::PoseidonHashFailed,
		PrimitiveError::InvalidPathLength,
		PrimitiveError::TreeDepthExceeded,
	];

	for error in errors {
		assert!(
			!error.as_str().is_empty(),
			"Error message should not be empty"
		);
		assert!(
			error.as_str().len() > 5,
			"Error message should be descriptive"
		);
	}
}
