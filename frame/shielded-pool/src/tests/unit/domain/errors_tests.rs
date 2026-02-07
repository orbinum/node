//! Tests for errors

use crate::domain::DomainError;

#[test]
fn domain_error_display_works() {
	let error = DomainError::InvalidCommitment;
	assert_eq!(format!("{error}"), "Invalid commitment");
}

#[test]
fn domain_error_as_str_works() {
	let error = DomainError::NullifierAlreadyUsed;
	assert_eq!(error.as_str(), "Nullifier already used");
}

#[test]
fn validation_error_with_message_works() {
	let error = DomainError::ValidationError("Custom validation failed");
	assert_eq!(error.as_str(), "Custom validation failed");
}
