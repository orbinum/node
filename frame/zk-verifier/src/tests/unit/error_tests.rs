//! Unit tests for domain and application errors

#[cfg(test)]
mod domain_error_tests {
	use crate::domain::errors::DomainError;

	#[test]
	fn domain_error_display_messages_are_stable() {
		assert_eq!(
			DomainError::EmptyVerificationKey.to_string(),
			"Verification key cannot be empty"
		);
		assert_eq!(DomainError::InvalidProof.to_string(), "Invalid proof");
		assert_eq!(
			DomainError::UnsupportedProofSystem.to_string(),
			"Proof system is not supported"
		);
	}
}

#[cfg(test)]
mod application_error_tests {
	use crate::{application::errors::ApplicationError, domain::errors::DomainError};

	#[test]
	fn converts_from_domain_error() {
		let app_error = ApplicationError::from(DomainError::InvalidPublicInputs);
		assert_eq!(
			app_error,
			ApplicationError::Domain(DomainError::InvalidPublicInputs)
		);
	}

	#[test]
	fn application_error_display_messages_are_stable() {
		assert_eq!(
			ApplicationError::CircuitNotFound.to_string(),
			"Circuit not found"
		);
		assert_eq!(
			ApplicationError::RepositoryError.to_string(),
			"Repository operation failed"
		);
		assert_eq!(
			ApplicationError::Domain(DomainError::InvalidProof).to_string(),
			"Domain error: Invalid proof"
		);
	}
}
