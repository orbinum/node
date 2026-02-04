//! Set active version use case

use crate::{
	application::{commands::SetActiveVersionCommand, errors::ApplicationError},
	domain::repositories::VerificationKeyRepository,
};

/// Use case for setting the active version of a circuit
pub struct SetActiveVersionUseCase<R> {
	repository: R,
}

impl<R: VerificationKeyRepository> SetActiveVersionUseCase<R> {
	/// Create a new use case instance
	pub fn new(repository: R) -> Self {
		Self { repository }
	}

	/// Execute the use case
	pub fn execute(&self, command: SetActiveVersionCommand) -> Result<(), ApplicationError> {
		// 1. Check if the version exists
		if !self.repository.exists(command.circuit_id, command.version) {
			return Err(ApplicationError::CircuitNotFound);
		}

		// 2. Persist to repository
		self.repository
			.set_active_version(command.circuit_id, command.version)
			.map_err(|_| ApplicationError::RepositoryError)?;

		Ok(())
	}
}
