//! Remove verification key use case

use crate::{
	application::{commands::RemoveVkCommand, errors::ApplicationError},
	domain::repositories::VerificationKeyRepository,
};

/// Use case for removing a verification key
pub struct RemoveVerificationKeyUseCase<R> {
	repository: R,
}

impl<R: VerificationKeyRepository> RemoveVerificationKeyUseCase<R> {
	/// Create a new use case instance
	pub fn new(repository: R) -> Self {
		Self { repository }
	}

	/// Execute the use case
	pub fn execute(&self, command: RemoveVkCommand) -> Result<(), ApplicationError> {
		// 1. Get version to remove
		let version = match command.version {
			Some(v) => v,
			None => self
				.repository
				.get_active_version(command.circuit_id)
				.map_err(|_| ApplicationError::CircuitNotFound)?,
		};

		// 2. Check if this specific version exists
		if !self.repository.exists(command.circuit_id, version) {
			return Err(ApplicationError::CircuitNotFound);
		}

		// 3. Delete from repository
		self.repository
			.delete(command.circuit_id, version)
			.map_err(|_| ApplicationError::RepositoryError)?;

		Ok(())
	}
}
