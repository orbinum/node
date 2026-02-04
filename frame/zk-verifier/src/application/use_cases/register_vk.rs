//! Register verification key use case

use crate::{
	application::{commands::RegisterVkCommand, errors::ApplicationError},
	domain::{
		entities::VerificationKey, repositories::VerificationKeyRepository, services::VkValidator,
	},
};
use alloc::boxed::Box;

/// Use case for registering a verification key
pub struct RegisterVerificationKeyUseCase<R> {
	repository: R,
	validator: Box<dyn VkValidator>,
}

impl<R: VerificationKeyRepository> RegisterVerificationKeyUseCase<R> {
	/// Create a new use case instance
	pub fn new(repository: R, validator: Box<dyn VkValidator>) -> Self {
		Self {
			repository,
			validator,
		}
	}

	/// Execute the use case
	pub fn execute(&self, command: RegisterVkCommand) -> Result<(), ApplicationError> {
		// 1. Check if this specific version already exists
		if self.repository.exists(command.circuit_id, command.version) {
			return Err(ApplicationError::CircuitAlreadyExists);
		}

		// 2. Create domain entity with validation
		let vk =
			VerificationKey::new(command.data, command.system).map_err(ApplicationError::Domain)?;

		// 3. Validate with domain service
		self.validator
			.validate(&vk)
			.map_err(ApplicationError::Domain)?;

		// 4. Persist to repository
		self.repository
			.save(command.circuit_id, command.version, vk)
			.map_err(|_| ApplicationError::RepositoryError)?;

		// 5. If this is the first version, set it as active
		// We ignore error here as it might fail if we can't find it immediately (unlikely)
		if self
			.repository
			.get_active_version(command.circuit_id)
			.is_err()
		{
			let _ = self
				.repository
				.set_active_version(command.circuit_id, command.version);
		}

		Ok(())
	}
}
