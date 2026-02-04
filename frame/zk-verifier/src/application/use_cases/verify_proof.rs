//! Verify proof use case

use crate::{
	application::{commands::VerifyProofCommand, errors::ApplicationError},
	domain::{
		entities::Proof,
		repositories::{StatisticsRepository, VerificationKeyRepository},
		services::ProofValidator,
		value_objects::PublicInputs,
	},
};
use alloc::boxed::Box;

/// Use case for verifying a zero-knowledge proof
pub struct VerifyProofUseCase<R, S> {
	vk_repository: R,
	statistics: S,
	validator: Box<dyn ProofValidator>,
}

impl<R: VerificationKeyRepository, S: StatisticsRepository> VerifyProofUseCase<R, S> {
	/// Create a new use case instance
	pub fn new(vk_repository: R, statistics: S, validator: Box<dyn ProofValidator>) -> Self {
		Self {
			vk_repository,
			statistics,
			validator,
		}
	}

	/// Execute the use case
	pub fn execute(&self, command: VerifyProofCommand) -> Result<bool, ApplicationError> {
		// 1. Determine version to use
		let version = match command.version {
			Some(v) => v,
			None => self
				.vk_repository
				.get_active_version(command.circuit_id)
				.map_err(|_| ApplicationError::CircuitNotFound)?,
		};

		// 2. Get verification key from repository for specific version
		let vk = self
			.vk_repository
			.find(command.circuit_id, version)
			.map_err(|_| ApplicationError::RepositoryError)?
			.ok_or(ApplicationError::CircuitNotFound)?;

		// 3. Create proof entity
		let proof = Proof::new(command.proof).map_err(ApplicationError::Domain)?;

		// 4. Create public inputs
		let public_inputs = if command.public_inputs.is_empty() {
			PublicInputs::empty()
		} else {
			PublicInputs::new(command.public_inputs).map_err(ApplicationError::Domain)?
		};

		// 5. Verify proof using domain service
		let result = self
			.validator
			.verify(&vk, &proof, &public_inputs)
			.map_err(ApplicationError::Domain)?;

		// 6. Update statistics for this specific version
		let _ = self
			.statistics
			.increment_verifications(command.circuit_id, version);
		if result {
			let _ = self
				.statistics
				.increment_successes(command.circuit_id, version);
		} else {
			let _ = self
				.statistics
				.increment_failures(command.circuit_id, version);
		}

		Ok(result)
	}
}
