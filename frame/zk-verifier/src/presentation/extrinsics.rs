//! Extrinsics - Pallet calls using Clean Architecture
//!
//! These functions are called from the pallet::call implementations in lib.rs.
//! They convert FRAME types to domain types, execute use cases, and handle results.

use crate::{
	application::{commands::VerifyProofCommand, use_cases::VerifyProofUseCase},
	domain::{
		repositories::VerificationKeyRepository, value_objects::CircuitId as DomainCircuitId,
	},
	infrastructure::{
		repositories::{FrameStatisticsRepository, FrameVkRepository},
		services::Groth16Verifier,
	},
	pallet::{self as pallet, Config, Error, Event, Pallet},
	types::CircuitId,
};
use alloc::boxed::Box;
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use sp_std::vec::Vec;

impl<T: Config> Pallet<T> {
	/// Verify a zero-knowledge proof
	pub fn execute_verify_proof(
		origin: OriginFor<T>,
		circuit_id_raw: u32,
		version: Option<u32>,
		proof: BoundedVec<u8, <T as pallet::Config>::MaxProofSize>,
		public_inputs: BoundedVec<
			BoundedVec<u8, ConstU32<32>>,
			<T as pallet::Config>::MaxPublicInputs,
		>,
	) -> DispatchResult {
		ensure_signed(origin)?;

		// Convert to domain type
		let circuit_id = DomainCircuitId::new(circuit_id_raw);

		// Convert public inputs
		let inputs: Vec<Vec<u8>> = public_inputs.into_iter().map(|i| i.to_vec()).collect();

		// Create command
		let command = VerifyProofCommand {
			circuit_id,
			version,
			proof: proof.to_vec(),
			public_inputs: inputs,
		};

		// Create dependencies
		let vk_repository = FrameVkRepository::<T>::new();
		let statistics = FrameStatisticsRepository::<T>::new();
		let validator = Box::new(Groth16Verifier);

		// Execute use case
		let use_case = VerifyProofUseCase::new(vk_repository, statistics, validator);
		let result = use_case
			.execute(command)
			.map_err(Self::map_application_error)?;

		// Get the actual version used for the event
		let actual_version = version.unwrap_or_else(|| {
			FrameVkRepository::<T>::new()
				.get_active_version(circuit_id)
				.unwrap_or_default()
		});

		// Emit event
		if result {
			Self::deposit_event(Event::ProofVerified {
				circuit_id: CircuitId(circuit_id_raw),
				version: actual_version,
			});
		} else {
			Self::deposit_event(Event::ProofVerificationFailed {
				circuit_id: CircuitId(circuit_id_raw),
				version: actual_version,
			});
			return Err(Error::<T>::VerificationFailed.into());
		}

		Ok(())
	}

	// Helper functions

	pub(crate) fn map_application_error(
		err: crate::application::errors::ApplicationError,
	) -> Error<T> {
		use crate::application::errors::ApplicationError;

		match err {
			ApplicationError::Domain(d) => Self::map_domain_error(d),
			ApplicationError::CircuitNotFound => Error::<T>::CircuitNotFound,
			ApplicationError::CircuitAlreadyExists => Error::<T>::CircuitAlreadyExists,
			ApplicationError::RepositoryError => Error::<T>::RepositoryError,
			ApplicationError::ValidationFailed => Error::<T>::InvalidVerificationKey,
			ApplicationError::CryptoError => Error::<T>::VerificationFailed,
		}
	}

	fn map_domain_error(err: crate::domain::errors::DomainError) -> Error<T> {
		use crate::domain::errors::DomainError;

		match err {
			DomainError::EmptyVerificationKey => Error::<T>::EmptyVerificationKey,
			DomainError::VerificationKeyTooLarge => Error::<T>::VerificationKeyTooLarge,
			DomainError::InvalidVerificationKeySize => Error::<T>::InvalidVerificationKey,
			DomainError::InvalidVerificationKeyFormat => Error::<T>::InvalidVerificationKey,
			DomainError::InvalidVerificationKey => Error::<T>::InvalidVerificationKey,
			DomainError::EmptyProof => Error::<T>::EmptyProof,
			DomainError::ProofTooLarge => Error::<T>::ProofTooLarge,
			DomainError::InvalidProofFormat => Error::<T>::InvalidProof,
			DomainError::InvalidProof => Error::<T>::InvalidProof,
			DomainError::EmptyPublicInputs => Error::<T>::EmptyPublicInputs,
			DomainError::TooManyPublicInputs => Error::<T>::TooManyPublicInputs,
			DomainError::InvalidPublicInputFormat => Error::<T>::InvalidPublicInputs,
			DomainError::InvalidPublicInputs => Error::<T>::InvalidPublicInputs,
			DomainError::VerificationFailed => Error::<T>::VerificationFailed,
			DomainError::UnsupportedProofSystem => Error::<T>::UnsupportedProofSystem,
			DomainError::CircuitNotFound => Error::<T>::CircuitNotFound,
			DomainError::CircuitAlreadyExists => Error::<T>::CircuitAlreadyExists,
		}
	}
}
