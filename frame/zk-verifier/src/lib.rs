//! # ZK Verifier Pallet
//!
//! A pallet for verifying Zero-Knowledge proofs on-chain using Clean Architecture.
//!
//! ## Architecture
//!
//! This pallet follows Clean Architecture + DDD principles:
//!
//! - **Domain Layer**: Pure business logic (entities, value objects, services)
//! - **Application Layer**: Use cases orchestrating domain logic
//! - **Infrastructure Layer**: FRAME integration (storage, repositories)
//! - **Presentation Layer**: Extrinsics and event emission
//!
//! ## Features
//!
//! - Groth16 proof verification with sub-10ms performance
//! - Circuit-specific verification key management
//! - Statistics tracking per circuit
//! - Support for multiple proof systems (Groth16, PLONK, Halo2)
//!
//! ## Usage
//!
//! ```ignore
//! // Register a verification key
//! ZkVerifier::register_verification_key(
//!     origin,
//!     circuit_id,
//!     vk_bytes,
//!     ProofSystem::Groth16
//! )?;
//!
//! // Verify a proof
//! ZkVerifier::verify_proof(
//!     origin,
//!     circuit_id,
//!     proof,
//!     public_inputs
//! )?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

// Clean Architecture Layers (módulos internos, NO re-exportar)
pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod presentation;

// Supporting modules (internos)
mod types;
pub mod weights;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

// ============================================================================
// PUBLIC API - Clean Architecture Ports (Contratos para otros pallets)
// ============================================================================

/// Puerto de dominio para verificación ZK (el ÚNICO contrato público)
pub use domain::services::ZkVerifierPort;

// Re-export tipos FRAME necesarios para el pallet runtime
pub use types::{
	CircuitId, CircuitMetadata, ProofSystem, VerificationKeyInfo, VerificationStatistics,
};
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::vec::Vec;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Configuration trait for the pallet
	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Origin that can register verification keys (admin/governance)
		type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Maximum size of a verification key in bytes
		#[pallet::constant]
		type MaxVerificationKeySize: Get<u32>;

		/// Maximum size of a proof in bytes
		#[pallet::constant]
		type MaxProofSize: Get<u32>;

		/// Maximum number of public inputs
		#[pallet::constant]
		type MaxPublicInputs: Get<u32>;

		/// Weight information for extrinsics in this pallet
		type WeightInfo: WeightInfo;
	}

	// ========================================================================
	// Storage
	// ========================================================================

	/// Verification keys indexed by circuit ID and version
	#[pallet::storage]
	#[pallet::getter(fn verification_keys)]
	pub type VerificationKeys<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CircuitId,
		Blake2_128Concat,
		u32, // Version
		VerificationKeyInfo<BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Current active version for each circuit
	#[pallet::storage]
	#[pallet::getter(fn active_circuit_version)]
	pub type ActiveCircuitVersion<T: Config> =
		StorageMap<_, Blake2_128Concat, CircuitId, u32, OptionQuery>;

	/// Circuit metadata
	#[pallet::storage]
	pub type CircuitInfo<T: Config> =
		StorageMap<_, Blake2_128Concat, CircuitId, CircuitMetadata, OptionQuery>;

	/// Verification statistics per circuit and version
	#[pallet::storage]
	pub type VerificationStats<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CircuitId,
		Blake2_128Concat,
		u32, // Version
		VerificationStatistics,
		ValueQuery,
	>;

	// ========================================================================
	// Genesis Config
	// ========================================================================

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		/// Pre-registered verification keys
		pub verification_keys: Vec<(CircuitId, Vec<u8>)>,
		#[serde(skip)]
		pub _phantom: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			for (circuit_id, vk_bytes) in &self.verification_keys {
				let vk_info = VerificationKeyInfo {
					key_data: vk_bytes.clone().try_into().unwrap_or_default(),
					system: ProofSystem::Groth16,
					registered_at: BlockNumberFor::<T>::default(),
				};
				// Map to version 1 by default in genesis
				VerificationKeys::<T>::insert(circuit_id, 1, vk_info);
				ActiveCircuitVersion::<T>::insert(circuit_id, 1);
			}
		}
	}

	// ========================================================================
	// Events
	// ========================================================================

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// Verification key registered
		VerificationKeyRegistered {
			circuit_id: CircuitId,
			version: u32,
			system: ProofSystem,
		},
		/// Verification key updated
		VerificationKeyUpdated { circuit_id: CircuitId, version: u32 },
		/// Verification key removed
		VerificationKeyRemoved { circuit_id: CircuitId, version: u32 },
		/// Active version for a circuit changed
		ActiveVersionChanged { circuit_id: CircuitId, version: u32 },
		/// Proof verified successfully
		ProofVerified { circuit_id: CircuitId, version: u32 },
		/// Proof verification failed
		ProofVerificationFailed { circuit_id: CircuitId, version: u32 },
	}

	// ========================================================================
	// Errors
	// ========================================================================

	#[pallet::error]
	pub enum Error<T> {
		// Domain errors - Verification Key
		EmptyVerificationKey,
		VerificationKeyTooLarge,
		InvalidVerificationKey,
		VerificationKeyNotFound,

		// Domain errors - Proof
		EmptyProof,
		ProofTooLarge,
		InvalidProof,

		// Domain errors - Public Inputs
		EmptyPublicInputs,
		TooManyPublicInputs,
		InvalidPublicInputs,

		// Domain errors - Verification
		VerificationFailed,
		UnsupportedProofSystem,

		// Application errors
		CircuitNotFound,
		CircuitAlreadyExists,

		// Infrastructure errors
		RepositoryError,
		DeserializationError,

		// Batch verification errors
		/// Batch size is invalid (0 or > MAX_BATCH_SIZE)
		InvalidBatchSize,
		/// Batch arrays have mismatched lengths
		BatchLengthMismatch,
		/// Batch verification failed
		BatchVerificationFailed,
	}

	// ========================================================================
	// Extrinsics
	// ========================================================================

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register a verification key for a circuit
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::register_verification_key())]
		pub fn register_verification_key(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
			vk_bytes: Vec<u8>,
			system: ProofSystem,
		) -> DispatchResult {
			Self::execute_register_verification_key(origin, circuit_id.0, version, vk_bytes, system)
		}

		/// Remove a verification key version
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::remove_verification_key())]
		pub fn remove_verification_key(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
		) -> DispatchResult {
			Self::execute_remove_verification_key(origin, circuit_id.0, version)
		}

		/// Set the active version for a circuit
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::register_verification_key())] // Reuse weight for now
		pub fn set_active_version(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
		) -> DispatchResult {
			Self::execute_set_active_version(origin, circuit_id.0, version)
		}

		/// Verify a zero-knowledge proof
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::verify_proof())]
		pub fn verify_proof(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			proof: BoundedVec<u8, T::MaxProofSize>,
			public_inputs: BoundedVec<BoundedVec<u8, ConstU32<32>>, T::MaxPublicInputs>,
		) -> DispatchResult {
			Self::execute_verify_proof(origin, circuit_id.0, None, proof, public_inputs)
		}
	}
}

// ============================================================================
// ZkVerifierPort Trait Implementation (Clean Architecture Port)
// ============================================================================

impl<T: Config> ZkVerifierPort for Pallet<T> {
	/// Verificar una prueba de transferencia privada
	fn verify_transfer_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifiers: &[[u8; 32]],
		commitments: &[[u8; 32]],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		use crate::{
			application::{commands::VerifyProofCommand, use_cases::VerifyProofUseCase},
			domain::value_objects::CircuitId as DomainCircuitId,
			infrastructure::{
				repositories::{FrameStatisticsRepository, FrameVkRepository},
				services::Groth16Verifier,
			},
		};
		use alloc::boxed::Box;
		use alloc::vec::Vec;

		// Construir public inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2]
		let mut public_inputs = Vec::new();
		public_inputs.push(merkle_root.to_vec());
		for nullifier in nullifiers {
			public_inputs.push(nullifier.to_vec());
		}
		for commitment in commitments {
			public_inputs.push(commitment.to_vec());
		}

		// Crear command para el use case
		let command = VerifyProofCommand {
			circuit_id: DomainCircuitId::new(CircuitId::TRANSFER.0),
			version,
			proof: proof.to_vec(),
			public_inputs,
		};

		// Ejecutar use case
		let vk_repository = FrameVkRepository::<T>::new();
		let statistics = FrameStatisticsRepository::<T>::new();
		let validator = Box::new(Groth16Verifier);

		let use_case = VerifyProofUseCase::new(vk_repository, statistics, validator);
		use_case
			.execute(command)
			.map_err(Self::map_application_error_to_dispatch)
	}

	/// Verificar una prueba de unshield (retiro del pool)
	fn verify_unshield_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifier: &[u8; 32],
		amount: u128,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		use crate::{
			application::{commands::VerifyProofCommand, use_cases::VerifyProofUseCase},
			domain::value_objects::CircuitId as DomainCircuitId,
			infrastructure::{
				repositories::{FrameStatisticsRepository, FrameVkRepository},
				services::Groth16Verifier,
			},
		};
		use alloc::boxed::Box;

		// Construir public inputs: [merkle_root, nullifier, amount]
		// amount se codifica como bytes de 32 bytes (u128 -> [u8; 32])
		let mut amount_bytes = [0u8; 32];
		amount_bytes[16..].copy_from_slice(&amount.to_le_bytes());

		use alloc::vec;
		let public_inputs = vec![
			merkle_root.to_vec(),
			nullifier.to_vec(),
			amount_bytes.to_vec(),
		];

		// Crear command para el use case
		let command = VerifyProofCommand {
			circuit_id: DomainCircuitId::new(CircuitId::UNSHIELD.0),
			version,
			proof: proof.to_vec(),
			public_inputs,
		};

		// Ejecutar use case
		let vk_repository = FrameVkRepository::<T>::new();
		let statistics = FrameStatisticsRepository::<T>::new();
		let validator = Box::new(Groth16Verifier);

		let use_case = VerifyProofUseCase::new(vk_repository, statistics, validator);
		use_case
			.execute(command)
			.map_err(Self::map_application_error_to_dispatch)
	}

	/// Verificar una prueba de disclosure (selective disclosure)
	fn verify_disclosure_proof(
		proof: &[u8],
		public_signals: &[u8],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		use crate::{
			application::{commands::VerifyProofCommand, use_cases::VerifyProofUseCase},
			domain::value_objects::CircuitId as DomainCircuitId,
			infrastructure::{
				repositories::{FrameStatisticsRepository, FrameVkRepository},
				services::Groth16Verifier,
			},
		};
		use alloc::boxed::Box;

		// Public signals structure (76 bytes):
		// [commitment(32)][revealed_value(8)][revealed_asset_id(4)][revealed_owner_hash(32)]
		if public_signals.len() != 76 {
			return Err(sp_runtime::DispatchError::Other(
				"Invalid public signals length (expected 76 bytes)",
			));
		}

		// Separar en 4 inputs para el verifier
		use alloc::vec;
		let public_inputs = vec![
			public_signals[0..32].to_vec(),  // commitment
			public_signals[32..40].to_vec(), // revealed_value
			public_signals[40..44].to_vec(), // revealed_asset_id
			public_signals[44..76].to_vec(), // revealed_owner_hash
		];

		// Crear command para el use case con circuit ID "disclosure"
		let command = VerifyProofCommand {
			circuit_id: DomainCircuitId::new(CircuitId::DISCLOSURE.0),
			version,
			proof: proof.to_vec(),
			public_inputs,
		};

		// Ejecutar use case
		let vk_repository = FrameVkRepository::<T>::new();
		let statistics = FrameStatisticsRepository::<T>::new();
		let validator = Box::new(Groth16Verifier);

		let use_case = VerifyProofUseCase::new(vk_repository, statistics, validator);
		use_case
			.execute(command)
			.map_err(Self::map_application_error_to_dispatch)
	}

	/// Verificar múltiples pruebas de disclosure en batch (optimizado)
	fn batch_verify_disclosure_proofs(
		proofs: &[sp_std::vec::Vec<u8>],
		public_signals: &[sp_std::vec::Vec<u8>],
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		use crate::{
			domain::{
				repositories::VerificationKeyRepository,
				value_objects::CircuitId as DomainCircuitId,
			},
			infrastructure::repositories::FrameVkRepository,
		};
		use orbinum_zk_verifier::{
			domain::value_objects::{Proof, PublicInputs, VerifyingKey},
			infrastructure::Groth16Verifier,
		};
		use sp_std::vec::Vec;

		// Maximum batch size to prevent DoS
		const MAX_BATCH_SIZE: usize = 10;

		// 1. Validate batch size
		if proofs.is_empty() || proofs.len() > MAX_BATCH_SIZE {
			return Err(Error::<T>::InvalidBatchSize.into());
		}

		// 2. Validate arrays have same length
		if proofs.len() != public_signals.len() {
			return Err(Error::<T>::BatchLengthMismatch.into());
		}

		// 3. Get verification key
		let vk_repository = FrameVkRepository::<T>::new();
		let circuit_id = DomainCircuitId::new(CircuitId::DISCLOSURE.0);

		// Determine actual version to search
		let actual_version = match version {
			Some(v) => v,
			None => vk_repository
				.get_active_version(circuit_id)
				.map_err(|_| Error::<T>::CircuitNotFound)?,
		};

		let vk_domain = vk_repository
			.find(circuit_id, actual_version)
			.map_err(|_| Error::<T>::RepositoryError)?
			.ok_or(Error::<T>::VerificationKeyNotFound)?;

		// 4. Create primitive verification key
		let vk = VerifyingKey::new(vk_domain.data().to_vec());

		// 5. Create primitive proofs
		let mut groth16_proofs = Vec::with_capacity(proofs.len());
		for proof_bytes in proofs {
			groth16_proofs.push(Proof::new(proof_bytes.clone()));
		}

		// 6. Create primitive public inputs
		let mut all_public_inputs = Vec::with_capacity(public_signals.len());
		for signals in public_signals {
			// Validate length
			if signals.len() != 76 {
				return Err(sp_runtime::DispatchError::Other(
					"Invalid public signals length (expected 76 bytes)",
				));
			}

			// Parse into 4 inputs (32, 8, 4, 32 bytes)
			let mut inputs_raw = Vec::with_capacity(4);

			// commitment
			let mut commitment = [0u8; 32];
			commitment.copy_from_slice(&signals[0..32]);
			inputs_raw.push(commitment);

			// revealed_value (8 bytes, pad to 32)
			let mut val = [0u8; 32];
			val[24..].copy_from_slice(&signals[32..40]);
			inputs_raw.push(val);

			// revealed_asset_id (4 bytes, pad to 32)
			let mut asset = [0u8; 32];
			asset[28..].copy_from_slice(&signals[40..44]);
			inputs_raw.push(asset);

			// revealed_owner_hash
			let mut owner = [0u8; 32];
			owner.copy_from_slice(&signals[44..76]);
			inputs_raw.push(owner);

			all_public_inputs.push(PublicInputs::new(inputs_raw));
		}

		// 7. Batch verify using fp-zk-verifier
		let valid = Groth16Verifier::batch_verify(&vk, &all_public_inputs, &groth16_proofs)
			.map_err(|_| Error::<T>::BatchVerificationFailed)?;

		Ok(valid)
	}
}

impl<T: Config> Pallet<T> {
	/// Helper para convertir ApplicationError a DispatchError
	fn map_application_error_to_dispatch(
		err: crate::application::errors::ApplicationError,
	) -> sp_runtime::DispatchError {
		Self::map_application_error(err).into()
	}
}
