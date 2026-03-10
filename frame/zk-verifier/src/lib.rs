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
//! - Groth16 proof verification
//! - Verification keys managed in on-chain storage (including genesis seeding)
//! - Statistics tracking per circuit
//! - Forward-compatible proof system model (runtime path currently Groth16)
//!
//! ## Usage
//!
//! ```ignore
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

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod presentation;

// Supporting modules (internal)
mod types;
pub mod weights;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

/// Domain port for ZK verification (the ONLY public contract)
pub use domain::services::ZkVerifierPort;

pub use types::{CircuitId, ProofSystem, VerificationKeyInfo, VerificationStatistics};
pub use weights::WeightInfo;

#[derive(
	Clone,
	PartialEq,
	Eq,
	parity_scale_codec::Encode,
	parity_scale_codec::Decode,
	scale_info::TypeInfo,
	Debug
)]
pub struct RuntimeVkVersionHash {
	pub version: u32,
	pub vk_hash: [u8; 32],
}

#[derive(
	Clone,
	PartialEq,
	Eq,
	parity_scale_codec::Encode,
	parity_scale_codec::Decode,
	scale_info::TypeInfo,
	Debug
)]
pub struct RuntimeCircuitVersionInfo {
	pub circuit_id: u32,
	pub active_version: u32,
	pub supported_versions: alloc::vec::Vec<u32>,
	pub vk_hashes: alloc::vec::Vec<RuntimeVkVersionHash>,
}

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
				let domain_vk = crate::domain::entities::VerificationKey::new(
					vk_bytes.clone(),
					crate::domain::value_objects::ProofSystem::Groth16,
				)
				.expect("Invalid zk_verifier genesis VK");

				let vk_info = VerificationKeyInfo {
					key_data: domain_vk
						.data()
						.to_vec()
						.try_into()
						.expect("Genesis VK exceeds maximum size"),
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
		/// Verification key registered on-chain
		VerificationKeyRegistered { circuit_id: CircuitId, version: u32 },
		/// Active version changed for a circuit
		ActiveVersionSet { circuit_id: CircuitId, version: u32 },
		/// Verification key removed from on-chain registry
		VerificationKeyRemoved { circuit_id: CircuitId, version: u32 },
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
		ActiveVersionNotSet,
		CannotRemoveActiveVersion,

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
		/// Register a verification key version for a circuit.
		///
		/// Origin must be Root (sudo/governance).
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::register_verification_key())]
		pub fn register_verification_key(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
			verification_key: BoundedVec<u8, ConstU32<8192>>,
		) -> DispatchResult {
			ensure_root(origin)?;

			let domain_vk = crate::domain::entities::VerificationKey::new(
				verification_key.to_vec(),
				crate::domain::value_objects::ProofSystem::Groth16,
			)
			.map_err(|err| {
				Self::map_application_error(crate::application::errors::ApplicationError::Domain(
					err,
				))
			})?;

			let vk_info = VerificationKeyInfo {
				key_data: domain_vk
					.data()
					.to_vec()
					.try_into()
					.map_err(|_| Error::<T>::VerificationKeyTooLarge)?,
				system: ProofSystem::Groth16,
				registered_at: frame_system::Pallet::<T>::block_number(),
			};

			VerificationKeys::<T>::insert(circuit_id, version, vk_info);

			if ActiveCircuitVersion::<T>::get(circuit_id).is_none() {
				ActiveCircuitVersion::<T>::insert(circuit_id, version);
				Self::deposit_event(Event::ActiveVersionSet {
					circuit_id,
					version,
				});
			}

			Self::deposit_event(Event::VerificationKeyRegistered {
				circuit_id,
				version,
			});
			Ok(())
		}

		/// Set active verification key version for a circuit.
		///
		/// Origin must be Root (sudo/governance).
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_active_version())]
		pub fn set_active_version(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
		) -> DispatchResult {
			ensure_root(origin)?;

			ensure!(
				VerificationKeys::<T>::contains_key(circuit_id, version),
				Error::<T>::VerificationKeyNotFound
			);

			ActiveCircuitVersion::<T>::insert(circuit_id, version);
			Self::deposit_event(Event::ActiveVersionSet {
				circuit_id,
				version,
			});
			Ok(())
		}

		/// Remove verification key version from a circuit.
		///
		/// Origin must be Root (sudo/governance).
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::remove_verification_key())]
		pub fn remove_verification_key(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
		) -> DispatchResult {
			ensure_root(origin)?;

			ensure!(
				VerificationKeys::<T>::contains_key(circuit_id, version),
				Error::<T>::VerificationKeyNotFound
			);

			let active_version = ActiveCircuitVersion::<T>::get(circuit_id)
				.ok_or(Error::<T>::ActiveVersionNotSet)?;
			ensure!(
				active_version != version,
				Error::<T>::CannotRemoveActiveVersion
			);

			VerificationKeys::<T>::remove(circuit_id, version);
			Self::deposit_event(Event::VerificationKeyRemoved {
				circuit_id,
				version,
			});
			Ok(())
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
// ZkVerifierPort Trait Implementation
// ============================================================================

impl<T: Config> ZkVerifierPort for Pallet<T> {
	/// Verify a private transfer proof
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
		use alloc::{boxed::Box, vec::Vec};

		// Build public inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2]
		// Canonical format between shielded-pool and zk-verifier is little-endian (LE).
		// Keep bytes as-is to avoid cross-pallet conversions.

		let mut public_inputs = Vec::new();
		public_inputs.push(merkle_root.to_vec());
		for nullifier in nullifiers {
			public_inputs.push(nullifier.to_vec());
		}
		for commitment in commitments {
			public_inputs.push(commitment.to_vec());
		}

		// Create command for the use case
		let command = VerifyProofCommand {
			circuit_id: DomainCircuitId::new(CircuitId::TRANSFER.0),
			version,
			proof: proof.to_vec(),
			public_inputs,
		};

		// Execute use case
		let vk_repository = FrameVkRepository::<T>::new();
		let statistics = FrameStatisticsRepository::<T>::new();
		let validator = Box::new(Groth16Verifier);

		let use_case = VerifyProofUseCase::new(vk_repository, statistics, validator);
		use_case
			.execute(command)
			.map_err(Self::map_application_error_to_dispatch)
	}

	/// Verify an unshield proof (pool withdrawal)
	fn verify_unshield_proof(
		proof: &[u8],
		merkle_root: &[u8; 32],
		nullifier: &[u8; 32],
		amount: u128,
		recipient: &[u8; 32],
		asset_id: u32,
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

		// Build public inputs: [merkle_root, nullifier, amount, recipient, asset_id]
		// Canonical format between shielded-pool and zk-verifier is LE.

		// amount is encoded as 32 bytes little-endian (u128 -> [u8; 32])
		let mut amount_bytes = [0u8; 32];
		amount_bytes[..16].copy_from_slice(&amount.to_le_bytes());

		// recipient is AccountId32 (32 bytes, big-endian).
		// For BN254 field LE encoding: reverse the byte order.
		let mut recipient_bytes = [0u8; 32];
		for (index, byte) in recipient.iter().rev().enumerate() {
			recipient_bytes[index] = *byte;
		}

		// asset_id is encoded as 32 bytes little-endian (u32 -> [u8; 32])
		let mut asset_id_bytes = [0u8; 32];
		asset_id_bytes[..4].copy_from_slice(&asset_id.to_le_bytes());

		use alloc::vec;
		let public_inputs = vec![
			merkle_root.to_vec(),
			nullifier.to_vec(),
			amount_bytes.to_vec(),
			recipient_bytes.to_vec(),
			asset_id_bytes.to_vec(),
		];

		// Create command for the use case
		let command = VerifyProofCommand {
			circuit_id: DomainCircuitId::new(CircuitId::UNSHIELD.0),
			version,
			proof: proof.to_vec(),
			public_inputs,
		};

		// Execute use case
		let vk_repository = FrameVkRepository::<T>::new();
		let statistics = FrameStatisticsRepository::<T>::new();
		let validator = Box::new(Groth16Verifier);

		let use_case = VerifyProofUseCase::new(vk_repository, statistics, validator);
		use_case
			.execute(command)
			.map_err(Self::map_application_error_to_dispatch)
	}

	/// Verify a disclosure proof (selective disclosure)
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

		// Separate into 4 inputs, padding each to 32 bytes for verifier
		// All public inputs must be exactly 32 bytes per domain validation
		use alloc::vec;

		// 1. commitment (32 bytes) - already correct size
		let commitment = public_signals[0..32].to_vec();

		// 2. revealed_value (8 bytes) - pad to 32 bytes little-endian
		let mut revealed_value_bytes = [0u8; 32];
		revealed_value_bytes[..8].copy_from_slice(&public_signals[32..40]);

		// 3. revealed_asset_id (4 bytes) - pad to 32 bytes little-endian
		let mut revealed_asset_id_bytes = [0u8; 32];
		revealed_asset_id_bytes[..4].copy_from_slice(&public_signals[40..44]);

		// 4. revealed_owner_hash (32 bytes) - already correct size
		let revealed_owner_hash = public_signals[44..76].to_vec();

		let public_inputs = vec![
			commitment,
			revealed_value_bytes.to_vec(),
			revealed_asset_id_bytes.to_vec(),
			revealed_owner_hash,
		];

		// Create command for the use case with circuit ID "disclosure"
		let command = VerifyProofCommand {
			circuit_id: DomainCircuitId::new(CircuitId::DISCLOSURE.0),
			version,
			proof: proof.to_vec(),
			public_inputs,
		};

		// Execute use case
		let vk_repository = FrameVkRepository::<T>::new();
		let statistics = FrameStatisticsRepository::<T>::new();
		let validator = Box::new(Groth16Verifier);

		let use_case = VerifyProofUseCase::new(vk_repository, statistics, validator);
		use_case
			.execute(command)
			.map_err(Self::map_application_error_to_dispatch)
	}

	/// Verify multiple disclosure proofs in batch (optimized)
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

			// Parse into 4 inputs, each padded to 32 bytes (low-order, little-endian style)
			let mut inputs_raw = Vec::with_capacity(4);

			// 1. commitment (32 bytes) - already correct size
			let mut commitment = [0u8; 32];
			commitment.copy_from_slice(&signals[0..32]);
			inputs_raw.push(commitment);

			// 2. revealed_value (8 bytes) - pad to 32 bytes little-endian
			let mut val = [0u8; 32];
			val[..8].copy_from_slice(&signals[32..40]);
			inputs_raw.push(val);

			// 3. revealed_asset_id (4 bytes) - pad to 32 bytes little-endian
			let mut asset = [0u8; 32];
			asset[..4].copy_from_slice(&signals[40..44]);
			inputs_raw.push(asset);

			// 4. revealed_owner_hash (32 bytes) - already correct size
			let mut owner = [0u8; 32];
			owner.copy_from_slice(&signals[44..76]);
			inputs_raw.push(owner);

			all_public_inputs.push(PublicInputs::new(inputs_raw));
		}

		// 7. Batch verify using orbinum-zk-verifier primitives
		let valid = Groth16Verifier::batch_verify(&vk, &all_public_inputs, &groth16_proofs)
			.map_err(|_| Error::<T>::BatchVerificationFailed)?;

		Ok(valid)
	}

	/// Verify a private link dispatch proof
	fn verify_private_link_proof(
		proof: &[u8],
		commitment: &[u8; 32],
		call_hash_fe: &[u8; 32],
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
		use alloc::{boxed::Box, vec};

		// Public inputs: [commitment(32B LE), call_hash_fe(32B LE)]
		let public_inputs = vec![commitment.to_vec(), call_hash_fe.to_vec()];

		let command = VerifyProofCommand {
			circuit_id: DomainCircuitId::new(CircuitId::PRIVATE_LINK.0),
			version,
			proof: proof.to_vec(),
			public_inputs,
		};

		let vk_repository = FrameVkRepository::<T>::new();
		let statistics = FrameStatisticsRepository::<T>::new();
		let validator = Box::new(Groth16Verifier);

		let use_case = VerifyProofUseCase::new(vk_repository, statistics, validator);
		use_case
			.execute(command)
			.map_err(Self::map_application_error_to_dispatch)
	}
}

impl<T: Config> Pallet<T> {
	pub fn runtime_api_get_circuit_version_info(
		circuit_id: u32,
	) -> Option<RuntimeCircuitVersionInfo> {
		use crate::infrastructure::repositories::{
			runtime_active_version, runtime_supported_versions, runtime_vk_hash,
		};

		let supported_versions = runtime_supported_versions::<T>(circuit_id);
		if supported_versions.is_empty() {
			return None;
		}

		let active_version = runtime_active_version::<T>(circuit_id)?;
		let vk_hashes = supported_versions
			.iter()
			.filter_map(|version| {
				runtime_vk_hash::<T>(circuit_id, *version).map(|vk_hash| RuntimeVkVersionHash {
					version: *version,
					vk_hash,
				})
			})
			.collect();

		Some(RuntimeCircuitVersionInfo {
			circuit_id,
			active_version,
			supported_versions,
			vk_hashes,
		})
	}

	pub fn runtime_api_get_all_circuit_versions() -> alloc::vec::Vec<RuntimeCircuitVersionInfo> {
		use alloc::collections::BTreeSet;

		let circuit_ids: BTreeSet<u32> = VerificationKeys::<T>::iter_keys()
			.map(|(circuit_id, _version)| circuit_id.0)
			.collect();

		circuit_ids
			.into_iter()
			.filter_map(Self::runtime_api_get_circuit_version_info)
			.collect()
	}
}

impl<T: Config> Pallet<T> {
	/// Helper to convert ApplicationError to DispatchError
	fn map_application_error_to_dispatch(
		err: crate::application::errors::ApplicationError,
	) -> sp_runtime::DispatchError {
		#[cfg(feature = "std")]
		log::error!("zk-verifier application error: {err:?}");
		Self::map_application_error(err).into()
	}
}
