//! # ZK Verifier Pallet
//!
//! On-chain Groth16 proof verification with versioned verification keys.
//!
//! ## Responsibilities
//!
//! - Store and version verification keys per circuit (Root-gated extrinsics).
//! - Expose [`ZkVerifierPort`] — the only public interface other pallets use.
//! - Verify proofs by delegating to [`verifier`].
//! - Track per-circuit statistics.
//!
//! ## Usage
//!
//! ```ignore
//! ZkVerifier::verify_proof(origin, circuit_id, proof, public_inputs)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

mod encoding;
mod port;
mod runtime_api;
mod types;
mod verifier;
pub mod weights;

#[cfg(test)]
mod mock;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use port::ZkVerifierPort;
pub use types::{
	CircuitId, CircuitVersionInfo, ProofSystem, VerificationKeyInfo, VerificationStatistics,
	VkEntry, VkVersionHash,
};
pub use weights::WeightInfo;

// ─── Pallet ───────────────────────────────────────────────────────────────────

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::vec::Vec;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		#[pallet::constant]
		type MaxProofSize: Get<u32>;

		#[pallet::constant]
		type MaxPublicInputs: Get<u32>;

		type WeightInfo: WeightInfo;
	}

	// ── Storage ───────────────────────────────────────────────────────────────

	/// Verification keys indexed by (circuit_id, version).
	#[pallet::storage]
	#[pallet::getter(fn verification_keys)]
	pub type VerificationKeys<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CircuitId,
		Blake2_128Concat,
		u32,
		VerificationKeyInfo<BlockNumberFor<T>>,
		OptionQuery,
	>;

	/// Active version for each circuit.
	#[pallet::storage]
	#[pallet::getter(fn active_circuit_version)]
	pub type ActiveCircuitVersion<T: Config> =
		StorageMap<_, Blake2_128Concat, CircuitId, u32, OptionQuery>;

	/// Verification statistics per (circuit_id, version).
	#[pallet::storage]
	pub type VerificationStats<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CircuitId,
		Blake2_128Concat,
		u32,
		VerificationStatistics,
		ValueQuery,
	>;

	// ── Genesis ───────────────────────────────────────────────────────────────

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub verification_keys: Vec<(CircuitId, Vec<u8>)>,
		#[serde(skip)]
		pub _phantom: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			for (circuit_id, vk_bytes) in &self.verification_keys {
				assert!(!vk_bytes.is_empty(), "Genesis VK cannot be empty");
				assert!(
					vk_bytes.len() >= 256,
					"Genesis VK too short (min 256 bytes)"
				);

				let key_data: BoundedVec<u8, ConstU32<8192>> = vk_bytes
					.clone()
					.try_into()
					.expect("Genesis VK exceeds maximum size (8 KB)");

				VerificationKeys::<T>::insert(
					circuit_id,
					1u32,
					VerificationKeyInfo {
						key_data,
						system: ProofSystem::Groth16,
						registered_at: BlockNumberFor::<T>::default(),
					},
				);
				ActiveCircuitVersion::<T>::insert(circuit_id, 1u32);
			}
		}
	}

	// ── Events ────────────────────────────────────────────────────────────────

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		VerificationKeyRegistered { circuit_id: CircuitId, version: u32 },
		ActiveVersionSet { circuit_id: CircuitId, version: u32 },
		VerificationKeyRemoved { circuit_id: CircuitId, version: u32 },
		ProofVerified { circuit_id: CircuitId, version: u32 },
		ProofVerificationFailed { circuit_id: CircuitId, version: u32 },
		BatchVerificationKeysRegistered { count: u32 },
	}

	// ── Errors ────────────────────────────────────────────────────────────────

	#[pallet::error]
	pub enum Error<T> {
		// Verification key
		EmptyVerificationKey,
		VerificationKeyTooLarge,
		InvalidVerificationKey,
		VerificationKeyNotFound,
		// Proof
		EmptyProof,
		ProofTooLarge,
		InvalidProof,
		// Public inputs
		EmptyPublicInputs,
		TooManyPublicInputs,
		InvalidPublicInputs,
		// Verification
		VerificationFailed,
		UnsupportedProofSystem,
		// Circuit management
		CircuitNotFound,
		CircuitAlreadyExists,
		ActiveVersionNotSet,
		CannotRemoveActiveVersion,
		// Infrastructure
		RepositoryError,
		DeserializationError,
		// Batch
		InvalidBatchSize,
		BatchLengthMismatch,
		BatchVerificationFailed,
	}

	// ── Extrinsics ────────────────────────────────────────────────────────────

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register a verification key version for a circuit (Root only).
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::register_verification_key())]
		pub fn register_verification_key(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
			verification_key: BoundedVec<u8, ConstU32<8192>>,
		) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(
				!verification_key.is_empty(),
				Error::<T>::EmptyVerificationKey
			);
			ensure!(
				verification_key.len() >= 256,
				Error::<T>::InvalidVerificationKey
			);
			// Prevent silent overwrite of an existing VK. Replacing a key that is
			// already referenced by recorded stats would desync the stats from the
			// actual key in use. Use set_active_version to switch active versions.
			ensure!(
				!VerificationKeys::<T>::contains_key(circuit_id, version),
				Error::<T>::CircuitAlreadyExists
			);

			VerificationKeys::<T>::insert(
				circuit_id,
				version,
				VerificationKeyInfo {
					key_data: verification_key,
					system: ProofSystem::Groth16,
					registered_at: frame_system::Pallet::<T>::block_number(),
				},
			);

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

		/// Set the active verification key version for a circuit (Root only).
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

		/// Remove a verification key version (Root only, cannot remove active version).
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

			let active = ActiveCircuitVersion::<T>::get(circuit_id)
				.ok_or(Error::<T>::ActiveVersionNotSet)?;
			ensure!(active != version, Error::<T>::CannotRemoveActiveVersion);

			VerificationKeys::<T>::remove(circuit_id, version);
			Self::deposit_event(Event::VerificationKeyRemoved {
				circuit_id,
				version,
			});
			Ok(())
		}

		/// Verify a zero-knowledge proof (any signed origin).
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::verify_proof())]
		pub fn verify_proof(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			proof: BoundedVec<u8, T::MaxProofSize>,
			public_inputs: BoundedVec<BoundedVec<u8, ConstU32<32>>, T::MaxPublicInputs>,
		) -> DispatchResult {
			ensure_signed(origin)?;

			let raw_inputs: Vec<[u8; 32]> = public_inputs
				.into_iter()
				.map(|i| {
					let mut arr = [0u8; 32];
					let len = i.len().min(32);
					arr[..len].copy_from_slice(&i[..len]);
					arr
				})
				.collect();

			let (result, version) = verifier::verify::<T>(circuit_id, None, &proof, raw_inputs)?;

			if result {
				Self::deposit_event(Event::ProofVerified {
					circuit_id,
					version,
				});
			} else {
				Self::deposit_event(Event::ProofVerificationFailed {
					circuit_id,
					version,
				});
				// In benchmarks, the full Groth16 pairing computation has already run
				// (deserialization succeeded, pairing was computed) so the measured
				// weight is accurate. We only skip the error return so the benchmark
				// runner can record the weight; production behaviour is unchanged.
				#[cfg(not(feature = "runtime-benchmarks"))]
				return Err(Error::<T>::VerificationFailed.into());
			}

			Ok(())
		}

		/// Atomically register (and optionally activate) up to 10 VKs (Root only).
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::batch_register_verification_keys(entries.len() as u32))]
		pub fn batch_register_verification_keys(
			origin: OriginFor<T>,
			entries: BoundedVec<VkEntry, ConstU32<10>>,
		) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(!entries.is_empty(), Error::<T>::InvalidBatchSize);

			for entry in entries.iter() {
				ensure!(
					!entry.verification_key.is_empty(),
					Error::<T>::EmptyVerificationKey
				);
				ensure!(
					entry.verification_key.len() >= 256,
					Error::<T>::InvalidVerificationKey
				);
				// Same silent-overwrite protection as single register.
				ensure!(
					!VerificationKeys::<T>::contains_key(entry.circuit_id, entry.version),
					Error::<T>::CircuitAlreadyExists
				);

				VerificationKeys::<T>::insert(
					entry.circuit_id,
					entry.version,
					VerificationKeyInfo {
						key_data: entry.verification_key.clone(),
						system: ProofSystem::Groth16,
						registered_at: frame_system::Pallet::<T>::block_number(),
					},
				);

				let auto_activate = ActiveCircuitVersion::<T>::get(entry.circuit_id).is_none();
				if entry.set_active || auto_activate {
					ActiveCircuitVersion::<T>::insert(entry.circuit_id, entry.version);
					Self::deposit_event(Event::ActiveVersionSet {
						circuit_id: entry.circuit_id,
						version: entry.version,
					});
				}

				Self::deposit_event(Event::VerificationKeyRegistered {
					circuit_id: entry.circuit_id,
					version: entry.version,
				});
			}

			Self::deposit_event(Event::BatchVerificationKeysRegistered {
				count: entries.len() as u32,
			});
			Ok(())
		}
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{MaxProofSize, MaxPublicInputs, RuntimeEvent, Test, ZkVerifier},
		pallet::{ActiveCircuitVersion, Event, VerificationKeys},
		types::{ProofSystem, VkEntry},
	};
	use frame_support::{BoundedVec, assert_err, assert_noop, assert_ok};
	use sp_io::TestExternalities;
	use sp_runtime::BuildStorage;

	// ── Helpers ───────────────────────────────────────────────────────────────

	fn new_test_ext() -> TestExternalities {
		let storage = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.expect("mock storage ok");
		let mut ext = TestExternalities::new(storage);
		// Events are only deposited when block_number > 0.
		ext.execute_with(|| frame_system::Pallet::<Test>::set_block_number(1));
		ext
	}

	/// Minimum valid VK: 300 bytes is well above the 256-byte floor.
	fn vk_bytes() -> BoundedVec<u8, frame_support::traits::ConstU32<8192>> {
		vec![0xABu8; 300].try_into().unwrap()
	}

	fn vk_too_short() -> BoundedVec<u8, frame_support::traits::ConstU32<8192>> {
		vec![0x01u8; 100].try_into().unwrap()
	}

	fn vk_empty() -> BoundedVec<u8, frame_support::traits::ConstU32<8192>> {
		BoundedVec::default()
	}

	type Proof = BoundedVec<u8, MaxProofSize>;
	type PublicInputs =
		BoundedVec<BoundedVec<u8, frame_support::traits::ConstU32<32>>, MaxPublicInputs>;

	fn proof_bytes() -> Proof {
		vec![0x01u8; 128].try_into().unwrap()
	}

	/// One valid 32-byte public input.
	fn one_public_input() -> PublicInputs {
		let inner: BoundedVec<u8, frame_support::traits::ConstU32<32>> =
			vec![0x02u8; 32].try_into().unwrap();
		vec![inner].try_into().unwrap()
	}

	fn root() -> frame_system::Origin<Test> {
		frame_system::RawOrigin::Root
	}

	fn signed() -> frame_system::Origin<Test> {
		frame_system::RawOrigin::Signed(1u64)
	}

	fn has_event(expected: Event<Test>) -> bool {
		frame_system::Pallet::<Test>::events()
			.iter()
			.any(|rec| rec.event == RuntimeEvent::ZkVerifier(expected.clone()))
	}

	fn insert_vk(circuit_id: CircuitId, version: u32) {
		use crate::pallet::VerificationKeys;
		VerificationKeys::<Test>::insert(
			circuit_id,
			version,
			crate::types::VerificationKeyInfo {
				key_data: vk_bytes(),
				system: ProofSystem::Groth16,
				registered_at: 0u64,
			},
		);
	}

	fn activate(circuit_id: CircuitId, version: u32) {
		ActiveCircuitVersion::<Test>::insert(circuit_id, version);
	}

	fn make_vk_entry(circuit_id: CircuitId, version: u32, set_active: bool) -> VkEntry {
		VkEntry {
			circuit_id,
			version,
			verification_key: vk_bytes(),
			set_active,
		}
	}

	// ── register_verification_key ─────────────────────────────────────────────

	#[test]
	fn register_vk_requires_root() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::register_verification_key(
					signed().into(),
					CircuitId::TRANSFER,
					1,
					vk_bytes(),
				),
				sp_runtime::DispatchError::BadOrigin
			);
		});
	}

	#[test]
	fn register_vk_rejects_empty_key() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::register_verification_key(
					root().into(),
					CircuitId::TRANSFER,
					1,
					vk_empty()
				),
				Error::<Test>::EmptyVerificationKey
			);
		});
	}

	#[test]
	fn register_vk_rejects_key_shorter_than_256_bytes() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::register_verification_key(
					root().into(),
					CircuitId::TRANSFER,
					1,
					vk_too_short()
				),
				Error::<Test>::InvalidVerificationKey
			);
		});
	}

	#[test]
	fn register_vk_stores_key_and_emits_event() {
		new_test_ext().execute_with(|| {
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				1,
				vk_bytes(),
			));
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId::TRANSFER,
				1u32
			));
			assert!(has_event(Event::VerificationKeyRegistered {
				circuit_id: CircuitId::TRANSFER,
				version: 1
			}));
		});
	}

	#[test]
	fn register_vk_auto_activates_when_no_active_version_exists() {
		new_test_ext().execute_with(|| {
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				1,
				vk_bytes(),
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(1u32)
			);
			assert!(has_event(Event::ActiveVersionSet {
				circuit_id: CircuitId::TRANSFER,
				version: 1
			}));
		});
	}

	#[test]
	fn register_vk_does_not_override_existing_active_version() {
		new_test_ext().execute_with(|| {
			// Register and auto-activate v1, then register v2 — active should remain v1.
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				1,
				vk_bytes(),
			));
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				2,
				vk_bytes(),
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(1u32),
				"active version must stay at 1"
			);
		});
	}

	#[test]
	fn register_vk_different_circuits_are_independent() {
		new_test_ext().execute_with(|| {
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				1,
				vk_bytes()
			));
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::UNSHIELD,
				1,
				vk_bytes()
			));
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId::TRANSFER,
				1u32
			));
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId::UNSHIELD,
				1u32
			));
		});
	}

	#[test]
	fn register_vk_rejects_duplicate_circuit_version() {
		// A second Root call with the same (circuit_id, version) must be rejected.
		// Silently overwriting would desync VerificationStats from the actual key in
		// use and could replace a live key without an on-chain trace.
		new_test_ext().execute_with(|| {
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				1,
				vk_bytes()
			));
			assert_noop!(
				ZkVerifier::register_verification_key(
					root().into(),
					CircuitId::TRANSFER,
					1,
					vk_bytes()
				),
				Error::<Test>::CircuitAlreadyExists
			);
		});
	}

	// ── set_active_version ────────────────────────────────────────────────────

	#[test]
	fn set_active_version_requires_root() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::set_active_version(signed().into(), CircuitId::TRANSFER, 1),
				sp_runtime::DispatchError::BadOrigin
			);
		});
	}

	#[test]
	fn set_active_version_rejects_non_existent_vk() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::set_active_version(root().into(), CircuitId::TRANSFER, 99),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn set_active_version_updates_storage_and_emits_event() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);

			assert_ok!(ZkVerifier::set_active_version(
				root().into(),
				CircuitId::TRANSFER,
				2
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(2u32)
			);
			assert!(has_event(Event::ActiveVersionSet {
				circuit_id: CircuitId::TRANSFER,
				version: 2
			}));
		});
	}

	#[test]
	fn set_active_version_can_downgrade() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 2);

			assert_ok!(ZkVerifier::set_active_version(
				root().into(),
				CircuitId::TRANSFER,
				1
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(1u32)
			);
		});
	}

	// ── remove_verification_key ───────────────────────────────────────────────

	#[test]
	fn remove_vk_requires_root() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::remove_verification_key(signed().into(), CircuitId::TRANSFER, 1),
				sp_runtime::DispatchError::BadOrigin
			);
		});
	}

	#[test]
	fn remove_vk_rejects_non_existent_key() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 99),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn remove_vk_cannot_remove_active_version() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);
			assert_noop!(
				ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 1),
				Error::<Test>::CannotRemoveActiveVersion
			);
		});
	}

	#[test]
	fn remove_vk_returns_active_version_not_set_when_no_active_exists() {
		new_test_ext().execute_with(|| {
			// VK exists but no active version is set.
			insert_vk(CircuitId::TRANSFER, 1);
			assert_noop!(
				ZkVerifier::remove_verification_key(root().into(), CircuitId::TRANSFER, 1),
				Error::<Test>::ActiveVersionNotSet
			);
		});
	}

	#[test]
	fn remove_vk_happy_path_removes_key_and_emits_event() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);

			assert_ok!(ZkVerifier::remove_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				2
			));
			assert!(!VerificationKeys::<Test>::contains_key(
				CircuitId::TRANSFER,
				2u32
			));
			assert!(has_event(Event::VerificationKeyRemoved {
				circuit_id: CircuitId::TRANSFER,
				version: 2
			}));
		});
	}

	#[test]
	fn remove_vk_active_version_is_preserved_after_removal() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);

			assert_ok!(ZkVerifier::remove_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				2
			));
			// Active version must still be 1.
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(1u32)
			);
		});
	}

	// ── verify_proof ──────────────────────────────────────────────────────────

	#[test]
	fn verify_proof_requires_signed_origin() {
		new_test_ext().execute_with(|| {
			assert_err!(
				ZkVerifier::verify_proof(
					root().into(),
					CircuitId::TRANSFER,
					proof_bytes(),
					one_public_input()
				),
				sp_runtime::DispatchError::BadOrigin
			);
		});
	}

	#[test]
	fn verify_proof_no_active_version_returns_circuit_not_found() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::verify_proof(
					signed().into(),
					CircuitId::TRANSFER,
					proof_bytes(),
					one_public_input()
				),
				Error::<Test>::CircuitNotFound
			);
		});
	}

	#[test]
	fn verify_proof_missing_vk_returns_not_found() {
		new_test_ext().execute_with(|| {
			activate(CircuitId::TRANSFER, 99);
			assert_noop!(
				ZkVerifier::verify_proof(
					signed().into(),
					CircuitId::TRANSFER,
					proof_bytes(),
					one_public_input()
				),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn verify_proof_empty_proof_returns_empty_proof_error() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);
			let empty: Proof = BoundedVec::default();
			assert_noop!(
				ZkVerifier::verify_proof(
					signed().into(),
					CircuitId::TRANSFER,
					empty,
					one_public_input()
				),
				Error::<Test>::EmptyProof
			);
		});
	}

	#[test]
	fn verify_proof_empty_public_inputs_returns_error() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);
			let no_inputs: PublicInputs = BoundedVec::default();
			assert_noop!(
				ZkVerifier::verify_proof(
					signed().into(),
					CircuitId::TRANSFER,
					proof_bytes(),
					no_inputs
				),
				Error::<Test>::EmptyPublicInputs
			);
		});
	}

	#[test]
	fn verify_proof_happy_path_emits_proof_verified_event() {
		// In test cfg, do_verify always returns true.
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);
			assert_ok!(ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::TRANSFER,
				proof_bytes(),
				one_public_input(),
			));
			assert!(has_event(Event::ProofVerified {
				circuit_id: CircuitId::TRANSFER,
				version: 1
			}));
		});
	}

	#[test]
	fn verify_proof_truncates_short_public_input_to_32_bytes() {
		// A short (<32 B) input is padded with trailing zeros and accepted.
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::UNSHIELD, 1);
			activate(CircuitId::UNSHIELD, 1);
			let short: BoundedVec<u8, frame_support::traits::ConstU32<32>> =
				vec![0xFFu8; 4].try_into().unwrap();
			let inputs: PublicInputs = vec![short].try_into().unwrap();
			assert_ok!(ZkVerifier::verify_proof(
				signed().into(),
				CircuitId::UNSHIELD,
				proof_bytes(),
				inputs
			));
		});
	}

	// ── batch_register_verification_keys ──────────────────────────────────────

	#[test]
	fn batch_register_requires_root() {
		new_test_ext().execute_with(|| {
			let entry = make_vk_entry(CircuitId::TRANSFER, 1, false);
			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> =
				vec![entry].try_into().unwrap();
			assert_noop!(
				ZkVerifier::batch_register_verification_keys(signed().into(), entries),
				sp_runtime::DispatchError::BadOrigin
			);
		});
	}

	#[test]
	fn batch_register_rejects_empty_entries() {
		new_test_ext().execute_with(|| {
			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> =
				BoundedVec::default();
			assert_noop!(
				ZkVerifier::batch_register_verification_keys(root().into(), entries),
				Error::<Test>::InvalidBatchSize
			);
		});
	}

	#[test]
	fn batch_register_rejects_empty_vk() {
		new_test_ext().execute_with(|| {
			let bad = VkEntry {
				circuit_id: CircuitId::TRANSFER,
				version: 1,
				verification_key: vk_empty(),
				set_active: false,
			};
			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> =
				vec![bad].try_into().unwrap();
			assert_noop!(
				ZkVerifier::batch_register_verification_keys(root().into(), entries),
				Error::<Test>::EmptyVerificationKey
			);
		});
	}

	#[test]
	fn batch_register_rejects_short_vk() {
		new_test_ext().execute_with(|| {
			let bad = VkEntry {
				circuit_id: CircuitId::TRANSFER,
				version: 1,
				verification_key: vk_too_short(),
				set_active: false,
			};
			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> =
				vec![bad].try_into().unwrap();
			assert_noop!(
				ZkVerifier::batch_register_verification_keys(root().into(), entries),
				Error::<Test>::InvalidVerificationKey
			);
		});
	}

	#[test]
	fn batch_register_stores_all_keys_and_emits_count() {
		new_test_ext().execute_with(|| {
			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> = vec![
				make_vk_entry(CircuitId::TRANSFER, 1, false),
				make_vk_entry(CircuitId::UNSHIELD, 1, false),
			]
			.try_into()
			.unwrap();
			assert_ok!(ZkVerifier::batch_register_verification_keys(
				root().into(),
				entries
			));
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId::TRANSFER,
				1u32
			));
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId::UNSHIELD,
				1u32
			));
			assert!(has_event(Event::BatchVerificationKeysRegistered {
				count: 2
			}));
		});
	}

	#[test]
	fn batch_register_auto_activates_when_no_active_version_exists() {
		new_test_ext().execute_with(|| {
			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> =
				vec![make_vk_entry(CircuitId::TRANSFER, 1, false)]
					.try_into()
					.unwrap();
			assert_ok!(ZkVerifier::batch_register_verification_keys(
				root().into(),
				entries
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(1u32)
			);
		});
	}

	#[test]
	fn batch_register_set_active_true_overrides_existing_active_version() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);

			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> =
				vec![make_vk_entry(CircuitId::TRANSFER, 2, true)]
					.try_into()
					.unwrap();
			assert_ok!(ZkVerifier::batch_register_verification_keys(
				root().into(),
				entries
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(2u32)
			);
		});
	}

	#[test]
	fn batch_register_set_active_false_does_not_override_existing_active_version() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);

			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> =
				vec![make_vk_entry(CircuitId::TRANSFER, 2, false)]
					.try_into()
					.unwrap();
			assert_ok!(ZkVerifier::batch_register_verification_keys(
				root().into(),
				entries
			));
			// Active must remain v1.
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(1u32)
			);
		});
	}

	#[test]
	fn batch_register_up_to_ten_entries_is_accepted() {
		new_test_ext().execute_with(|| {
			// Use different versions of the same circuit to fill 10 slots.
			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> = (1u32..=10)
				.map(|v| make_vk_entry(CircuitId::TRANSFER, v, false))
				.collect::<alloc::vec::Vec<_>>()
				.try_into()
				.unwrap();
			assert_ok!(ZkVerifier::batch_register_verification_keys(
				root().into(),
				entries
			));
			assert!(has_event(Event::BatchVerificationKeysRegistered {
				count: 10
			}));
		});
	}

	#[test]
	fn batch_register_rejects_duplicate_circuit_version() {
		// If any entry in the batch tries to overwrite an existing (circuit_id, version)
		// the entire batch must fail atomically — no partial state changes.
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);

			let entries: BoundedVec<VkEntry, frame_support::traits::ConstU32<10>> =
				vec![make_vk_entry(CircuitId::TRANSFER, 1, false)] // version 1 already exists
					.try_into()
					.unwrap();
			assert_noop!(
				ZkVerifier::batch_register_verification_keys(root().into(), entries),
				Error::<Test>::CircuitAlreadyExists
			);
		});
	}

	// ── runtime_api_get_circuit_version_info ──────────────────────────────────

	#[test]
	fn runtime_api_circuit_version_info_returns_none_for_unknown_circuit() {
		new_test_ext().execute_with(|| {
			assert!(
				Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0)
					.is_none()
			);
		});
	}

	#[test]
	fn runtime_api_circuit_version_info_returns_none_when_no_active_version() {
		// VK registered but active version never set.
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			assert!(
				Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0)
					.is_none()
			);
		});
	}

	#[test]
	fn runtime_api_circuit_version_info_returns_correct_fields() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);
			let info = Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0)
				.expect("should be Some");
			assert_eq!(info.circuit_id, CircuitId::TRANSFER.0);
			assert_eq!(info.active_version, 1u32);
			assert_eq!(info.supported_versions, vec![1u32, 2u32]);
			assert_eq!(info.vk_hashes.len(), 2);
		});
	}

	#[test]
	fn runtime_api_circuit_version_info_supported_versions_are_sorted() {
		new_test_ext().execute_with(|| {
			// Insert in reverse order — result must still be sorted.
			insert_vk(CircuitId::TRANSFER, 3);
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);
			let info = Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0)
				.unwrap();
			assert_eq!(info.supported_versions, vec![1u32, 2u32, 3u32]);
		});
	}

	#[test]
	fn runtime_api_circuit_version_info_vk_hashes_are_blake2_256_of_key_data() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);
			let info = Pallet::<Test>::runtime_api_get_circuit_version_info(CircuitId::TRANSFER.0)
				.unwrap();
			let expected_hash = sp_io::hashing::blake2_256(&vec![0xABu8; 300]);
			assert_eq!(info.vk_hashes[0].vk_hash, expected_hash);
			assert_eq!(info.vk_hashes[0].version, 1u32);
		});
	}

	// ── runtime_api_get_all_circuit_versions ──────────────────────────────────

	#[test]
	fn runtime_api_all_circuit_versions_empty_when_nothing_registered() {
		new_test_ext().execute_with(|| {
			assert!(Pallet::<Test>::runtime_api_get_all_circuit_versions().is_empty());
		});
	}

	#[test]
	fn runtime_api_all_circuit_versions_returns_all_active_circuits() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::UNSHIELD, 1);
			activate(CircuitId::TRANSFER, 1);
			activate(CircuitId::UNSHIELD, 1);

			let all = Pallet::<Test>::runtime_api_get_all_circuit_versions();
			assert_eq!(all.len(), 2);
			let ids: alloc::vec::Vec<u32> = all.iter().map(|i| i.circuit_id).collect();
			assert!(ids.contains(&CircuitId::TRANSFER.0));
			assert!(ids.contains(&CircuitId::UNSHIELD.0));
		});
	}

	#[test]
	fn runtime_api_all_circuit_versions_excludes_circuits_with_no_active_version() {
		new_test_ext().execute_with(|| {
			// TRANSFER has a VK but no active version → excluded.
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::UNSHIELD, 1);
			activate(CircuitId::UNSHIELD, 1);

			let all = Pallet::<Test>::runtime_api_get_all_circuit_versions();
			assert_eq!(all.len(), 1);
			assert_eq!(all[0].circuit_id, CircuitId::UNSHIELD.0);
		});
	}

	// ── Genesis ───────────────────────────────────────────────────────────────

	#[test]
	fn genesis_registers_vk_at_version_1_and_activates_it() {
		let storage = pallet::GenesisConfig::<Test> {
			verification_keys: vec![(CircuitId::TRANSFER, vec![0xCCu8; 300])],
			_phantom: Default::default(),
		}
		.build_storage()
		.unwrap();

		TestExternalities::new(storage).execute_with(|| {
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId::TRANSFER,
				1u32
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(1u32)
			);
		});
	}

	#[test]
	fn genesis_multiple_circuits_are_all_registered() {
		let storage = pallet::GenesisConfig::<Test> {
			verification_keys: vec![
				(CircuitId::TRANSFER, vec![0x11u8; 300]),
				(CircuitId::UNSHIELD, vec![0x22u8; 300]),
			],
			_phantom: Default::default(),
		}
		.build_storage()
		.unwrap();

		TestExternalities::new(storage).execute_with(|| {
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId::TRANSFER,
				1u32
			));
			assert!(VerificationKeys::<Test>::contains_key(
				CircuitId::UNSHIELD,
				1u32
			));
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::TRANSFER),
				Some(1u32)
			);
			assert_eq!(
				ActiveCircuitVersion::<Test>::get(CircuitId::UNSHIELD),
				Some(1u32)
			);
		});
	}
}
