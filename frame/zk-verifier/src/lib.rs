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

	/// Storage version history:
	/// - v1: drop the retired `private_link` circuit (id 5).
	///
	/// The v1 migration code was removed once every live chain reached v1; a new chain
	/// starts here via genesis. See git history if an old chain ever needs it.
	pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
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

	/// Retired `(circuit_id, version)` pairs rejected during verification.
	#[pallet::storage]
	pub type RetiredVersions<T: Config> =
		StorageDoubleMap<_, Blake2_128Concat, CircuitId, Blake2_128Concat, u32, (), OptionQuery>;

	/// Cached `blake2_256(key_data)` hash for each registered verification key.
	#[pallet::storage]
	pub type VkHashes<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		CircuitId,
		Blake2_128Concat,
		u32,
		[u8; 32],
		OptionQuery,
	>;

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

				let hash = sp_io::hashing::blake2_256(key_data.as_slice());
				VerificationKeys::<T>::insert(
					circuit_id,
					1u32,
					VerificationKeyInfo {
						key_data,
						system: ProofSystem::Groth16,
						registered_at: BlockNumberFor::<T>::default(),
					},
				);
				VkHashes::<T>::insert(circuit_id, 1u32, hash);
				ActiveCircuitVersion::<T>::insert(circuit_id, 1u32);
			}
		}
	}

	// ── Hooks ─────────────────────────────────────────────────────────────────

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Runs when the runtime is built. `skip-proof-verification` disables ZK
		/// verification and is only legitimate together with `runtime-benchmarks`
		/// (the benchmark runner). Enabling it alone means a release runtime with no
		/// verification, so abort construction in that case.
		fn integrity_test() {
			assert!(
				!cfg!(feature = "skip-proof-verification") || cfg!(feature = "runtime-benchmarks"),
				"pallet-zk-verifier compiled with `skip-proof-verification` but without \
				 `runtime-benchmarks`: ZK proof verification is disabled outside a \
				 benchmark build. This must never run on a live chain."
			);
		}
	}

	// ── Events ────────────────────────────────────────────────────────────────

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		VerificationKeyRegistered {
			circuit_id: CircuitId,
			version: u32,
		},
		ActiveVersionSet {
			circuit_id: CircuitId,
			version: u32,
		},
		VerificationKeyRemoved {
			circuit_id: CircuitId,
			version: u32,
		},
		VersionRetired {
			circuit_id: CircuitId,
			version: u32,
		},
		VersionUnretired {
			circuit_id: CircuitId,
			version: u32,
		},
		ProofVerified {
			circuit_id: CircuitId,
			version: u32,
		},
		ProofVerificationFailed {
			circuit_id: CircuitId,
			version: u32,
		},
		BatchVerificationKeysRegistered {
			count: u32,
		},
		/// Every version of a retired circuit was purged from storage.
		CircuitPurged {
			circuit_id: CircuitId,
			removed: u32,
		},
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
		UnsupportedCircuitVersion,
		CannotRetireActiveVersion,
		VersionAlreadyRetired,
		VersionNotRetired,
		TooManyVersions,
		// Infrastructure
		RepositoryError,
		DeserializationError,
		// Batch
		InvalidBatchSize,
		BatchLengthMismatch,
		BatchVerificationFailed,
		// Purge
		CircuitStillInUse,
		CircuitHasNoStorage,
	}

	// ── Extrinsics ────────────────────────────────────────────────────────────

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Register a verification key version for a circuit (Root only).
		///
		/// SECURITY INVARIANT: a new version of an EXISTING circuit id must only be
		/// a key rotation of the *same* circuit (identical R1CS / public-signal
		/// semantics — e.g. a fresh trusted setup). A note's circuit version is NOT
		/// bound into its commitment (see shielded-pool Limitation 1), so the
		/// submitter picks the version freely; verification is safe only because a
		/// proof verifies solely under the exact VK of the circuit that produced it.
		/// Registering a version whose circuit keeps the same public-input arity but
		/// changes a constraint's *meaning* would let a note be spent under weaker
		/// rules. A semantic change MUST use a NEW circuit id, never a new version.
		/// `ensure_vk_arity` enforces arity, NOT semantics — that is a governance
		/// responsibility. Retire a superseded weak version with `retire_version`.
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
			Self::ensure_vk_arity(circuit_id, &verification_key)?;
			ensure!(
				!VerificationKeys::<T>::contains_key(circuit_id, version),
				Error::<T>::CircuitAlreadyExists
			);

			Self::store_vk(circuit_id, version, verification_key)?;

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
			RetiredVersions::<T>::remove(circuit_id, version);
			VkHashes::<T>::remove(circuit_id, version);
			VerificationStats::<T>::remove(circuit_id, version);
			Self::deposit_event(Event::VerificationKeyRemoved {
				circuit_id,
				version,
			});
			Ok(())
		}

		/// Verify a zero-knowledge proof (any signed origin).
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::verify_proof(public_inputs.len() as u32))]
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
					<[u8; 32]>::try_from(i.as_slice()).map_err(|_| Error::<T>::InvalidPublicInputs)
				})
				.collect::<Result<_, _>>()?;

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
				// Benchmarks feed dummy proofs that never verify; skipping the error
				// return lets the runner record the weight (the pairing already ran).
				// Gated on `skip-proof-verification`, NOT `runtime-benchmarks`, so a
				// release runtime never disables the error path. See integrity_test.
				#[cfg(not(feature = "skip-proof-verification"))]
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
				Self::ensure_vk_arity(entry.circuit_id, &entry.verification_key)?;
				// Same silent-overwrite protection as single register.
				ensure!(
					!VerificationKeys::<T>::contains_key(entry.circuit_id, entry.version),
					Error::<T>::CircuitAlreadyExists
				);

				Self::store_vk(
					entry.circuit_id,
					entry.version,
					entry.verification_key.clone(),
				)?;

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

		/// Retires a verification key version while preserving its data.
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::retire_version())]
		pub fn retire_version(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
		) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(
				VerificationKeys::<T>::contains_key(circuit_id, version),
				Error::<T>::VerificationKeyNotFound
			);
			ensure!(
				!RetiredVersions::<T>::contains_key(circuit_id, version),
				Error::<T>::VersionAlreadyRetired
			);
			let active = ActiveCircuitVersion::<T>::get(circuit_id)
				.ok_or(Error::<T>::ActiveVersionNotSet)?;
			ensure!(active != version, Error::<T>::CannotRetireActiveVersion);

			RetiredVersions::<T>::insert(circuit_id, version, ());
			Self::deposit_event(Event::VersionRetired {
				circuit_id,
				version,
			});
			Ok(())
		}

		/// Reverse `retire_version`: allow proofs for `(circuit_id, version)` again.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::unretire_version())]
		pub fn unretire_version(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
		) -> DispatchResult {
			ensure_root(origin)?;
			ensure!(
				RetiredVersions::<T>::contains_key(circuit_id, version),
				Error::<T>::VersionNotRetired
			);
			RetiredVersions::<T>::remove(circuit_id, version);
			Self::deposit_event(Event::VersionUnretired {
				circuit_id,
				version,
			});
			Ok(())
		}

		/// Erase every trace of a circuit the runtime no longer implements.
		///
		/// `remove_verification_key` and `retire_version` both refuse to touch the
		/// active version, which is what keeps a live circuit from ending up with
		/// no key to verify against. That guard also makes them unable to retire a
		/// circuit as a whole: its last version is, by construction, the active one.
		/// This call covers that gap — and only that gap.
		///
		/// The one guard: the runtime must no longer know the id —
		/// `expected_public_inputs` returns `None`. An id above `u8::MAX` is
		/// rejected outright rather than truncated into that lookup, so a future
		/// circuit numbered past 255 cannot alias its way past this check.
		///
		/// `ActiveCircuitVersion` is cleared here rather than required to be empty
		/// beforehand. Requiring it would make the call unreachable: the first
		/// `register_verification_key` for a circuit activates the version it
		/// registers, and no extrinsic ever clears that entry — `set_active_version`
		/// only overwrites, and both `retire_version` and `remove_verification_key`
		/// refuse to touch whichever version is active. An unknown id has no
		/// verification route regardless of what the entry says, so it carries no
		/// authority worth guarding.
		///
		/// Clears all five maps by prefix — `VerificationKeys`, `VkHashes`,
		/// `VerificationStats`, `RetiredVersions`, `ActiveCircuitVersion` — rather
		/// than iterating one map's versions, so entries orphaned in the satellite
		/// maps by an earlier `remove_verification_key` are collected too.
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::purge_circuit(Pallet::<T>::MAX_VERSIONS_PER_CIRCUIT))]
		pub fn purge_circuit(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
		) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;

			// Fail closed on ids that do not fit the lookup: `as u8` would alias
			// e.g. 257 onto 1, so an id past 255 must never reach the table.
			let id = u8::try_from(circuit_id.0).map_err(|_| Error::<T>::CircuitStillInUse)?;
			ensure!(
				orbinum_zk_verifier::expected_public_inputs(id).is_none(),
				Error::<T>::CircuitStillInUse
			);

			// Counted by iterating rather than from `clear_prefix`'s result: its
			// counters only report keys committed to the backend, and everything
			// written earlier in the same block still lives in the overlay.
			//
			// Each map is counted on its own and the totals summed, not maxed: the
			// four normally share a version set, but nothing in the type system says
			// they must, and the sum is what the clear below actually pays for.
			let per_map = [
				VerificationKeys::<T>::iter_key_prefix(circuit_id).count(),
				VkHashes::<T>::iter_key_prefix(circuit_id).count(),
				VerificationStats::<T>::iter_key_prefix(circuit_id).count(),
				RetiredVersions::<T>::iter_key_prefix(circuit_id).count(),
			];
			// A stale `ActiveCircuitVersion` with no versions behind it is still an
			// entry to clear, so it belongs in the total the event reports.
			let active_entries = usize::from(ActiveCircuitVersion::<T>::contains_key(circuit_id));
			let entries = per_map.iter().sum::<usize>().saturating_add(active_entries);

			ensure!(entries > 0, Error::<T>::CircuitHasNoStorage);
			// The cap bounds versions per map, so the clear is bounded by the widest
			// map, not by the total. More than that means storage was built outside
			// `store_vk`; bail rather than clear part of it — the extrinsic reverts
			// as a whole, so nothing is left half-done.
			let widest = per_map.iter().copied().max().unwrap_or(0);
			ensure!(
				widest <= Self::MAX_VERSIONS_PER_CIRCUIT as usize,
				Error::<T>::TooManyVersions
			);

			// `u32::MAX` as the limit: the count above already proved the prefix
			// fits within the cap, so this only has to clear everything in one pass.
			let _ = VerificationKeys::<T>::clear_prefix(circuit_id, u32::MAX, None);
			let _ = VkHashes::<T>::clear_prefix(circuit_id, u32::MAX, None);
			let _ = VerificationStats::<T>::clear_prefix(circuit_id, u32::MAX, None);
			let _ = RetiredVersions::<T>::clear_prefix(circuit_id, u32::MAX, None);
			ActiveCircuitVersion::<T>::remove(circuit_id);

			// Reports entries cleared across every map, not versions: an indexer
			// reconciling against its own view needs the real figure, and a stale
			// active pointer with no versions behind it still cleared something.
			Self::deposit_event(Event::CircuitPurged {
				circuit_id,
				removed: entries as u32,
			});
			// Weighed by versions, not entries: the benchmark's linear component
			// charges one read and four writes per version, so it is already the
			// per-version cost of clearing all four maps.
			Ok(Some(T::WeightInfo::purge_circuit(widest as u32)).into())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Verify the VK deserializes as a BN254 Groth16 key and, for known circuits,
		/// that its arity matches. Unknown circuits are only checked to deserialize.
		fn ensure_vk_arity(circuit_id: CircuitId, key_data: &[u8]) -> DispatchResult {
			use orbinum_zk_verifier::{VerifyingKey, expected_public_inputs};

			let vk = VerifyingKey::new(key_data.to_vec());
			let arity = vk
				.num_public_inputs()
				.map_err(|_| Error::<T>::InvalidVerificationKey)?;

			// circuit ids fit in u8 for the known set.
			if let Some(expected) = expected_public_inputs(circuit_id.0 as u8) {
				ensure!(arity == expected, Error::<T>::InvalidVerificationKey);
			}
			Ok(())
		}

		/// Upper bound on stored versions per circuit — keeps the versions DoubleMap
		/// and the runtime-API iteration provably bounded. Registration is Root-only,
		/// so this is operator-discipline, not an attacker limit.
		pub(crate) const MAX_VERSIONS_PER_CIRCUIT: u32 = 64;

		/// Insert a validated VK for `(circuit_id, version)` and store its hash.
		/// Enforces the per-circuit version cap. Callers must have already run
		/// `ensure_vk_arity` + the silent-overwrite check.
		fn store_vk(
			circuit_id: CircuitId,
			version: u32,
			key_data: BoundedVec<u8, ConstU32<8192>>,
		) -> DispatchResult {
			let count = VerificationKeys::<T>::iter_key_prefix(circuit_id).count() as u32;
			ensure!(
				count < Self::MAX_VERSIONS_PER_CIRCUIT,
				Error::<T>::TooManyVersions
			);

			let hash = sp_io::hashing::blake2_256(key_data.as_slice());
			VerificationKeys::<T>::insert(
				circuit_id,
				version,
				VerificationKeyInfo {
					key_data,
					system: ProofSystem::Groth16,
					registered_at: frame_system::Pallet::<T>::block_number(),
				},
			);
			VkHashes::<T>::insert(circuit_id, version, hash);
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
		pallet::{ActiveCircuitVersion, Event, RetiredVersions, VerificationKeys},
		types::{ProofSystem, VkEntry},
	};
	use frame_support::{BoundedVec, assert_err, assert_noop, assert_ok};
	use orbinum_zk_verifier::{TRANSFER_PUBLIC_INPUTS, UNSHIELD_PUBLIC_INPUTS};
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
	/// A serialized BN254 Groth16 VK with `arity` public inputs. Registration now
	/// validates arity, so tests need a key that deserializes and matches.
	fn real_vk(arity: usize) -> BoundedVec<u8, frame_support::traits::ConstU32<8192>> {
		use ark_bn254::{Bn254, G1Affine, G2Affine};
		use ark_ec::AffineRepr;
		use ark_groth16::VerifyingKey as ArkVk;
		use orbinum_zk_verifier::VerifyingKey;

		let vk = ArkVk::<Bn254> {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: G2Affine::generator(),
			gamma_abc_g1: (0..=arity).map(|_| G1Affine::generator()).collect(),
		};
		VerifyingKey::from_ark_vk(&vk)
			.unwrap()
			.bytes
			.try_into()
			.expect("serialized VK fits in 8192 bytes")
	}

	/// VK for the TRANSFER circuit (arity 5) — the default used by most tests.
	fn vk_bytes() -> BoundedVec<u8, frame_support::traits::ConstU32<8192>> {
		real_vk(TRANSFER_PUBLIC_INPUTS)
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
		// Use a VK whose arity matches the circuit (validated on register).
		let arity = orbinum_zk_verifier::expected_public_inputs(circuit_id.0 as u8)
			.unwrap_or(TRANSFER_PUBLIC_INPUTS);
		VkEntry {
			circuit_id,
			version,
			verification_key: real_vk(arity),
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
	fn register_vk_rejects_wrong_arity() {
		new_test_ext().execute_with(|| {
			// TRANSFER expects TRANSFER_PUBLIC_INPUTS; a VK of a different arity is rejected.
			assert_noop!(
				ZkVerifier::register_verification_key(
					root().into(),
					CircuitId::TRANSFER,
					1,
					real_vk(TRANSFER_PUBLIC_INPUTS + 1)
				),
				Error::<Test>::InvalidVerificationKey
			);
			// The matching arity is accepted.
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				1,
				real_vk(TRANSFER_PUBLIC_INPUTS)
			));
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
				real_vk(UNSHIELD_PUBLIC_INPUTS)
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
	fn verify_proof_weight_grows_with_inputs() {
		use crate::weights::WeightInfo;
		type W = crate::weights::SubstrateWeight<Test>;
		assert!(W::verify_proof(8).ref_time() > W::verify_proof(1).ref_time());
		assert!(W::verify_proof(32).ref_time() > W::verify_proof(8).ref_time());
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
	fn verify_proof_rejects_short_public_input() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::UNSHIELD, 1);
			activate(CircuitId::UNSHIELD, 1);
			let short: BoundedVec<u8, frame_support::traits::ConstU32<32>> =
				vec![0xFFu8; 4].try_into().unwrap();
			let inputs: PublicInputs = vec![short].try_into().unwrap();
			assert_noop!(
				ZkVerifier::verify_proof(
					signed().into(),
					CircuitId::UNSHIELD,
					proof_bytes(),
					inputs
				),
				Error::<Test>::InvalidPublicInputs
			);
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
			let expected_hash = sp_io::hashing::blake2_256(&vk_bytes());
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

	// ── retire_version / unretire_version ─────────────────────────────────────

	#[test]
	fn retire_version_requires_root() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);
			assert_noop!(
				ZkVerifier::retire_version(signed().into(), CircuitId::TRANSFER, 2),
				sp_runtime::DispatchError::BadOrigin
			);
		});
	}

	#[test]
	fn retire_version_rejects_active_and_unknown() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			activate(CircuitId::TRANSFER, 1);
			// active version cannot be retired
			assert_noop!(
				ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 1),
				Error::<Test>::CannotRetireActiveVersion
			);
			// unknown version cannot be retired
			assert_noop!(
				ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 9),
				Error::<Test>::VerificationKeyNotFound
			);
		});
	}

	#[test]
	fn retire_then_unretire_toggles_the_flag() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);

			assert_ok!(ZkVerifier::retire_version(
				root().into(),
				CircuitId::TRANSFER,
				2
			));
			assert!(RetiredVersions::<Test>::contains_key(
				CircuitId::TRANSFER,
				2
			));
			assert!(has_event(Event::VersionRetired {
				circuit_id: CircuitId::TRANSFER,
				version: 2
			}));
			// double-retire rejected
			assert_noop!(
				ZkVerifier::retire_version(root().into(), CircuitId::TRANSFER, 2),
				Error::<Test>::VersionAlreadyRetired
			);

			assert_ok!(ZkVerifier::unretire_version(
				root().into(),
				CircuitId::TRANSFER,
				2
			));
			assert!(!RetiredVersions::<Test>::contains_key(
				CircuitId::TRANSFER,
				2
			));
			// unretire of a non-retired version rejected
			assert_noop!(
				ZkVerifier::unretire_version(root().into(), CircuitId::TRANSFER, 2),
				Error::<Test>::VersionNotRetired
			);
		});
	}

	#[test]
	fn removing_a_vk_clears_its_retirement_flag() {
		new_test_ext().execute_with(|| {
			insert_vk(CircuitId::TRANSFER, 1);
			insert_vk(CircuitId::TRANSFER, 2);
			activate(CircuitId::TRANSFER, 1);
			assert_ok!(ZkVerifier::retire_version(
				root().into(),
				CircuitId::TRANSFER,
				2
			));
			assert_ok!(ZkVerifier::remove_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				2
			));
			assert!(!RetiredVersions::<Test>::contains_key(
				CircuitId::TRANSFER,
				2
			));
		});
	}

	// ── version cap + stored vk_hash ──────────────────────────────────────────

	#[test]
	fn register_stores_the_vk_hash() {
		new_test_ext().execute_with(|| {
			let vk = real_vk(TRANSFER_PUBLIC_INPUTS);
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				CircuitId::TRANSFER,
				1,
				vk.clone()
			));
			let expected = sp_io::hashing::blake2_256(vk.as_slice());
			assert_eq!(
				crate::pallet::VkHashes::<Test>::get(CircuitId::TRANSFER, 1),
				Some(expected)
			);
		});
	}

	#[test]
	fn register_rejects_beyond_max_versions_per_circuit() {
		new_test_ext().execute_with(|| {
			// Fill the circuit up to the cap with direct inserts (versions 1..=MAX).
			let max = Pallet::<Test>::MAX_VERSIONS_PER_CIRCUIT;
			for v in 1..=max {
				insert_vk(CircuitId::TRANSFER, v);
			}
			// One more via the real path must be rejected by the cap.
			assert_noop!(
				ZkVerifier::register_verification_key(
					root().into(),
					CircuitId::TRANSFER,
					max + 1,
					real_vk(TRANSFER_PUBLIC_INPUTS)
				),
				Error::<Test>::TooManyVersions
			);
		});
	}

	// The integrity_test must abort when verification is compiled out WITHOUT the
	// benchmark feature — i.e. a would-be release runtime with no verification. Only
	// compiles in that exact combination (skip on, benchmarks off).
	#[cfg(all(
		feature = "skip-proof-verification",
		not(feature = "runtime-benchmarks")
	))]
	#[test]
	#[should_panic(expected = "skip-proof-verification")]
	fn integrity_test_panics_when_verification_disabled() {
		use frame_support::traits::Hooks;
		<ZkVerifier as Hooks<frame_system::pallet_prelude::BlockNumberFor<Test>>>::integrity_test();
	}

	// ── purge_circuit ─────────────────────────────────────────────────────────

	/// Seeds every map for `(circuit_id, version)` and marks the version active.
	/// Callers that then purge must clear `ActiveCircuitVersion` first — the
	/// extrinsic refuses circuits that still have one.
	fn seed_circuit(circuit_id: CircuitId, version: u32, arity: usize) {
		VerificationKeys::<Test>::insert(
			circuit_id,
			version,
			VerificationKeyInfo {
				key_data: real_vk(arity),
				system: ProofSystem::Groth16,
				registered_at: 0u64,
			},
		);
		crate::pallet::VkHashes::<Test>::insert(circuit_id, version, [0x11u8; 32]);
		ActiveCircuitVersion::<Test>::insert(circuit_id, version);
	}

	#[test]
	fn purge_circuit_clears_every_map() {
		new_test_ext().execute_with(|| {
			let retired = CircuitId(5);
			seed_circuit(retired, 1, 2);
			RetiredVersions::<Test>::insert(retired, 1, ());

			assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

			assert!(VerificationKeys::<Test>::get(retired, 1).is_none());
			assert!(crate::pallet::VkHashes::<Test>::get(retired, 1).is_none());
			assert!(!crate::pallet::VerificationStats::<Test>::contains_key(
				retired, 1
			));
			assert!(!RetiredVersions::<Test>::contains_key(retired, 1));
			assert!(ActiveCircuitVersion::<Test>::get(retired).is_none());
		});
	}

	/// The guard that makes this call safe: a circuit the runtime still
	/// implements can never be purged, no matter what storage holds.
	#[test]
	fn purge_circuit_rejects_live_circuits() {
		new_test_ext().execute_with(|| {
			for cid in [
				CircuitId::TRANSFER,
				CircuitId::UNSHIELD,
				CircuitId::VALUE_PROOF,
			] {
				seed_circuit(cid, 1, TRANSFER_PUBLIC_INPUTS);
				assert_noop!(
					ZkVerifier::purge_circuit(root().into(), cid),
					Error::<Test>::CircuitStillInUse
				);
				assert!(VerificationKeys::<Test>::get(cid, 1).is_some());
			}
		});
	}

	/// `circuit_id.0 as u8` would alias 257 onto TRANSFER(1). Ids past `u8::MAX`
	/// must be rejected outright rather than truncated into the lookup.
	#[test]
	fn purge_circuit_rejects_ids_above_u8_max() {
		new_test_ext().execute_with(|| {
			for id in [256u32, 257, 261, 262, u32::MAX] {
				let cid = CircuitId(id);
				seed_circuit(cid, 1, 2);
				assert_noop!(
					ZkVerifier::purge_circuit(root().into(), cid),
					Error::<Test>::CircuitStillInUse
				);
				assert!(VerificationKeys::<Test>::get(cid, 1).is_some());
			}
		});
	}

	/// Purging must work on a circuit reached the only way an operator can reach
	/// one: through the extrinsics. `register_verification_key` activates the
	/// first version it stores and nothing else ever clears that pointer, so a
	/// call that required `ActiveCircuitVersion` to be empty could never fire.
	#[test]
	fn purge_circuit_works_on_a_circuit_built_through_extrinsics() {
		new_test_ext().execute_with(|| {
			let retired = CircuitId(5);
			assert_ok!(ZkVerifier::register_verification_key(
				root().into(),
				retired,
				1,
				real_vk(2)
			));
			// The registration activated version 1, and no extrinsic can undo that:
			// `retire_version` and `remove_verification_key` both refuse the active
			// version, and `set_active_version` only ever overwrites.
			assert_eq!(ActiveCircuitVersion::<Test>::get(retired), Some(1));
			assert_noop!(
				ZkVerifier::retire_version(root().into(), retired, 1),
				Error::<Test>::CannotRetireActiveVersion
			);
			assert_noop!(
				ZkVerifier::remove_verification_key(root().into(), retired, 1),
				Error::<Test>::CannotRemoveActiveVersion
			);

			assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

			assert!(VerificationKeys::<Test>::get(retired, 1).is_none());
			assert!(ActiveCircuitVersion::<Test>::get(retired).is_none());
		});
	}

	#[test]
	fn purge_circuit_requires_root() {
		new_test_ext().execute_with(|| {
			let retired = CircuitId(5);
			seed_circuit(retired, 1, 2);
			assert_err!(
				ZkVerifier::purge_circuit(signed().into(), retired),
				sp_runtime::DispatchError::BadOrigin
			);
			assert!(VerificationKeys::<Test>::get(retired, 1).is_some());
		});
	}

	#[test]
	fn purge_circuit_fails_when_nothing_stored() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ZkVerifier::purge_circuit(root().into(), CircuitId(5)),
				Error::<Test>::CircuitHasNoStorage
			);
		});
	}

	/// The declared weight is charged upfront, so a purge at the version cap must
	/// leave room for the rest of the block. The runtime allows 2s of compute and
	/// this call currently costs ~33ms of it; the 10% bound is loose enough not to
	/// break on a re-benchmark but tight enough to catch a coefficient that grows
	/// by an order of magnitude.
	#[test]
	fn purge_circuit_at_the_cap_fits_in_a_block() {
		use crate::weights::WeightInfo;
		use frame_support::weights::constants::WEIGHT_REF_TIME_PER_MILLIS;

		let worst =
			<Test as Config>::WeightInfo::purge_circuit(Pallet::<Test>::MAX_VERSIONS_PER_CIRCUIT);
		// Matches MAXIMUM_BLOCK_WEIGHT in the runtime.
		let block = 2_000u64 * WEIGHT_REF_TIME_PER_MILLIS;
		assert!(
			worst.ref_time() < block / 10,
			"purge_circuit at the cap costs {}ms of a 2000ms block",
			worst.ref_time() / WEIGHT_REF_TIME_PER_MILLIS
		);
	}

	/// An active pointer with no versions behind it is the one thing left to
	/// clear, so the "nothing stored" guard must not treat it as nothing — and
	/// the event must not report it as having cleared nothing either.
	#[test]
	fn purge_circuit_clears_a_stranded_active_pointer() {
		new_test_ext().execute_with(|| {
			let retired = CircuitId(5);
			ActiveCircuitVersion::<Test>::insert(retired, 1);

			assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

			assert!(ActiveCircuitVersion::<Test>::get(retired).is_none());
			assert!(has_event(Event::CircuitPurged {
				circuit_id: retired,
				removed: 1
			}));
		});
	}

	/// `removed` counts entries across every map, not versions. Maps whose
	/// version sets differ would under-report if the count were a max, leaving an
	/// indexer reconciling against a figure smaller than what actually went away.
	#[test]
	fn purge_circuit_reports_entries_not_versions() {
		new_test_ext().execute_with(|| {
			let retired = CircuitId(5);
			// One version with a key + hash, plus an orphan hash at another version
			// and a retired marker at a third: 2 + 1 + 1 entries, spread over three
			// distinct versions, none of which is a max of the per-map counts.
			seed_circuit(retired, 1, 2);
			crate::pallet::VkHashes::<Test>::insert(retired, 2, [0x22u8; 32]);
			RetiredVersions::<Test>::insert(retired, 3, ());

			assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

			// keys(1) + hashes(2) + stats(0) + retired(1) + active pointer(1)
			assert!(has_event(Event::CircuitPurged {
				circuit_id: retired,
				removed: 5
			}));
		});
	}

	#[test]
	fn purge_circuit_removes_every_version() {
		new_test_ext().execute_with(|| {
			let retired = CircuitId(5);
			for version in 1..=3u32 {
				seed_circuit(retired, version, 2);
			}

			assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

			assert!(
				VerificationKeys::<Test>::iter_key_prefix(retired)
					.next()
					.is_none()
			);
		});
	}

	/// An earlier `remove_verification_key` used to strand hashes and stats with
	/// no `VerificationKeys` row to enumerate them. Clearing by prefix collects
	/// them; iterating one map's versions would not.
	#[test]
	fn purge_circuit_clears_orphaned_satellite_entries() {
		new_test_ext().execute_with(|| {
			let retired = CircuitId(5);
			crate::pallet::VkHashes::<Test>::insert(retired, 1, [0x11u8; 32]);
			crate::pallet::VerificationStats::<Test>::insert(
				retired,
				1,
				crate::types::VerificationStatistics::default(),
			);
			RetiredVersions::<Test>::insert(retired, 1, ());
			// Deliberately no VerificationKeys entry.

			assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

			assert!(crate::pallet::VkHashes::<Test>::get(retired, 1).is_none());
			assert!(!crate::pallet::VerificationStats::<Test>::contains_key(
				retired, 1
			));
			assert!(!RetiredVersions::<Test>::contains_key(retired, 1));
		});
	}

	/// After a purge the circuit must be invisible to the runtime API, which is
	/// what keeps explorers from listing a circuit the runtime cannot serve.
	#[test]
	fn purged_circuit_disappears_from_runtime_api() {
		new_test_ext().execute_with(|| {
			let retired = CircuitId(5);
			seed_circuit(retired, 1, 2);
			seed_circuit(CircuitId::TRANSFER, 1, TRANSFER_PUBLIC_INPUTS);

			assert_ok!(ZkVerifier::purge_circuit(root().into(), retired));

			let ids: Vec<u32> = ZkVerifier::runtime_api_get_all_circuit_versions()
				.into_iter()
				.map(|info| info.circuit_id)
				.collect();
			assert!(!ids.contains(&5));
			assert!(ids.contains(&CircuitId::TRANSFER.0));
		});
	}

	/// `remove_verification_key` must not strand the satellite maps either —
	/// that stranding is what made the orphan case above possible.
	#[test]
	fn remove_vk_also_clears_hash_and_stats() {
		new_test_ext().execute_with(|| {
			let cid = CircuitId::TRANSFER;
			seed_circuit(cid, 1, TRANSFER_PUBLIC_INPUTS);
			seed_circuit(cid, 2, TRANSFER_PUBLIC_INPUTS);
			ActiveCircuitVersion::<Test>::insert(cid, 1u32);
			crate::pallet::VerificationStats::<Test>::insert(
				cid,
				2,
				crate::types::VerificationStatistics::default(),
			);

			assert_ok!(ZkVerifier::remove_verification_key(root().into(), cid, 2));

			assert!(crate::pallet::VkHashes::<Test>::get(cid, 2).is_none());
			assert!(!crate::pallet::VerificationStats::<Test>::contains_key(
				cid, 2
			));
			// The active version is untouched.
			assert!(VerificationKeys::<Test>::get(cid, 1).is_some());
			assert!(crate::pallet::VkHashes::<Test>::get(cid, 1).is_some());
		});
	}
}
