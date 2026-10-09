//! # ZK Verifier Pallet
//!
//! On-chain Groth16 proof verification with versioned verification keys.
//!
//! ## Responsibilities
//!
//! - Store and version verification keys per circuit (Root-gated extrinsics).
//! - Expose [`ZkVerifierPort`] — the only public interface other pallets use.
//! - Encode spend statements into public inputs ([`encoding`]) for the layout of
//!   the key they are checked against.
//! - Verify proofs and track per-circuit statistics ([`verifier`]).
//!
//! ## Key rotation
//!
//! A spend circuit's keys are memo-bound or, for a transfer, cross-tree (one
//! root per input); shield has one layout. Rotation is done by Root: register
//! the new version, `set_active_version`, then `retire_version` the old one.
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
#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub use port::{ShieldStatement, TransferStatement, UnshieldStatement, ZkVerifierPort};
pub use types::{
	CircuitId, CircuitVersionInfo, ProofSystem, VerificationKeyInfo, VerificationStatistics,
	VkBytes, VkEntry, VkVersionHash,
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
	/// - v1: the retired `private_link` circuit (id 5) is dropped.
	///
	/// No migration code remains: every live chain is at v1 and a new chain starts
	/// there via genesis.
	pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Largest proof accepted, in bytes.
		#[pallet::constant]
		type MaxProofSize: Get<u32>;
		/// Most public inputs `verify_proof` takes.
		#[pallet::constant]
		type MaxPublicInputs: Get<u32>;
		/// Benchmarked weights.
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
		/// One key per circuit, registered as version 1 and activated.
		pub verification_keys: Vec<(CircuitId, Vec<u8>)>,
		#[serde(skip)]
		pub _phantom: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			for (circuit_id, vk_bytes) in &self.verification_keys {
				let key_data: VkBytes = vk_bytes
					.clone()
					.try_into()
					.expect("Genesis VK exceeds the maximum key size");
				Pallet::<T>::register_vk(*circuit_id, Pallet::<T>::FIRST_VERSION, key_data, true)
					.expect("Genesis VK must deserialize and match its circuit's arity");
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
			// A `const` block: both operands are `cfg!`, so a bad feature set fails
			// the build, not the runtime check (what clippy::assertions_on_constants
			// asks for).
			const {
				assert!(
					!cfg!(feature = "skip-proof-verification")
						|| cfg!(feature = "runtime-benchmarks"),
					"pallet-zk-verifier compiled with `skip-proof-verification` but without \
					 `runtime-benchmarks`: ZK proof verification is disabled outside a \
					 benchmark build. This must never run on a live chain."
				);
			}
		}
	}

	// ── Events ────────────────────────────────────────────────────────────────

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A key was registered for `(circuit_id, version)`.
		VerificationKeyRegistered { circuit_id: CircuitId, version: u32 },
		/// `version` is now the circuit's active one.
		ActiveVersionSet { circuit_id: CircuitId, version: u32 },
		/// A version's key and its data were removed.
		VerificationKeyRemoved { circuit_id: CircuitId, version: u32 },
		/// A version stopped verifying; its data is kept.
		VersionRetired { circuit_id: CircuitId, version: u32 },
		/// A retired version verifies again.
		VersionUnretired { circuit_id: CircuitId, version: u32 },
		/// `verify_proof` accepted a proof.
		ProofVerified { circuit_id: CircuitId, version: u32 },
		/// `verify_proof` rejected a proof.
		ProofVerificationFailed { circuit_id: CircuitId, version: u32 },
		/// `count` keys were registered in one batch.
		BatchVerificationKeysRegistered { count: u32 },
		/// Every version of a retired circuit was purged from storage.
		CircuitPurged { circuit_id: CircuitId, removed: u32 },
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
		/// Refused when the key does not deserialize, its arity gives no admitted
		/// layout (a spend key is memo-bound or, for a transfer, cross-tree — never
		/// base), the version exists, or the circuit is at its version cap.
		///
		/// SECURITY INVARIANT: a note's circuit version is not bound into its
		/// commitment, so the submitter picks it freely. Every version of a circuit
		/// must therefore accept the same notes under rules at least as strict: a
		/// key rotation, its memo-bound variant, or its cross-tree variant (one root
		/// per input; the pool checks each is known). The pallet checks arity, not
		/// semantics: any other change takes a new circuit id, and a superseded
		/// version is retired with `retire_version`.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::register_verification_key())]
		pub fn register_verification_key(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
			verification_key: VkBytes,
		) -> DispatchResult {
			ensure_root(origin)?;
			Self::register_vk(circuit_id, version, verification_key, false)
		}

		/// Make `version` the circuit's active one (Root only).
		///
		/// Refused for a missing key, a retired version, or a key of a layout the
		/// pallet does not admit: wallets would prove against a key every proof
		/// then fails.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_active_version())]
		pub fn set_active_version(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
			version: u32,
		) -> DispatchResult {
			ensure_root(origin)?;
			let info = VerificationKeys::<T>::get(circuit_id, version)
				.ok_or(Error::<T>::VerificationKeyNotFound)?;
			ensure!(
				!RetiredVersions::<T>::contains_key(circuit_id, version),
				Error::<T>::UnsupportedCircuitVersion
			);
			Self::ensure_vk_arity(circuit_id, &info.key_data)?;

			Self::activate(circuit_id, version);
			Ok(())
		}

		/// Remove a version and all its data (Root only); never the active one.
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

		/// Verify a proof against caller-encoded inputs, under the circuit's active
		/// key (any signed origin).
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

			let (result, version) =
				verifier::verify_raw::<T>(circuit_id, None, &proof, raw_inputs)?;

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
				// Benchmarks feed proofs that never verify: skipping the error lets the
				// runner record the weight. Gated on `skip-proof-verification`, which
				// `integrity_test` keeps out of any non-benchmark build.
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
				Self::register_vk(
					entry.circuit_id,
					entry.version,
					entry.verification_key.clone(),
					entry.set_active,
				)?;
			}

			Self::deposit_event(Event::BatchVerificationKeysRegistered {
				count: entries.len() as u32,
			});
			Ok(())
		}

		/// Retire a version (Root only): it stops verifying, its data is kept.
		/// Never the active one.
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

		/// Undo `retire_version` (Root only).
		///
		/// The key is held to the registration rules, so one retired for being
		/// unsafe cannot come back.
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
			let info = VerificationKeys::<T>::get(circuit_id, version)
				.ok_or(Error::<T>::VerificationKeyNotFound)?;
			Self::ensure_vk_arity(circuit_id, &info.key_data)?;
			RetiredVersions::<T>::remove(circuit_id, version);
			Self::deposit_event(Event::VersionUnretired {
				circuit_id,
				version,
			});
			Ok(())
		}

		/// Erase every trace of a circuit the runtime no longer implements (Root
		/// only).
		///
		/// `retire_version` and `remove_verification_key` never touch the active
		/// version, so neither can retire a circuit whose last version is active.
		/// This call covers that gap, and only it.
		///
		/// 1. The id must be unknown to the runtime (`expected_public_inputs` is
		///    `None`).
		/// 2. Count every map's entries, plus a stale `ActiveCircuitVersion`.
		/// 3. Refuse a map wider than `MAX_VERSIONS_PER_CIRCUIT`.
		/// 4. Clear all five maps by prefix — so entries without a
		///    `VerificationKeys` row go too — and report the entries cleared.
		///
		/// `ActiveCircuitVersion` is cleared, not required empty: no extrinsic ever
		/// clears it, and an unknown id has no verification route whatever it says.
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::purge_circuit(Pallet::<T>::MAX_VERSIONS_PER_CIRCUIT))]
		pub fn purge_circuit(
			origin: OriginFor<T>,
			circuit_id: CircuitId,
		) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;

			// 1. Unknown id. One past 255 is refused: `as u8` would alias 257 onto 1.
			let id = u8::try_from(circuit_id.0).map_err(|_| Error::<T>::CircuitStillInUse)?;
			ensure!(
				orbinum_zk_verifier::expected_public_inputs(id).is_none(),
				Error::<T>::CircuitStillInUse
			);

			// 2. Count, by iterating: `clear_prefix`'s counters miss this block's
			// overlay writes. Summed per map, as nothing forces the maps to share a
			// version set.
			let per_map = [
				VerificationKeys::<T>::iter_key_prefix(circuit_id).count(),
				VkHashes::<T>::iter_key_prefix(circuit_id).count(),
				VerificationStats::<T>::iter_key_prefix(circuit_id).count(),
				RetiredVersions::<T>::iter_key_prefix(circuit_id).count(),
			];
			// A stale active pointer is an entry to clear too.
			let active_entries = usize::from(ActiveCircuitVersion::<T>::contains_key(circuit_id));
			let entries = per_map.iter().sum::<usize>().saturating_add(active_entries);

			ensure!(entries > 0, Error::<T>::CircuitHasNoStorage);
			// 3. Bound. The cap is per map, so the widest map bounds the clear; a
			// wider one was built outside `store_vk`.
			let widest = per_map.iter().copied().max().unwrap_or(0);
			ensure!(
				widest <= Self::MAX_VERSIONS_PER_CIRCUIT as usize,
				Error::<T>::TooManyVersions
			);

			// 4. Clear, in one pass: the count proved every prefix fits the cap.
			let _ = VerificationKeys::<T>::clear_prefix(circuit_id, u32::MAX, None);
			let _ = VkHashes::<T>::clear_prefix(circuit_id, u32::MAX, None);
			let _ = VerificationStats::<T>::clear_prefix(circuit_id, u32::MAX, None);
			let _ = RetiredVersions::<T>::clear_prefix(circuit_id, u32::MAX, None);
			ActiveCircuitVersion::<T>::remove(circuit_id);

			// Entries, not versions: the figure an indexer reconciles against.
			Self::deposit_event(Event::CircuitPurged {
				circuit_id,
				removed: entries as u32,
			});
			// Weighed by versions: the benchmark charges one read and four writes
			// per version, the cost of clearing all four maps.
			Ok(Some(T::WeightInfo::purge_circuit(widest as u32)).into())
		}
	}

	// ── Key rules ─────────────────────────────────────────────────────────────

	impl<T: Config> Pallet<T> {
		/// Upper bound on stored versions per circuit — keeps the versions DoubleMap
		/// and the runtime-API iteration provably bounded. Registration is Root-only,
		/// so this is operator-discipline, not an attacker limit.
		pub(crate) const MAX_VERSIONS_PER_CIRCUIT: u32 = 64;

		/// The version genesis registers.
		pub(crate) const FIRST_VERSION: u32 = 1;

		/// Validate and store a new key for `(circuit_id, version)`, then activate
		/// it if `set_active` or the circuit has no active version yet. Every
		/// registration path (extrinsics, genesis) goes through here.
		pub(crate) fn register_vk(
			circuit_id: CircuitId,
			version: u32,
			key_data: VkBytes,
			set_active: bool,
		) -> DispatchResult {
			ensure!(!key_data.is_empty(), Error::<T>::EmptyVerificationKey);
			Self::ensure_vk_arity(circuit_id, &key_data)?;
			// Never overwrite: a replaced key would silently change what verifies.
			ensure!(
				!VerificationKeys::<T>::contains_key(circuit_id, version),
				Error::<T>::CircuitAlreadyExists
			);
			Self::store_vk(circuit_id, version, key_data)?;
			Self::deposit_event(Event::VerificationKeyRegistered {
				circuit_id,
				version,
			});
			if set_active || ActiveCircuitVersion::<T>::get(circuit_id).is_none() {
				Self::activate(circuit_id, version);
			}
			Ok(())
		}

		/// Make `version` the one new spends of `circuit_id` are verified under.
		pub(crate) fn activate(circuit_id: CircuitId, version: u32) {
			ActiveCircuitVersion::<T>::insert(circuit_id, version);
			Self::deposit_event(Event::ActiveVersionSet {
				circuit_id,
				version,
			});
		}

		/// The rule every stored key is held to: it deserializes as a BN254 Groth16
		/// key and its arity gives an admitted layout
		/// ([`verifier::admitted_layout`]). Ids outside the known table are only
		/// checked to deserialize.
		fn ensure_vk_arity(circuit_id: CircuitId, key_data: &[u8]) -> DispatchResult {
			let arity = orbinum_zk_verifier::VerifyingKey::new(key_data.to_vec())
				.num_public_inputs()
				.map_err(|_| Error::<T>::InvalidVerificationKey)?;
			verifier::admitted_layout(circuit_id, arity)
				.map(|_| ())
				.ok_or(Error::<T>::InvalidVerificationKey.into())
		}

		/// Insert a validated VK for `(circuit_id, version)` and store its hash,
		/// within the per-circuit version cap.
		fn store_vk(circuit_id: CircuitId, version: u32, key_data: VkBytes) -> DispatchResult {
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
