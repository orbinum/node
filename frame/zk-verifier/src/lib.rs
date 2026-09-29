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
//! A known circuit's first version may use its base input layout; every later
//! version must be memo-bound. Rotation is done by Root: register the new
//! version, `set_active_version`, then `retire_version` the old one.
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

pub use port::{TransferStatement, UnshieldStatement, ZkVerifierPort};
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
			// `const` block: both operands are `cfg!`, so this resolves at compile time
			// and a bad feature combination fails the build rather than the runtime's
			// integrity check. Strictly stronger than asserting at runtime, and it is
			// what clippy::assertions_on_constants asks for.
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
		/// SECURITY INVARIANT: a new version of an EXISTING circuit id must accept
		/// the same notes under rules at least as strict: a key rotation of the same
		/// circuit, or its memo-bound variant (the same constraints plus
		/// `memo_hash`, recognised by arity — see `InputLayout`). A note's circuit
		/// version is NOT bound into its commitment, so the submitter picks the
		/// version freely; a version with weaker constraints at a known arity would
		/// let any note be spent under it. Any other semantic change MUST use a NEW
		/// circuit id. `ensure_vk_arity` enforces arity, NOT semantics — that is a
		/// governance responsibility. Retire a superseded version with
		/// `retire_version` (a v1 key binds neither memos nor the full recipient).
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
			// A retired version cannot verify: making it active would leave wallets
			// proving against a key every proof then fails.
			ensure!(
				!RetiredVersions::<T>::contains_key(circuit_id, version),
				Error::<T>::UnsupportedCircuitVersion
			);

			Self::activate(circuit_id, version);
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
		/// than iterating one map's versions, so satellite entries left without a
		/// `VerificationKeys` row are collected too.
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
		/// Upper bound on stored versions per circuit — keeps the versions DoubleMap
		/// and the runtime-API iteration provably bounded. Registration is Root-only,
		/// so this is operator-discipline, not an attacker limit.
		pub(crate) const MAX_VERSIONS_PER_CIRCUIT: u32 = 64;

		/// The version genesis registers, and the only version of a known circuit
		/// allowed the base input layout.
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
			Self::ensure_vk_arity(circuit_id, version, &key_data)?;
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

		/// Verify the VK deserializes as a BN254 Groth16 key and that its arity
		/// fits one of the circuit's input layouts (base or memo-bound).
		///
		/// For a known circuit, only [`Self::FIRST_VERSION`] may use the base
		/// layout: every later version must bind its memos and the full recipient.
		/// That keeps a v1 key from being registered again as "v2" — a rotation
		/// that would retire nothing but the version number.
		///
		/// Only ids in the known table carry an expected arity; the rest are
		/// checked to deserialize and nothing more. An id that does not fit a
		/// `u8` is rejected outright rather than truncated — `as u8` would alias
		/// 257 onto 1 and silently validate a key against the wrong circuit's
		/// arity. `purge_circuit` guards the same lookup the same way.
		fn ensure_vk_arity(circuit_id: CircuitId, version: u32, key_data: &[u8]) -> DispatchResult {
			use orbinum_zk_verifier::{
				InputLayout, VerifyingKey, expected_public_inputs, input_layout,
			};

			let id = u8::try_from(circuit_id.0).map_err(|_| Error::<T>::InvalidVerificationKey)?;

			let vk = VerifyingKey::new(key_data.to_vec());
			let arity = vk
				.num_public_inputs()
				.map_err(|_| Error::<T>::InvalidVerificationKey)?;

			let layout = input_layout(id, arity).ok_or(Error::<T>::InvalidVerificationKey)?;
			let known = expected_public_inputs(id).is_some();
			ensure!(
				!(known && version != Self::FIRST_VERSION && layout == InputLayout::Base),
				Error::<T>::InvalidVerificationKey
			);
			Ok(())
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
