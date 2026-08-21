#![cfg_attr(not(feature = "std"), no_std)]

//! # Pallet Relayer
//!
//! Centralizes all on-chain relay concerns:
//!
//! - **Configuration**: `MinRelayFee` and `AllowedSelectors` — updatable by
//!   governance, consumed by the node-native EVM relay via
//!   `ShieldedPoolRuntimeApi::relay_config()`.
//! - **Registry**: EVM address → AccountId binding so fee attribution is
//!   unambiguous even when the EVM and substrate keys differ.
//!   Self-service: an approved validator registers its own address via
//!   `register_relayer`, and the binding is cleared when it leaves the set.
//! - **Fee accounting**: `PendingRelayerFees` tracks accrued relay fees per
//!   (AccountId, asset_id).  Other pallets (pallet-shielded-pool) call
//!   `T::Relayer::accumulate_relay_fee()` and `T::Relayer::consume_relay_fee()`
//!   via the [`RelayerInterface`] trait instead of touching storage directly.
//!
//! ## Module layout
//!
//! | File | Responsibility |
//! |------|----------------|
//! | `traits.rs`       | `RelayerInterface` — public port consumed by other pallets |
//! | `weights.rs`      | `WeightInfo` trait + `SubstrateWeight<T>` + unit (`()`) impl |
//! | `benchmarking.rs` | FRAME benchmarks (`runtime-benchmarks` feature) |
//! | `lib.rs`          | FRAME pallet: Config, Storage, Events, Errors, Extrinsics |
//! | `mock.rs`         | Test runtime (`#[cfg(test)]`) |
//! | `tests/`          | Integration tests split by concern |
//!
//! ## Integration with pallet-shielded-pool
//!
//! ```text
//! pallet-shielded-pool::Config {
//!     type Relayer: pallet_relayer::RelayerInterface<AccountId = Self::AccountId>;
//! }
//! // In runtime:
//! type Relayer = pallet_relayer::Pallet<Runtime>;
//! ```

pub mod evm_proof;
#[cfg(any(test, feature = "runtime-benchmarks"))]
pub mod test_signing;
pub mod traits;
pub mod weights;

pub use evm_proof::EvmSignature;
pub use pallet::*;
pub use traits::RelayerInterface;
pub use weights::WeightInfo;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

// ─────────────────────────────────────────────────────────────────────────────
// FRAME pallet
// ─────────────────────────────────────────────────────────────────────────────

#[frame_support::pallet]
pub mod pallet {
	use super::{
		RelayerInterface, WeightInfo,
		evm_proof::{self, EvmSignature},
	};
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
	use frame_system::pallet_prelude::*;
	use pallet_validator_set::ValidatorSetInterface;
	use sp_core::H160;
	use sp_std::vec::Vec;

	// ── Config ────────────────────────────────────────────────────────────────

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Provides the current block author (Aura / BABE author).
		type BlockAuthor: Get<Option<Self::AccountId>>;

		/// Initial value for `MinRelayFee` storage.
		/// Overridable at runtime by `set_min_relay_fee` (governance/sudo).
		#[pallet::constant]
		type DefaultMinRelayFee: Get<u128>;

		/// Origin allowed to update relay configuration (fee, selectors).
		/// Use `EnsureRoot` for testnets; a governance pallet for mainnet.
		type ManageOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Maximum number of ABI selectors in the whitelist.
		#[pallet::constant]
		type MaxAllowedSelectors: Get<u32>;

		/// Gate for `register_relayer`: only accounts in the active validator
		/// set may bind an EVM relay address.
		type ValidatorSet: ValidatorSetInterface<Self::AccountId>;

		type WeightInfo: WeightInfo;
	}

	// ── Default values ────────────────────────────────────────────────────────

	#[pallet::type_value]
	pub fn DefaultMinRelayFeeValue<T: Config>() -> u128 {
		T::DefaultMinRelayFee::get()
	}

	// ── Storage ───────────────────────────────────────────────────────────────

	/// Minimum relay fee (planck).  Initialised from `T::DefaultMinRelayFee`;
	/// updatable by `ManageOrigin` via `set_min_relay_fee`.
	#[pallet::storage]
	pub type MinRelayFee<T: Config> = StorageValue<_, u128, ValueQuery, DefaultMinRelayFeeValue<T>>;

	/// ABI selector whitelist.  Empty = use built-in defaults (resolved in
	/// the Runtime API impl so the relay always has a non-empty list).
	#[pallet::storage]
	pub type AllowedSelectors<T: Config> =
		StorageValue<_, BoundedVec<[u8; 4], T::MaxAllowedSelectors>, ValueQuery>;

	/// On-chain registry: EVM address → substrate AccountId.
	#[pallet::storage]
	pub type RelayerRegistry<T: Config> =
		StorageMap<_, Blake2_128Concat, H160, T::AccountId, OptionQuery>;

	/// Reverse index: AccountId → registered EVM address.
	#[pallet::storage]
	pub type RelayerByAccount<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, H160, OptionQuery>;

	/// Accumulated relay fees per (AccountId, asset_id) in planck.
	#[pallet::storage]
	pub type PendingRelayerFees<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Blake2_128Concat,
		u32,  // asset_id
		u128, // amount in planck
		ValueQuery,
	>;

	// ── Events ────────────────────────────────────────────────────────────────

	#[pallet::event]
	#[pallet::generate_deposit(pub(crate) fn deposit_event)]
	pub enum Event<T: Config> {
		/// `ManageOrigin` updated the minimum relay fee.
		MinRelayFeeUpdated { new_fee: u128 },
		/// `ManageOrigin` updated the allowed selector whitelist.
		AllowedSelectorsUpdated { count: u32 },
		/// A validator registered its EVM relay address.
		RelayerRegistered {
			evm_address: H160,
			account: T::AccountId,
		},
		/// A relayer mapping was removed, either by the owner calling
		/// `unregister_relayer` or by the account leaving the validator set.
		RelayerUnregistered {
			evm_address: H160,
			account: T::AccountId,
		},
		/// Relay fee accrued for a block author during extrinsic processing.
		RelayFeeAccumulated {
			relayer: T::AccountId,
			asset_id: u32,
			amount: u128,
		},
		/// Relay fees were marked as consumed (by `claim_shielded_fees`).
		RelayFeesConsumed {
			relayer: T::AccountId,
			asset_id: u32,
			amount: u128,
		},
	}

	// ── Errors ────────────────────────────────────────────────────────────────

	#[pallet::error]
	pub enum Error<T> {
		/// No EVM address registered for this account.
		NotRegistered,
		/// The EVM address already has a registered AccountId.
		AlreadyRegistered,
		/// The calling account already has an active EVM registration.
		/// Call `unregister_relayer` first.
		AccountAlreadyRegistered,
		/// Requested amount exceeds pending relay fees.
		InsufficientPendingFees,
		/// Selector list exceeds `MaxAllowedSelectors`.
		TooManySelectors,
		/// Only accounts in the active validator set may register a relay address.
		NotValidator,
		/// The EVM address is not usable as a relay identity (zero, or reserved).
		InvalidEvmAddress,
		/// The signature does not prove control of the EVM address being claimed.
		BadEvmSignature,
	}

	// ── Pallet core ───────────────────────────────────────────────────────────

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	// ── Extrinsics ────────────────────────────────────────────────────────────

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Update the minimum relay fee.
		///
		/// Requires `ManageOrigin`. The new value takes effect immediately.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_min_relay_fee())]
		pub fn set_min_relay_fee(origin: OriginFor<T>, fee: u128) -> DispatchResult {
			T::ManageOrigin::ensure_origin(origin)?;
			MinRelayFee::<T>::put(fee);
			Self::deposit_event(Event::MinRelayFeeUpdated { new_fee: fee });
			Ok(())
		}

		/// Replace the allowed ABI selector whitelist.
		///
		/// Pass an empty `Vec` to fall back to the Runtime API built-in defaults.
		/// Requires `ManageOrigin`.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::set_allowed_selectors(selectors.len() as u32))]
		pub fn set_allowed_selectors(
			origin: OriginFor<T>,
			selectors: Vec<[u8; 4]>,
		) -> DispatchResult {
			T::ManageOrigin::ensure_origin(origin)?;
			let bounded: BoundedVec<[u8; 4], T::MaxAllowedSelectors> = selectors
				.try_into()
				.map_err(|_| Error::<T>::TooManySelectors)?;
			let count = bounded.len() as u32;
			AllowedSelectors::<T>::put(bounded);
			Self::deposit_event(Event::AllowedSelectorsUpdated { count });
			Ok(())
		}

		/// Register the caller's EVM relay address.
		///
		/// Three things must hold:
		///
		/// 1. the caller is in the active validator set (`NotValidator`);
		/// 2. `signature` proves the caller holds the EVM private key
		///    (`BadEvmSignature`) — without this an approved validator could claim
		///    a rival's public relay address and divert its fees;
		/// 3. the address and the account are both unclaimed (`AlreadyRegistered`,
		///    `AccountAlreadyRegistered`).
		///
		/// The address is chosen freely by the operator; it must match the key the
		/// node signs relay transactions with (keystore type `evmr`).
		///
		/// See [`crate::evm_proof`] for the exact bytes to sign.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::register_relayer())]
		pub fn register_relayer(
			origin: OriginFor<T>,
			evm_address: H160,
			signature: EvmSignature,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(
				T::ValidatorSet::is_active_validator(&who),
				Error::<T>::NotValidator
			);
			ensure!(
				evm_proof::is_usable_relay_address(&evm_address),
				Error::<T>::InvalidEvmAddress
			);
			ensure!(
				Self::verify_evm_ownership(&who, &evm_address, &signature),
				Error::<T>::BadEvmSignature
			);
			ensure!(
				!RelayerRegistry::<T>::contains_key(evm_address),
				Error::<T>::AlreadyRegistered
			);
			ensure!(
				!RelayerByAccount::<T>::contains_key(&who),
				Error::<T>::AccountAlreadyRegistered
			);
			RelayerRegistry::<T>::insert(evm_address, who.clone());
			RelayerByAccount::<T>::insert(who.clone(), evm_address);
			Self::deposit_event(Event::RelayerRegistered {
				evm_address,
				account: who,
			});
			Ok(())
		}

		/// Remove an EVM relay address mapping.
		///
		/// The caller (account owner) may remove their own registration.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::unregister_relayer())]
		pub fn unregister_relayer(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::clear_relayer(&who).ok_or(Error::<T>::NotRegistered)?;
			Ok(())
		}
	}

	// ── Internal helpers ──────────────────────────────────────────────────────

	impl<T: Config> Pallet<T> {
		/// Drop any EVM binding held by `who`, in both directions, returning the
		/// address that was removed. `None` when the account had no registration.
		///
		/// Infallible and idempotent: the runtime calls it when a validator leaves
		/// the set, and removal from the set must never be blocked by cleanup.
		///
		/// `PendingRelayerFees` is deliberately left untouched — those fees were
		/// already earned and stay claimable via `claim_shielded_fees`.
		pub fn clear_relayer(who: &T::AccountId) -> Option<H160> {
			let evm_address = RelayerByAccount::<T>::take(who)?;
			RelayerRegistry::<T>::remove(evm_address);
			Self::deposit_event(Event::RelayerUnregistered {
				evm_address,
				account: who.clone(),
			});
			Some(evm_address)
		}

		/// Check that `signature` was produced by the key behind `evm_address`
		/// over the binding message for `who` on this chain.
		fn verify_evm_ownership(
			who: &T::AccountId,
			evm_address: &H160,
			signature: &EvmSignature,
		) -> bool {
			let digest = evm_proof::binding_digest(
				who.encode().as_slice(),
				evm_address,
				&evm_proof::genesis_hash::<T>(),
			);
			evm_proof::recover_evm_address(signature, &digest) == Some(*evm_address)
		}
	}

	// ── RelayerInterface implementation ───────────────────────────────────────

	impl<T: Config> RelayerInterface for Pallet<T> {
		type AccountId = T::AccountId;

		fn resolve_relayer(evm_address: &sp_core::H160) -> Option<T::AccountId> {
			RelayerRegistry::<T>::get(evm_address)
		}

		fn min_relay_fee() -> u128 {
			MinRelayFee::<T>::get()
		}

		fn allowed_selectors() -> Vec<[u8; 4]> {
			AllowedSelectors::<T>::get().into_inner()
		}

		fn block_author() -> Option<T::AccountId> {
			T::BlockAuthor::get()
		}

		fn accumulate_relay_fee(author: &T::AccountId, asset_id: u32, amount: u128) {
			PendingRelayerFees::<T>::mutate(author, asset_id, |b| {
				*b = b.saturating_add(amount);
			});
			Self::deposit_event(Event::RelayFeeAccumulated {
				relayer: author.clone(),
				asset_id,
				amount,
			});
		}

		fn pending_relay_fees(who: &T::AccountId, asset_id: u32) -> u128 {
			PendingRelayerFees::<T>::get(who, asset_id)
		}

		fn consume_relay_fee(
			who: &T::AccountId,
			asset_id: u32,
			amount: u128,
		) -> frame_support::dispatch::DispatchResult {
			let pending = PendingRelayerFees::<T>::get(who, asset_id);
			ensure!(pending >= amount, Error::<T>::InsufficientPendingFees);
			PendingRelayerFees::<T>::mutate(who, asset_id, |b| {
				*b = b.saturating_sub(amount);
			});
			Self::deposit_event(Event::RelayFeesConsumed {
				relayer: who.clone(),
				asset_id,
				amount,
			});
			Ok(())
		}

		fn registered_evm_address(who: &T::AccountId) -> Option<sp_core::H160> {
			RelayerByAccount::<T>::get(who)
		}
	}
}
