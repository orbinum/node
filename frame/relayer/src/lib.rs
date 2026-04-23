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
//!   Only validator nodes (as determined by `T::IsValidator`) may register.
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

pub mod traits;
pub mod weights;

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
	use super::{RelayerInterface, WeightInfo};
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*, traits::Contains};
	use frame_system::pallet_prelude::*;
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

		/// Returns whether an account is currently a validator node.
		///
		/// Only accounts recognised as validators may call `register_relayer`.
		/// Wire this to a session-validator or Aura-authority check in the runtime.
		type IsValidator: frame_support::traits::Contains<Self::AccountId>;

		/// Origin allowed to update relay configuration (fee, selectors).
		/// Use `EnsureRoot` for testnets; a governance pallet for mainnet.
		type ManageOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Maximum number of ABI selectors in the whitelist.
		#[pallet::constant]
		type MaxAllowedSelectors: Get<u32>;

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
	/// Only validator nodes may have entries here.
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
		/// A validator node registered an EVM address.
		RelayerRegistered {
			evm_address: H160,
			account: T::AccountId,
		},
		/// A validator node unregistered its EVM address.
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
		/// Caller is not a validator node. Only validators may register as relayers.
		NotValidator,
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

		/// Register a substrate account as the owner of an EVM relay address.
		///
		/// Only validator nodes (as determined by `T::IsValidator`) may call this.
		/// Non-validator accounts are rejected with `NotValidator`.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::register_relayer())]
		pub fn register_relayer(origin: OriginFor<T>, evm_address: H160) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(T::IsValidator::contains(&who), Error::<T>::NotValidator);
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

		/// Remove the caller's EVM address from the relay registry.
		///
		/// The caller must be a registered validator node.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::unregister_relayer())]
		pub fn unregister_relayer(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let evm_address = RelayerByAccount::<T>::get(&who).ok_or(Error::<T>::NotRegistered)?;
			RelayerRegistry::<T>::remove(evm_address);
			RelayerByAccount::<T>::remove(&who);
			Self::deposit_event(Event::RelayerUnregistered {
				evm_address,
				account: who,
			});
			Ok(())
		}

		/// Standalone claim for accrued relay fees (planck accounting only).
		///
		/// Decrements `PendingRelayerFees` without performing the actual token
		/// transfer.  Validators should prefer
		/// `pallet-shielded-pool::claim_shielded_fees`, which inserts a private
		/// note into the Merkle tree.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::claim_relay_fees())]
		pub fn claim_relay_fees(
			origin: OriginFor<T>,
			asset_id: u32,
			amount: u128,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let pending = PendingRelayerFees::<T>::get(&who, asset_id);
			ensure!(pending >= amount, Error::<T>::InsufficientPendingFees);
			PendingRelayerFees::<T>::mutate(&who, asset_id, |b| {
				*b = b.saturating_sub(amount);
			});
			Self::deposit_event(Event::RelayFeesConsumed {
				relayer: who,
				asset_id,
				amount,
			});
			Ok(())
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
