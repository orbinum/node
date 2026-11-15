// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Private staking: nomination pools joined with shielded notes.
//!
//! A pool's root opens it to private members (`set_private`). The pallet then
//! holds one membership in it, `m_P` (a keyless account per pool), that gathers
//! every private member's stake, and issues a pallet-backed asset, `sP`, whose
//! notes are shares of that membership. Nobody signs anything:
//!
//! - **Enter**: a bound spend of an ORB note pays `m_P`, which bonds it into the
//!   pool at once. The entry keeps the pool points its bond issued; its shares
//!   are minted once the pool has compounded the era the entry came in, so an
//!   entry never collects a reward its stake did not earn, and shares a slash
//!   with everyone while it waits.
//! - **Exit**: a bound spend of an `sP` note burns its shares and unbonds their
//!   value from `m_P` (the nominator unbonding time). When it unlocks, an ORB
//!   note is minted: its value, scaled down if the unbonding stake was slashed.
//! - **Compounding**: once per era, after `pallet-auto-payout` has paid the
//!   previous one, `m_P`'s rewards are bonded back, raising every share's value.
//!
//! Every output is a note the chain computes from a one-time key and blinding the
//! action carried (`pallet_shielded_pool::mint_note`). A share's value is
//! `(value of m_P's points not held by pending entries + V) / (supply + V)`,
//! with a virtual offset `V` against inflating the first shares, rounded in the
//! pool's favour. Only this pallet moves `m_P`'s stake: the runtime's call filter
//! refuses anyone else's unbond or withdrawal of a private member
//! (`configs::staking::private::PrivateMembersStay`).
//!
//! ORB withdrawn for outputs not paid yet is held in `m_P` as `Escrow`, which
//! compounding leaves alone. An output that cannot be paid stays queued.
//!
//! Public per action: the pool and the amount. Hidden: who enters or exits, and
//! every member's balance and history.

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::{
		pallet_prelude::*,
		traits::{Currency, ExistenceRequirement},
		weights::WeightMeter,
		PalletId,
	};
	use frame_system::pallet_prelude::*;
	use pallet_nomination_pools::{self as pools, BondExtra, PoolId, PoolState};
	use pallet_shielded_pool::{
		self as shielded,
		types::{Funding, NATIVE_ASSET_ID},
		Commitment,
	};
	use sp_runtime::{
		helpers_128bit::multiply_by_rational_with_rounding,
		traits::{AccountIdConversion, StaticLookup},
		Perquintill, Rounding, SaturatedConversion,
	};
	use sp_staking::{EraIndex, StakingInterface};

	#[pallet::config]
	pub trait Config:
		frame_system::Config<RuntimeEvent: From<Event<Self>>>
		+ pools::Config
		+ shielded::Config
		+ pallet_staking_async::Config
		+ pallet_auto_payout::Config
	{
		/// Derives each pool's member account `m_P` and tags the pallet's assets.
		#[pallet::constant]
		type PrivateStakingId: Get<PalletId>;
		/// Most entries, exits or fees per queue page.
		#[pallet::constant]
		type MaxQueue: Get<u32>;
		/// Most pages of a pool's entry queue for one era. Exits and fees take
		/// any number: none is ever refused for room.
		#[pallet::constant]
		type MaxPages: Get<u32>;
		/// The virtual value and shares added to every price (`V = S`), in
		/// planck: inflating the first shares costs at least this much.
		#[pallet::constant]
		type VirtualOffset: Get<u128>;
		/// The smallest private entry until governance sets another.
		type DefaultMinEntry: Get<u128>;
		/// Sets the smallest private entry.
		type MinEntryOrigin: EnsureOrigin<Self::RuntimeOrigin>;
		/// Most of `on_idle`'s leftover weight the pallet takes per block.
		#[pallet::constant]
		type MaxIdleWeight: Get<Weight>;
	}

	/// A pool open to private members, and its shares.
	#[derive(Clone, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
	pub struct PrivatePool {
		/// The `sP` asset in the shielded pool.
		pub asset_id: u32,
		/// Whether new entries are taken. Exits never close.
		pub enabled: bool,
		/// `sP` in existence: notes, and fees not yet redeemed.
		pub supply: u128,
		/// The last era whose rewards were compounded.
		pub compounded_era: Option<EraIndex>,
		/// Set once the pool is destroying: what the shares left are worth.
		pub wind_down: Option<WindDown>,
	}

	/// A destroying pool's shares, fixed in value once `m_P` has unbonded.
	#[derive(
		Clone,
		Copy,
		Default,
		PartialEq,
		Eq,
		Encode,
		Decode,
		MaxEncodedLen,
		TypeInfo,
		Debug
	)]
	pub struct WindDown {
		/// What the shares left are worth.
		pub value: u128,
		/// The part of `value` already in `m_P`'s free balance (in `Escrow`).
		pub liquid: u128,
		/// When the unbonded rest unlocks.
		pub unlock_era: EraIndex,
		/// Whether the rest was withdrawn: `value` is then all liquid.
		pub withdrawn: bool,
	}

	/// An entry waiting for its shares: the pool points its bond issued.
	#[derive(Clone, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
	pub struct Entry {
		pub points: u128,
		/// The ORB it brought, for the record.
		pub value: u128,
		/// The fewest shares it takes: fewer at its price, and it is refunded.
		pub min_shares: u128,
		pub owner_pk: [u8; 32],
		pub blinding: [u8; 32],
	}

	/// An exit waiting to unlock: the ORB it was promised, and how much of it is
	/// already held in `Escrow` (the rest is scaled by what the unbonding pays).
	#[derive(Clone, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
	pub struct Pending {
		pub value: u128,
		pub funded: u128,
		pub owner_pk: [u8; 32],
		pub blinding: [u8; 32],
	}

	/// Spend fees redeemed for a validator, paid as an exit is.
	#[derive(Clone, PartialEq, Eq, Encode, Decode, MaxEncodedLen, TypeInfo, Debug)]
	pub struct FeeExit<AccountId> {
		pub validator: AccountId,
		pub value: u128,
		pub funded: u128,
	}

	/// What a bound spend asks of private staking. Its encoding is bound by the
	/// proof, so the note it mints cannot be redirected.
	#[derive(
		Clone,
		PartialEq,
		Eq,
		Encode,
		Decode,
		DecodeWithMemTracking,
		MaxEncodedLen,
		TypeInfo,
		Debug
	)]
	pub enum Action {
		/// Join `pool_id` with an ORB note; its shares go to `owner_pk`. If they
		/// would be fewer than `min_shares` when minted, the ORB is refunded to
		/// `owner_pk` instead, once its unbonding unlocks.
		#[codec(index = 0)]
		Enter {
			pool_id: PoolId,
			owner_pk: [u8; 32],
			blinding: [u8; 32],
			min_shares: u128,
		},
		/// Leave `pool_id` with an `sP` note; the ORB goes to `owner_pk`. Refused
		/// if the shares are worth less than `min_value` now.
		#[codec(index = 1)]
		Exit {
			pool_id: PoolId,
			owner_pk: [u8; 32],
			blinding: [u8; 32],
			min_value: u128,
		},
	}

	/// A queue page: the era it belongs to and its page number.
	pub type Slot = (EraIndex, u32);

	/// The pages of one queue of an unlock era: `next..end` hold items.
	#[derive(
		Clone,
		Copy,
		Default,
		PartialEq,
		Eq,
		Encode,
		Decode,
		MaxEncodedLen,
		TypeInfo,
		Debug
	)]
	pub struct Pages {
		pub next: u32,
		pub end: u32,
	}

	/// The outputs of one unlock era: their pages, what they were promised and
	/// is not escrowed (what the withdrawal must pay), and, once withdrawn, the
	/// share of it the withdrawal paid (below one only when the unbonding stake
	/// was slashed).
	#[derive(
		Clone,
		Default,
		PartialEq,
		Eq,
		Encode,
		Decode,
		MaxEncodedLen,
		TypeInfo,
		Debug
	)]
	pub struct Unlock {
		pub exits: Pages,
		pub fees: Pages,
		pub owed: u128,
		pub paid: Option<Perquintill>,
	}

	/// What redeeming shares releases: their value, the part already escrowed, the
	/// era it unlocks, and the pool points to unbond (none while winding down).
	pub struct Redeem {
		pub value: u128,
		pub funded: u128,
		pub unlock_era: EraIndex,
		pub points: u128,
	}

	impl Redeem {
		fn fixed(value: u128, funded: u128, unlock_era: EraIndex) -> Self {
			Self {
				value,
				funded,
				unlock_era,
				points: 0,
			}
		}
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	pub type Pools<T> = StorageMap<_, Twox64Concat, PoolId, PrivatePool, OptionQuery>;

	/// The pool an `sP` asset belongs to.
	#[pallet::storage]
	pub type AssetPool<T> = StorageMap<_, Twox64Concat, u32, PoolId, OptionQuery>;

	/// Every `m_P`: the accounts plain unshield must not pay, and that nobody but
	/// this pallet unbonds.
	#[pallet::storage]
	pub type Members<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, PoolId, OptionQuery>;

	/// Pool points of `m_P` held by entries whose shares are not minted yet.
	#[pallet::storage]
	pub type EntryPoints<T> = StorageMap<_, Twox64Concat, PoolId, u128, ValueQuery>;

	/// Entries waiting for their era to be compounded: `(pool, (era entered, page))`.
	#[pallet::storage]
	pub type Entries<T: Config> = StorageDoubleMap<
		_,
		Twox64Concat,
		PoolId,
		Twox64Concat,
		Slot,
		BoundedVec<Entry, T::MaxQueue>,
		ValueQuery,
	>;

	/// Exits waiting to unlock: `(pool, (unlock era, page))`, pages as in [`Unlocks`].
	#[pallet::storage]
	pub type Exits<T: Config> = StorageDoubleMap<
		_,
		Twox64Concat,
		PoolId,
		Twox64Concat,
		Slot,
		BoundedVec<Pending, T::MaxQueue>,
		ValueQuery,
	>;

	/// Redeemed spend fees waiting to unlock: `(pool, (unlock era, page))`, pages as
	/// in [`Unlocks`].
	#[pallet::storage]
	pub type FeeExits<T: Config> = StorageDoubleMap<
		_,
		Twox64Concat,
		PoolId,
		Twox64Concat,
		Slot,
		BoundedVec<FeeExit<T::AccountId>, T::MaxQueue>,
		ValueQuery,
	>;

	/// Each unlock era with outputs not paid yet: `(pool, unlock era)`.
	#[pallet::storage]
	pub type Unlocks<T> =
		StorageDoubleMap<_, Twox64Concat, PoolId, Twox64Concat, EraIndex, Unlock, OptionQuery>;

	/// ORB in `m_P`'s free balance that belongs to outputs not paid yet.
	#[pallet::storage]
	pub type Escrow<T> = StorageMap<_, Twox64Concat, PoolId, u128, ValueQuery>;

	/// The smallest private entry, in planck.
	#[pallet::storage]
	pub type MinEntry<T: Config> = StorageValue<_, u128, ValueQuery, T::DefaultMinEntry>;

	/// The last pool `on_idle` finished; the next block starts after it.
	#[pallet::storage]
	pub type NextPool<T> = StorageValue<_, PoolId, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A pool's root opened or closed it to new private entries.
		PrivateMembersSet {
			pool_id: PoolId,
			enabled: bool,
			asset_id: u32,
		},
		/// An entry was bonded; its shares are minted after its era compounds.
		Entered {
			pool_id: PoolId,
			value: u128,
			era: EraIndex,
		},
		/// Shares were burned and their value unbonded until `unlock_era`.
		Exited {
			pool_id: PoolId,
			shares: u128,
			value: u128,
			unlock_era: EraIndex,
		},
		/// An era's rewards were bonded back into the pool.
		Compounded {
			pool_id: PoolId,
			era: EraIndex,
		},
		/// An entry's shares were minted.
		EntrySettled {
			pool_id: PoolId,
			shares: u128,
			commitment: Commitment,
		},
		/// An entry would have taken fewer shares than it asked for: its ORB is
		/// unbonded and minted back to its key when it unlocks.
		EntryRefunded {
			pool_id: PoolId,
			value: u128,
			unlock_era: EraIndex,
		},
		/// An exit's ORB was minted.
		ExitSettled {
			pool_id: PoolId,
			value: u128,
			commitment: Commitment,
		},
		/// An output whose note already exists (a reused key with the same value)
		/// was not minted: its value stays with the other members.
		OutputDropped {
			pool_id: PoolId,
			value: u128,
		},
		/// Spend fees earned in shares were redeemed for a validator.
		FeesRedeemed {
			pool_id: PoolId,
			validator: T::AccountId,
			value: u128,
		},
		/// An unlock era was withdrawn; `paid` is the share of its value it paid.
		Withdrawn {
			pool_id: PoolId,
			value: u128,
			paid: Perquintill,
		},
		/// The pool is destroying: its shares are now worth a fixed value.
		WindingDown {
			pool_id: PoolId,
			value: u128,
			unlock_era: EraIndex,
		},
		/// A dissolved pool with nothing left to settle was forgotten.
		PoolClosed {
			pool_id: PoolId,
		},
		MinEntrySet {
			amount: u128,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		/// No such nomination pool.
		NoSuchPool,
		/// Only the pool's root opens or closes it to private members.
		NotRoot,
		/// The pool is not open to private members.
		NotPrivate,
		/// The pool takes no new members (blocked or destroying).
		PoolNotOpen,
		/// Below the smallest private entry, or the pool's join minimum.
		BelowMinimum,
		/// This era's entry queue for the pool is full.
		QueueFull,
		/// The owner key or blinding is zero or not a field element.
		InvalidKey,
		/// The spent asset is not the one this action takes.
		WrongAsset,
		/// The shares are worth nothing.
		NothingToRedeem,
		/// The exit would leave the pool membership below the join minimum.
		RemainderBelowMinimum,
		/// The pool is full.
		TooManyMembers,
		/// The shares are worth less than the exit's minimum.
		BelowMinimumOutput,
		/// The pool was slashed too far to take members (its points exceed
		/// `MaxPointsToBalance` times its stake).
		PoolSlashed,
		/// The pool's member has as many unbonding chunks as it can hold.
		TooManyUnbonding,
		/// More shares than the pool has issued.
		SharesExceedSupply,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Open or close `pool_id` to new private entries. Only its root. The
		/// first opening issues the pool's share asset.
		#[pallet::call_index(0)]
		#[pallet::weight(T::DbWeight::get().reads_writes(4, 6))]
		pub fn set_private(origin: OriginFor<T>, pool_id: PoolId, enabled: bool) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let pool = pools::BondedPools::<T>::get(pool_id).ok_or(Error::<T>::NoSuchPool)?;
			ensure!(pool.roles.root.as_ref() == Some(&who), Error::<T>::NotRoot);
			ensure!(
				!enabled || pool.state != PoolState::Destroying,
				Error::<T>::PoolNotOpen
			);
			let asset_id = match Pools::<T>::get(pool_id) {
				Some(mut private) => {
					// A wound-down private side (its pool destroyed, the id in use again)
					// only pays out: it opens again once forgotten.
					ensure!(
						!enabled || private.wind_down.is_none(),
						Error::<T>::PoolNotOpen
					);
					private.enabled = enabled;
					let asset_id = private.asset_id;
					Pools::<T>::insert(pool_id, private);
					asset_id
				}
				None => {
					// Closing a pool never opened issues nothing.
					ensure!(enabled, Error::<T>::NotPrivate);
					let asset_id = Self::issue_asset(pool_id)?;
					Pools::<T>::insert(
						pool_id,
						PrivatePool {
							asset_id,
							enabled,
							supply: 0,
							compounded_era: None,
							wind_down: None,
						},
					);
					AssetPool::<T>::insert(asset_id, pool_id);
					Members::<T>::insert(Self::member_account(pool_id), pool_id);
					asset_id
				}
			};
			Self::deposit_event(Event::PrivateMembersSet {
				pool_id,
				enabled,
				asset_id,
			});
			Ok(())
		}

		/// Set the smallest private entry: at least the pool's join minimum.
		#[pallet::call_index(1)]
		#[pallet::weight(T::DbWeight::get().writes(1))]
		pub fn set_min_entry(origin: OriginFor<T>, amount: u128) -> DispatchResult {
			T::MinEntryOrigin::ensure_origin(origin)?;
			// A first private member joins the pool, so no entry is smaller.
			ensure!(
				amount >= pools::MinJoinBond::<T>::get().saturated_into::<u128>(),
				Error::<T>::BelowMinimum
			);
			MinEntry::<T>::put(amount);
			Self::deposit_event(Event::MinEntrySet { amount });
			Ok(())
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Compounds, mints pending shares and pays unlocked exits, pool by pool
		/// from where the last block stopped, as far as the leftover weight allows.
		fn on_idle(_: BlockNumberFor<T>, remaining: Weight) -> Weight {
			let mut meter = WeightMeter::with_limit(remaining.min(T::MaxIdleWeight::get()));
			if meter.try_consume(T::DbWeight::get().reads(1)).is_err() {
				return meter.consumed();
			}
			let start = NextPool::<T>::get();
			let mut keys = match start {
				Some(after) => Pools::<T>::iter_keys_from(Pools::<T>::hashed_key_for(after)),
				None => Pools::<T>::iter_keys(),
			};
			let mut last = start;
			let step = Self::step_weight();
			loop {
				if meter.try_consume(T::DbWeight::get().reads(1)).is_err() {
					break;
				}
				let Some(pool_id) = keys.next() else {
					// The end: the next block starts over.
					last = None;
					break;
				};
				let before = meter.consumed();
				let finished = Self::work_on(pool_id, &mut meter);
				// A pool that took a step yields its turn: the next block starts
				// after it, so a long queue never holds up the other pools.
				if finished || meter.consumed().saturating_sub(before).all_gte(step) {
					last = Some(pool_id);
				}
				if !finished {
					break;
				}
			}
			match last {
				Some(pool_id) => NextPool::<T>::put(pool_id),
				None => NextPool::<T>::kill(),
			}
			meter.consumed()
		}

		#[cfg(feature = "try-runtime")]
		fn try_state(_: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
			for (pool_id, private) in Pools::<T>::iter() {
				let ledger: u128 =
					shielded::PoolBalancePerAsset::<T>::get(private.asset_id).saturated_into();
				ensure!(
					ledger == private.supply,
					sp_runtime::TryRuntimeError::Other("share supply != the shielded ledger")
				);
				ensure!(
					EntryPoints::<T>::get(pool_id) <= Self::member_points(pool_id),
					sp_runtime::TryRuntimeError::Other("pending entries exceed the membership")
				);
				let free: u128 =
					<T as shielded::Config>::Currency::free_balance(&Self::member_account(pool_id))
						.saturated_into();
				ensure!(
					Escrow::<T>::get(pool_id) <= free,
					sp_runtime::TryRuntimeError::Other("escrow exceeds the member's balance")
				);
			}
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// The pool's private member, `m_P`.
		pub fn member_account(pool_id: PoolId) -> T::AccountId {
			T::PrivateStakingId::get().into_sub_account_truncating(pool_id)
		}

		fn active_era() -> EraIndex {
			pallet_staking_async::ActiveEra::<T>::get()
				.map(|era| era.index)
				.unwrap_or_default()
		}

		/// `m_P`'s active points.
		pub fn member_points(pool_id: PoolId) -> u128 {
			pools::PoolMembers::<T>::get(Self::member_account(pool_id))
				.map(|member| member.points.saturated_into())
				.unwrap_or_default()
		}

		fn points_value(pool_id: PoolId, points: u128) -> u128 {
			pools::Pallet::<T>::api_points_to_balance(pool_id, points.saturated_into())
				.saturated_into()
		}

		/// The ORB `m_P`'s active points are worth.
		pub fn member_value(pool_id: PoolId) -> u128 {
			Self::points_value(pool_id, Self::member_points(pool_id))
		}

		/// `m_P`'s points that back minted shares.
		fn minted_points(pool_id: PoolId) -> u128 {
			Self::member_points(pool_id).saturating_sub(EntryPoints::<T>::get(pool_id))
		}

		/// What the minted shares are worth: `m_P`'s points less pending entries'.
		pub fn net_value(pool_id: PoolId) -> u128 {
			Self::points_value(pool_id, Self::minted_points(pool_id))
		}

		/// ORB `shares` are worth now, rounded down: the offset price, never above the
		/// pro-rata share of the minted value (a price below one, after a slash, would
		/// otherwise overvalue all but the last shares). The last shares take the dust.
		pub fn value_of(pool_id: PoolId, private: &PrivatePool, shares: u128) -> u128 {
			if let Some(wind) = private.wind_down {
				if shares >= private.supply {
					return wind.value;
				}
				return multiply_by_rational_with_rounding(
					shares,
					wind.value,
					private.supply.max(1),
					Rounding::Down,
				)
				.unwrap_or_default();
			}
			let net = Self::net_value(pool_id);
			if shares >= private.supply {
				return net;
			}
			let offset = T::VirtualOffset::get();
			let priced = multiply_by_rational_with_rounding(
				shares,
				net.saturating_add(offset),
				private.supply.saturating_add(offset),
				Rounding::Down,
			)
			.unwrap_or_default();
			let pro_rata =
				multiply_by_rational_with_rounding(shares, net, private.supply, Rounding::Down)
					.unwrap_or_default();
			priced.min(pro_rata)
		}

		/// Shares worth at least `value` of ORB now, rounded up: what a spend fee
		/// floor of `value` costs in shares.
		fn shares_worth(pool_id: PoolId, private: &PrivatePool, value: u128) -> u128 {
			let floor = match private.wind_down {
				Some(wind) => multiply_by_rational_with_rounding(
					value,
					private.supply.max(1),
					wind.value.max(1),
					Rounding::Up,
				),
				None => {
					let offset = T::VirtualOffset::get();
					let net = Self::net_value(pool_id);
					let priced = multiply_by_rational_with_rounding(
						value,
						private.supply.saturating_add(offset),
						net.saturating_add(offset),
						Rounding::Up,
					);
					// `value_of` caps the offset price at pro rata: below a price of one
					// the shares that are worth `value` are the pro-rata count.
					let pro_rata = (net > 0)
						.then(|| {
							multiply_by_rational_with_rounding(
								value,
								private.supply,
								net,
								Rounding::Up,
							)
						})
						.flatten();
					priced.max(pro_rata)
				}
			};
			floor.unwrap_or(u128::MAX).max(1)
		}

		fn issue_asset(pool_id: PoolId) -> Result<u32, DispatchError> {
			let mut name = b"Private stake in pool #".to_vec();
			let mut symbol = b"s".to_vec();
			let digits = alloc_digits(pool_id);
			name.extend_from_slice(&digits);
			symbol.extend_from_slice(&digits);
			shielded::Pallet::<T>::register_pallet_asset(
				BoundedVec::truncate_from(name),
				BoundedVec::truncate_from(symbol),
				18,
				T::PrivateStakingId::get(),
			)
		}

		/// Both must be non-zero field elements: a zero key has no secret behind
		/// it (the note could never be spent), and a zero blinding exposes the note.
		fn ensure_key(owner_pk: &[u8; 32], blinding: &[u8; 32]) -> Result<(), Error<T>> {
			let ok = |bytes: &[u8; 32]| {
				let field = Commitment::new(*bytes);
				field.is_canonical() && !field.is_zero()
			};
			ensure!(ok(owner_pk) && ok(blinding), Error::<T>::InvalidKey);
			Ok(())
		}

		fn unlock_era() -> EraIndex {
			Self::active_era().saturating_add(
				<pallet_staking_async::Pallet<T> as StakingInterface>::nominator_bonding_duration(),
			)
		}

		/// The first page of the entries of `era` with room, if any.
		fn entry_page(pool_id: PoolId, era: EraIndex) -> Option<u32> {
			(0..T::MaxPages::get()).find(|page| {
				(Entries::<T>::decode_len(pool_id, (era, *page)).unwrap_or(0) as u32)
					< T::MaxQueue::get()
			})
		}

		/// The page an output joins: the last one if it has room, else a new one.
		fn tail(pages: &mut Pages, len: impl Fn(u32) -> Option<usize>) -> u32 {
			if pages.end > pages.next
				&& (len(pages.end - 1).unwrap_or(0) as u32) < T::MaxQueue::get()
			{
				return pages.end - 1;
			}
			pages.end = pages.end.saturating_add(1);
			pages.end - 1
		}

		/// Queues an exit to be paid once `era` is withdrawn.
		fn push_exit(pool_id: PoolId, era: EraIndex, exit: Pending) -> DispatchResult {
			let mut unlock = Unlocks::<T>::get(pool_id, era).unwrap_or_default();
			let page = Self::tail(&mut unlock.exits, |page| {
				Exits::<T>::decode_len(pool_id, (era, page))
			});
			unlock.owed = unlock
				.owed
				.saturating_add(exit.value.saturating_sub(exit.funded));
			Exits::<T>::try_mutate(pool_id, (era, page), |queue| queue.try_push(exit))
				.map_err(|_| Error::<T>::QueueFull)?;
			Unlocks::<T>::insert(pool_id, era, unlock);
			Ok(())
		}

		/// Queues redeemed fees to be paid once `era` is withdrawn.
		fn push_fee(pool_id: PoolId, era: EraIndex, fee: FeeExit<T::AccountId>) -> DispatchResult {
			let mut unlock = Unlocks::<T>::get(pool_id, era).unwrap_or_default();
			let page = Self::tail(&mut unlock.fees, |page| {
				FeeExits::<T>::decode_len(pool_id, (era, page))
			});
			unlock.owed = unlock
				.owed
				.saturating_add(fee.value.saturating_sub(fee.funded));
			FeeExits::<T>::try_mutate(pool_id, (era, page), |queue| queue.try_push(fee))
				.map_err(|_| Error::<T>::QueueFull)?;
			Unlocks::<T>::insert(pool_id, era, unlock);
			Ok(())
		}

		/// Collects `items`, charging a read for each; `None` once out of weight.
		fn metered<I>(
			items: impl Iterator<Item = I>,
			meter: &mut WeightMeter,
		) -> Option<alloc::vec::Vec<I>> {
			let read = T::DbWeight::get().reads(1);
			items
				.map(|item| meter.try_consume(read).ok().map(|()| item))
				.collect()
		}

		/// Every check `enter` makes. Returns the pool.
		fn check_enter(
			pool_id: PoolId,
			owner_pk: &[u8; 32],
			blinding: &[u8; 32],
			asset_id: u32,
			amount: u128,
		) -> Result<PrivatePool, DispatchError> {
			ensure!(asset_id == NATIVE_ASSET_ID, Error::<T>::WrongAsset);
			let private = Pools::<T>::get(pool_id).ok_or(Error::<T>::NotPrivate)?;
			ensure!(
				private.enabled && private.wind_down.is_none(),
				Error::<T>::NotPrivate
			);
			let pool = pools::BondedPools::<T>::get(pool_id).ok_or(Error::<T>::NoSuchPool)?;
			ensure!(pool.state == PoolState::Open, Error::<T>::PoolNotOpen);
			// As the pool's own `ok_to_be_open`: a pool slashed past
			// `MaxPointsToBalance` takes no one, so the bond would fail after the proof.
			let points: u128 = pool.points.saturated_into();
			if points > 0 {
				let stake = Self::points_value(pool_id, points);
				let max: u128 = <T as pools::Config>::MaxPointsToBalance::get().into();
				ensure!(stake > 0 && points / stake < max, Error::<T>::PoolSlashed);
			}
			ensure!(amount >= MinEntry::<T>::get(), Error::<T>::BelowMinimum);
			Self::ensure_key(owner_pk, blinding)?;
			if !pools::PoolMembers::<T>::contains_key(Self::member_account(pool_id)) {
				ensure!(
					amount >= pools::MinJoinBond::<T>::get().saturated_into::<u128>(),
					Error::<T>::BelowMinimum
				);
				let per_pool = pools::MaxPoolMembersPerPool::<T>::get();
				ensure!(
					per_pool.is_none_or(|max| pool.member_counter < max),
					Error::<T>::TooManyMembers
				);
				let total = pools::MaxPoolMembers::<T>::get();
				ensure!(
					total.is_none_or(|max| pools::PoolMembers::<T>::count() < max),
					Error::<T>::TooManyMembers
				);
			}
			Self::entry_page(pool_id, Self::active_era()).ok_or(Error::<T>::QueueFull)?;
			Ok(private)
		}

		/// Every check `exit` makes. Returns the pool. `fee` is the spend's fee in
		/// shares, redeemed after the exit.
		fn check_exit(
			pool_id: PoolId,
			owner_pk: &[u8; 32],
			blinding: &[u8; 32],
			asset_id: u32,
			shares: u128,
			fee: u128,
			min_value: u128,
		) -> Result<PrivatePool, DispatchError> {
			let private = Pools::<T>::get(pool_id).ok_or(Error::<T>::NotPrivate)?;
			ensure!(asset_id == private.asset_id, Error::<T>::WrongAsset);
			Self::ensure_key(owner_pk, blinding)?;
			let redeem = Self::check_redeem(pool_id, &private, shares, fee)?;
			ensure!(redeem.value >= min_value, Error::<T>::BelowMinimumOutput);
			Ok(private)
		}

		/// The points that unbond `value` of minted value: all of them for the
		/// whole minted value, so no dust stays under the join minimum.
		fn points_for(pool_id: PoolId, value: u128) -> u128 {
			if value >= Self::net_value(pool_id) {
				return Self::minted_points(pool_id);
			}
			pools::Pallet::<T>::api_balance_to_points(pool_id, value.saturated_into())
				.saturated_into()
		}

		/// What `shares` redeem for, if the membership can release it: see [`Redeem`].
		///
		/// The pool keeps a partial member at its join minimum, and its own stake at
		/// the nominator minimum. A remainder below the join minimum is let go only
		/// when the other shares are dust (worth less than a spend fee), not
		/// counting the `fee` shares the same spend pays: the last holder then
		/// unbonds all of `m_P` and takes the dust's value, the fee's included.
		fn check_redeem(
			pool_id: PoolId,
			private: &PrivatePool,
			shares: u128,
			fee: u128,
		) -> Result<Redeem, DispatchError> {
			// The ledger keeps notes within the supply; checked again here, as the
			// price of the last shares is everything left.
			ensure!(shares > 0, Error::<T>::NothingToRedeem);
			ensure!(
				shares
					.checked_add(fee)
					.is_some_and(|total| total <= private.supply),
				Error::<T>::SharesExceedSupply
			);
			let mut value = Self::value_of(pool_id, private, shares);
			// The exit leaves only its own fee's shares: it takes the minted value but
			// what the fee is worth, so the offset's dust is the holder's, not the
			// author's (who redeems the fee as the last shares).
			if private.wind_down.is_none() && shares.saturating_add(fee) == private.supply {
				value =
					Self::net_value(pool_id).saturating_sub(Self::value_of(pool_id, private, fee));
			}
			ensure!(value > 0, Error::<T>::NothingToRedeem);
			if let Some(wind) = private.wind_down {
				if wind.withdrawn {
					return Ok(Redeem::fixed(value, value, Self::active_era()));
				}
				let funded = multiply_by_rational_with_rounding(
					value,
					wind.liquid,
					wind.value.max(1),
					Rounding::Down,
				)
				.unwrap_or_default()
				.min(value);
				return Ok(Redeem::fixed(
					value,
					funded,
					wind.unlock_era.max(Self::active_era()),
				));
			}
			let min_join: u128 = pools::MinJoinBond::<T>::get().saturated_into();
			let left = Self::member_value(pool_id).saturating_sub(value);
			let others = Self::value_of(
				pool_id,
				private,
				private.supply.saturating_sub(shares).saturating_sub(fee),
			);
			let sweep = left > 0
				&& left < min_join
				&& EntryPoints::<T>::get(pool_id) == 0
				&& others < <T as shielded::Config>::MinSpendFee::get();
			ensure!(
				left == 0 || left >= min_join || sweep,
				Error::<T>::RemainderBelowMinimum
			);
			let points = if sweep {
				Self::minted_points(pool_id)
			} else {
				Self::points_for(pool_id, value)
			};
			let released = Self::points_value(pool_id, points);
			ensure!(released > 0, Error::<T>::NothingToRedeem);
			// Staking keeps a nominating pool's bond at the nominator minimum (or
			// none); a chilled pool has no minimum.
			let pool = pools::BondedPools::<T>::get(pool_id).ok_or(Error::<T>::NoSuchPool)?;
			let stake_left =
				Self::points_value(pool_id, pool.points.saturated_into()).saturating_sub(released);
			let nominating = pallet_staking_async::Nominators::<T>::contains_key(
				pools::Pallet::<T>::generate_bonded_account(pool_id),
			);
			let min_bond: u128 =
				<pallet_staking_async::Pallet<T> as StakingInterface>::minimum_nominator_bond()
					.saturated_into();
			ensure!(
				!nominating || stake_left == 0 || stake_left >= min_bond,
				Error::<T>::RemainderBelowMinimum
			);
			let unlock_era = Self::unlock_era();
			// An unbonding chunk for a new era needs room in the member's chunks.
			if let Some(member) = pools::PoolMembers::<T>::get(Self::member_account(pool_id)) {
				ensure!(
					member.unbonding_eras.contains_key(&unlock_era)
						|| (member.unbonding_eras.len() as u32)
							< <T as pools::Config>::MaxUnbonding::get(),
					Error::<T>::TooManyUnbonding
				);
			}
			Ok(Redeem {
				// What the exit is paid (`release`): its minimum is checked against this.
				value: if sweep { released } else { released.min(value) },
				funded: 0,
				unlock_era,
				points,
			})
		}

		/// Takes `shares` out: unbonds their value from `m_P` or, winding down,
		/// from the fixed value. Returns the value, the part already escrowed,
		/// and the unlock era.
		fn release(
			pool_id: PoolId,
			private: &mut PrivatePool,
			shares: u128,
			fee: u128,
		) -> Result<(u128, u128, EraIndex), DispatchError> {
			let Redeem {
				value,
				funded,
				unlock_era,
				points,
			} = Self::check_redeem(pool_id, private, shares, fee)?;
			private.supply = private.supply.saturating_sub(shares);
			if let Some(wind) = private.wind_down.as_mut() {
				wind.value = wind.value.saturating_sub(value);
				wind.liquid = wind.liquid.saturating_sub(funded);
				return Ok((value, funded, unlock_era));
			}
			let released = Self::points_value(pool_id, points);
			let member = Self::member_account(pool_id);
			pools::Pallet::<T>::unbond(
				frame_system::RawOrigin::Signed(member.clone()).into(),
				T::Lookup::unlookup(member),
				points.saturated_into(),
			)?;
			Ok((released.min(value), 0, unlock_era))
		}

		/// Refunds an entry: unbonds its points and queues their value as an exit
		/// to its key. Returns `false` when the pool cannot release them (then the
		/// shares are minted after all).
		fn refund_entry(pool_id: PoolId, entry: &Entry) -> bool {
			let value = Self::points_value(pool_id, entry.points);
			let unlock_era = Self::unlock_era();
			let member = Self::member_account(pool_id);
			let refunded = frame_support::storage::with_transaction(|| {
				let result = pools::Pallet::<T>::unbond(
					frame_system::RawOrigin::Signed(member.clone()).into(),
					T::Lookup::unlookup(member.clone()),
					entry.points.saturated_into(),
				)
				.and_then(|()| {
					Self::push_exit(
						pool_id,
						unlock_era,
						Pending {
							value,
							funded: 0,
							owner_pk: entry.owner_pk,
							blinding: entry.blinding,
						},
					)
				});
				match result {
					Ok(()) => frame_support::storage::TransactionOutcome::Commit(Ok(())),
					Err(error) => frame_support::storage::TransactionOutcome::Rollback(Err(error)),
				}
			});
			if refunded.is_ok() {
				Self::deposit_event(Event::EntryRefunded {
					pool_id,
					value,
					unlock_era,
				});
			}
			refunded.is_ok()
		}

		/// An era whose outputs are all escrowed in full is paid as soon as it is
		/// due, with no withdrawal.
		fn mark_funded(pool_id: PoolId, era: EraIndex) {
			Unlocks::<T>::mutate(pool_id, era, |unlock| {
				if let Some(unlock) = unlock.as_mut().filter(|unlock| unlock.owed == 0) {
					unlock.paid.get_or_insert(Perquintill::one());
				}
			});
		}

		/// One pool's turn in `on_idle`. Returns `false` once out of weight.
		fn work_on(pool_id: PoolId, meter: &mut WeightMeter) -> bool {
			let db = T::DbWeight::get();
			// The pool, the era, the bonded pool and auto-payout's state; queue keys
			// are charged as they are read.
			if meter.try_consume(db.reads(10)).is_err() {
				return false;
			}
			let Some(mut private) = Pools::<T>::get(pool_id) else {
				return true;
			};
			let era = Self::active_era();
			let member = Self::member_account(pool_id);
			let bonded = pools::BondedPools::<T>::get(pool_id);
			let destroying = bonded
				.as_ref()
				.is_some_and(|pool| pool.state == PoolState::Destroying);

			// A dissolved or wound-down pool with nothing left is forgotten, even when its
			// id was created again: the new pool can then open to private members.
			if bonded.is_none() || private.wind_down.is_some() {
				if meter.try_consume(db.reads_writes(4, 5)).is_err() {
					return false;
				}
				if private.supply == 0
					&& EntryPoints::<T>::get(pool_id) == 0
					&& !pools::PoolMembers::<T>::contains_key(&member)
					&& Entries::<T>::iter_key_prefix(pool_id).next().is_none()
					&& Unlocks::<T>::iter_key_prefix(pool_id).next().is_none()
				{
					Pools::<T>::remove(pool_id);
					AssetPool::<T>::remove(private.asset_id);
					Members::<T>::remove(&member);
					Escrow::<T>::remove(pool_id);
					Self::deposit_event(Event::PoolClosed { pool_id });
					return true;
				}
			}

			let step = Self::step_weight();
			if !meter.can_consume(step) {
				return false;
			}

			// Compound the previous era once it is paid.
			if bonded.is_some()
				&& !destroying
				&& private.compounded_era.is_none_or(|done| done < era)
				&& (era == 0 || Self::era_paid(era - 1))
			{
				if meter.try_consume(Self::compound_weight()).is_err() {
					return false;
				}
				Self::compound(pool_id, &member);
				private.compounded_era = Some(era);
				Pools::<T>::insert(pool_id, &private);
				Self::deposit_event(Event::Compounded { pool_id, era });
			}

			// Mint the shares of entries whose era was compounded. A destroying
			// pool refunds them all instead: the rewards it did not compound
			// belong to the shares already minted.
			let Some(slots) = Self::metered(Entries::<T>::iter_key_prefix(pool_id), meter) else {
				return false;
			};
			let due = slots.into_iter().filter(|(entered, _)| {
				destroying || (*entered < era && private.compounded_era == Some(era))
			});
			for slot in due {
				let mut queue = Entries::<T>::get(pool_id, slot);
				while let Some(entry) = queue.first().cloned() {
					if meter.try_consume(step).is_err() {
						Entries::<T>::insert(pool_id, slot, queue);
						return false;
					}
					queue.remove(0);
					// Priced against the minted points alone: pending entries are
					// still out of `net_value`.
					let value = Self::points_value(pool_id, entry.points);
					let offset = T::VirtualOffset::get();
					let shares = multiply_by_rational_with_rounding(
						value,
						private.supply.saturating_add(offset),
						Self::net_value(pool_id).saturating_add(offset),
						Rounding::Down,
					)
					.unwrap_or_default();
					// Fewer shares than it asked for: its ORB goes back to its key.
					if (destroying || shares < entry.min_shares)
						&& Self::refund_entry(pool_id, &entry)
					{
						EntryPoints::<T>::mutate(pool_id, |p| *p = p.saturating_sub(entry.points));
						Pools::<T>::insert(pool_id, &private);
						continue;
					}
					EntryPoints::<T>::mutate(pool_id, |p| *p = p.saturating_sub(entry.points));
					let minted = (shares > 0)
						.then(|| {
							shielded::Pallet::<T>::mint_note(
								private.asset_id,
								shares,
								entry.owner_pk,
								entry.blinding,
								Funding::Issued(T::PrivateStakingId::get()),
							)
						})
						.transpose();
					match minted {
						Ok(Some(note)) => {
							private.supply = private.supply.saturating_add(note.value);
							Self::deposit_event(Event::EntrySettled {
								pool_id,
								shares: note.value,
								commitment: note.commitment,
							});
						}
						// Its value stays with the other members.
						_ => Self::deposit_event(Event::OutputDropped { pool_id, value }),
					}
					Pools::<T>::insert(pool_id, &private);
				}
				Entries::<T>::remove(pool_id, slot);
			}

			// A destroying pool: unbond what is left and fix the shares' value.
			if destroying && private.wind_down.is_none() && EntryPoints::<T>::get(pool_id) == 0 {
				if meter.try_consume(step).is_err() {
					return false;
				}
				if !Self::wind_down(pool_id, &mut private, &member) {
					return true;
				}
			}

			// Withdraw what has unlocked, once per unlock era.
			let Some(mut unlocks) = Self::metered(Unlocks::<T>::iter_prefix(pool_id), meter) else {
				return false;
			};
			let fresh =
				|unlock_era: EraIndex, unlock: &Unlock| unlock_era <= era && unlock.paid.is_none();
			let wind_due = private
				.wind_down
				.is_some_and(|wind| !wind.withdrawn && wind.unlock_era <= era);
			if wind_due || unlocks.iter().any(|(e, unlock)| fresh(*e, unlock)) {
				if meter.try_consume(step).is_err() {
					return false;
				}
				let mut owed = unlocks
					.iter()
					.filter(|(e, unlock)| fresh(*e, unlock))
					.fold(0u128, |sum, (_, unlock)| sum.saturating_add(unlock.owed));
				if let Some(wind) = private.wind_down.filter(|_| wind_due) {
					owed = owed.saturating_add(wind.value.saturating_sub(wind.liquid));
				}
				let free = |who: &T::AccountId| -> u128 {
					<T as shielded::Config>::Currency::free_balance(who).saturated_into()
				};
				let before = free(&member);
				let withdrawn = pools::Pallet::<T>::withdraw_unbonded(
					frame_system::RawOrigin::Signed(member.clone()).into(),
					T::Lookup::unlookup(member.clone()),
					0,
				);
				let got = free(&member).saturating_sub(before);
				// Nothing came out though something is owed: staking refuses for
				// now (unapplied slashes). Try again next block.
				if withdrawn.is_err() && owed > 0 {
					return true;
				}
				let paid = if owed == 0 {
					Perquintill::one()
				} else {
					Perquintill::from_rational(got.min(owed), owed)
				};
				for (unlock_era, unlock) in unlocks.iter_mut() {
					if fresh(*unlock_era, unlock) {
						unlock.paid = Some(paid);
						Unlocks::<T>::insert(pool_id, *unlock_era, &*unlock);
					}
				}
				Escrow::<T>::mutate(pool_id, |e| *e = e.saturating_add(got.min(owed)));
				if let Some(wind) = private.wind_down.as_mut().filter(|_| wind_due) {
					let bonded = wind.value.saturating_sub(wind.liquid);
					wind.value = wind.liquid.saturating_add(paid.mul_floor(bonded));
					wind.liquid = wind.value;
					wind.withdrawn = true;
					Pools::<T>::insert(pool_id, &private);
				}
				Self::deposit_event(Event::Withdrawn {
					pool_id,
					value: got,
					paid,
				});
			}

			// Pay what was withdrawn, page by page.
			let mut left = false;
			for (unlock_era, mut unlock) in unlocks {
				let Some(paid) = unlock.paid.filter(|_| unlock_era <= era) else {
					left = true;
					continue;
				};
				while unlock.exits.next < unlock.exits.end {
					let slot = (unlock_era, unlock.exits.next);
					let mut queue = Exits::<T>::get(pool_id, slot);
					while let Some(exit) = queue.first().cloned() {
						if meter.try_consume(step).is_err() {
							Exits::<T>::insert(pool_id, slot, queue);
							Unlocks::<T>::insert(pool_id, unlock_era, unlock);
							return false;
						}
						let value = exit
							.funded
							.saturating_add(paid.mul_floor(exit.value.saturating_sub(exit.funded)));
						let minted = (value > 0)
							.then(|| {
								shielded::Pallet::<T>::mint_note(
									NATIVE_ASSET_ID,
									value,
									exit.owner_pk,
									exit.blinding,
									Funding::From(&member),
								)
							})
							.transpose();
						match minted {
							Ok(Some(note)) => Self::deposit_event(Event::ExitSettled {
								pool_id,
								value: note.value,
								commitment: note.commitment,
							}),
							Ok(None) => {}
							// A note that already exists: the value stays with the members.
							Err(error)
								if error
									== shielded::Error::<T>::CommitmentAlreadyExists.into() =>
							{
								Self::deposit_event(Event::OutputDropped { pool_id, value })
							}
							// Anything else may pass later: keep it queued.
							Err(error) => {
								log::warn!(
									target: "runtime::private-staking",
									"exit from pool {pool_id} not paid yet: {error:?}"
								);
								Exits::<T>::insert(pool_id, slot, queue);
								Unlocks::<T>::insert(pool_id, unlock_era, unlock);
								return true;
							}
						}
						queue.remove(0);
						Escrow::<T>::mutate(pool_id, |e| *e = e.saturating_sub(value));
					}
					Exits::<T>::remove(pool_id, slot);
					unlock.exits.next = unlock.exits.next.saturating_add(1);
				}
				while unlock.fees.next < unlock.fees.end {
					let slot = (unlock_era, unlock.fees.next);
					let mut fees = FeeExits::<T>::get(pool_id, slot);
					while let Some(fee) = fees.first().cloned() {
						if meter.try_consume(step).is_err() {
							FeeExits::<T>::insert(pool_id, slot, fees);
							Unlocks::<T>::insert(pool_id, unlock_era, unlock);
							return false;
						}
						let value = fee
							.funded
							.saturating_add(paid.mul_floor(fee.value.saturating_sub(fee.funded)));
						if value > 0 {
							if let Err(error) = <T as shielded::Config>::Currency::transfer(
								&member,
								&fee.validator,
								value.saturated_into(),
								ExistenceRequirement::AllowDeath,
							) {
								log::warn!(
									target: "runtime::private-staking",
									"fees from pool {pool_id} not paid yet: {error:?}"
								);
								FeeExits::<T>::insert(pool_id, slot, fees);
								Unlocks::<T>::insert(pool_id, unlock_era, unlock);
								return true;
							}
							Self::deposit_event(Event::FeesRedeemed {
								pool_id,
								validator: fee.validator,
								value,
							});
						}
						fees.remove(0);
						Escrow::<T>::mutate(pool_id, |e| *e = e.saturating_sub(value));
					}
					FeeExits::<T>::remove(pool_id, slot);
					unlock.fees.next = unlock.fees.next.saturating_add(1);
				}
				Unlocks::<T>::remove(pool_id, unlock_era);
			}

			// With every output paid, rounding dust of the escrow goes back to the
			// members, except what a winding-down pool still owes.
			if !left {
				let owed = private.wind_down.map_or(0, |wind| wind.liquid);
				Escrow::<T>::mutate(pool_id, |e| *e = (*e).min(owed));
			}
			true
		}

		/// Bonds `m_P`'s rewards back: those still in the pool and those already
		/// paid to its free balance, except what it holds for unpaid outputs.
		fn compound(pool_id: PoolId, member: &T::AccountId) {
			let origin =
				|| -> OriginFor<T> { frame_system::RawOrigin::Signed(member.clone()).into() };
			if pools::Pallet::<T>::api_pending_rewards(member.clone())
				.is_some_and(|pending| pending > Default::default())
			{
				let _ = pools::Pallet::<T>::bond_extra(origin(), BondExtra::Rewards);
			}
			let free = Self::liquid(pool_id, member);
			if free > 0 && pools::PoolMembers::<T>::contains_key(member) {
				let _ = pools::Pallet::<T>::bond_extra(
					origin(),
					BondExtra::FreeBalance(free.saturated_into()),
				);
			}
		}

		/// `m_P`'s free balance above its existential deposit and its escrow.
		fn liquid(pool_id: PoolId, member: &T::AccountId) -> u128 {
			let free: u128 =
				<T as shielded::Config>::Currency::free_balance(member).saturated_into();
			let reserve: u128 =
				<T as shielded::Config>::Currency::minimum_balance().saturated_into();
			free.saturating_sub(reserve)
				.saturating_sub(Escrow::<T>::get(pool_id))
		}

		/// Whether `pallet-auto-payout` is done with `era`. While it is paused nothing
		/// is known to be paid, so the pool waits: an entry minted before rewards are
		/// claimed by hand would share rewards its stake did not earn.
		fn era_paid(era: EraIndex) -> bool {
			!pallet_auto_payout::Paused::<T>::get()
				&& !pallet_auto_payout::Queue::<T>::get().contains(&era)
				&& pallet_auto_payout::Current::<T>::get().is_none_or(|paying| paying.era != era)
		}

		/// Unbonds what is left of `m_P` and fixes the shares' value: what its
		/// active points are worth, plus its free balance. Returns `false` if the
		/// unbond failed (tried again next block).
		fn wind_down(pool_id: PoolId, private: &mut PrivatePool, member: &T::AccountId) -> bool {
			// No entry is pending, so every active point backs the shares; queued
			// outputs are in other chunks and bear their own slashes.
			let points = Self::member_points(pool_id);
			let bonded = Self::points_value(pool_id, points);
			let origin =
				|| -> OriginFor<T> { frame_system::RawOrigin::Signed(member.clone()).into() };
			let unbond = || {
				pools::Pallet::<T>::unbond(
					origin(),
					T::Lookup::unlookup(member.clone()),
					points.saturated_into(),
				)
			};
			let unbonded = points == 0
				|| frame_support::storage::with_storage_layer(unbond).is_ok()
				|| frame_support::storage::with_storage_layer(|| {
					// Staking keeps a nominating pool at the nominator minimum; with
					// its depositor below it (slashed), anyone may chill the pool so
					// its members can leave.
					pools::Pallet::<T>::chill(origin(), pool_id)?;
					unbond()
				})
				.is_ok();
			if !unbonded {
				return false;
			}
			// Rewards claimed into the free balance belong to the shares.
			let liquid = Self::liquid(pool_id, member);
			Escrow::<T>::mutate(pool_id, |e| *e = e.saturating_add(liquid));
			// The chunk this unbond made unlocks with the exits made now.
			let unlock_era = Self::unlock_era();
			let value = bonded.saturating_add(liquid);
			private.wind_down = Some(WindDown {
				value,
				liquid,
				unlock_era,
				withdrawn: bonded == 0,
			});
			Pools::<T>::insert(pool_id, &*private);
			Self::deposit_event(Event::WindingDown {
				pool_id,
				value,
				unlock_era,
			});
			true
		}

		/// The most one step of `on_idle` costs: a mint (a shield's work), a pool
		/// operation, or a withdrawal.
		pub fn step_weight() -> Weight {
			use pallet_nomination_pools::WeightInfo as _;
			shielded::Pallet::<T>::mint_note_weight()
				.max(<T as pools::Config>::WeightInfo::bond_extra_other())
				.max(<T as pools::Config>::WeightInfo::bond_extra_transfer())
				.max(<T as pools::Config>::WeightInfo::withdraw_unbonded_kill(0))
				.max(<T as pools::Config>::WeightInfo::unbond())
				.saturating_add(T::DbWeight::get().reads_writes(4, 4))
		}

		/// What compounding costs: bonding the pool rewards back and the paid-out
		/// ones from the free balance (two pool calls).
		fn compound_weight() -> Weight {
			use pallet_nomination_pools::WeightInfo as _;
			<T as pools::Config>::WeightInfo::bond_extra_other()
				.saturating_add(<T as pools::Config>::WeightInfo::bond_extra_transfer())
				.saturating_add(T::DbWeight::get().reads_writes(6, 2))
		}

		/// What releasing shares costs: a pool unbond, the price reads and the
		/// queue's last page.
		fn release_weight() -> Weight {
			use pallet_nomination_pools::WeightInfo as _;
			<T as pools::Config>::WeightInfo::unbond()
				.saturating_add(T::DbWeight::get().reads_writes(10, 5))
		}
	}

	/// `n` in decimal ASCII.
	fn alloc_digits(mut n: u32) -> alloc::vec::Vec<u8> {
		let mut digits = alloc::vec::Vec::new();
		loop {
			digits.push(b'0' + (n % 10) as u8);
			n /= 10;
			if n == 0 {
				break;
			}
		}
		digits.reverse();
		digits
	}

	impl<T: Config> shielded::BoundActions<T::AccountId> for Pallet<T> {
		type Action = Action;

		fn executor(action: &Action) -> Option<T::AccountId> {
			let (Action::Enter { pool_id, .. } | Action::Exit { pool_id, .. }) = action;
			Pools::<T>::contains_key(pool_id).then(|| Self::member_account(*pool_id))
		}

		fn is_executor(who: &T::AccountId) -> bool {
			Members::<T>::contains_key(who)
		}

		fn min_fee(asset_id: u32) -> Option<u128> {
			let pool_id = AssetPool::<T>::get(asset_id)?;
			let private = Pools::<T>::get(pool_id)?;
			Some(Self::shares_worth(
				pool_id,
				&private,
				<T as shielded::Config>::MinSpendFee::get(),
			))
		}

		fn validate(action: &Action, asset_id: u32, amount: u128, fee: u128) -> DispatchResult {
			match action {
				Action::Enter {
					pool_id,
					owner_pk,
					blinding,
					..
				} => Self::check_enter(*pool_id, owner_pk, blinding, asset_id, amount).map(|_| ()),
				Action::Exit {
					pool_id,
					owner_pk,
					blinding,
					min_value,
				} => Self::check_exit(
					*pool_id, owner_pk, blinding, asset_id, amount, fee, *min_value,
				)
				.map(|_| ()),
			}
		}

		fn execute(action: Action, asset_id: u32, amount: u128, fee: u128) -> DispatchResult {
			match action {
				Action::Enter {
					pool_id,
					owner_pk,
					blinding,
					min_shares,
				} => {
					Self::check_enter(pool_id, &owner_pk, &blinding, asset_id, amount)?;
					let member = Self::member_account(pool_id);
					let origin: OriginFor<T> =
						frame_system::RawOrigin::Signed(member.clone()).into();
					let before = Self::member_points(pool_id);
					if pools::PoolMembers::<T>::contains_key(&member) {
						pools::Pallet::<T>::bond_extra(
							origin,
							BondExtra::FreeBalance(amount.saturated_into()),
						)?;
					} else {
						pools::Pallet::<T>::join(origin, amount.saturated_into(), pool_id)?;
					}
					let points = Self::member_points(pool_id).saturating_sub(before);
					ensure!(points > 0, Error::<T>::BelowMinimum);
					let era = Self::active_era();
					let page = Self::entry_page(pool_id, era).ok_or(Error::<T>::QueueFull)?;
					EntryPoints::<T>::mutate(pool_id, |p| *p = p.saturating_add(points));
					Entries::<T>::try_mutate(pool_id, (era, page), |queue| {
						queue.try_push(Entry {
							points,
							value: amount,
							min_shares,
							owner_pk,
							blinding,
						})
					})
					.map_err(|_| Error::<T>::QueueFull)?;
					Self::deposit_event(Event::Entered {
						pool_id,
						value: amount,
						era,
					});
				}
				Action::Exit {
					pool_id,
					owner_pk,
					blinding,
					min_value,
				} => {
					let mut private = Self::check_exit(
						pool_id, &owner_pk, &blinding, asset_id, amount, fee, min_value,
					)?;
					let (value, funded, unlock_era) =
						Self::release(pool_id, &mut private, amount, fee)?;
					Pools::<T>::insert(pool_id, &private);
					Self::push_exit(
						pool_id,
						unlock_era,
						Pending {
							value,
							funded,
							owner_pk,
							blinding,
						},
					)?;
					if funded == value && private.wind_down.is_some_and(|wind| wind.withdrawn) {
						Self::mark_funded(pool_id, unlock_era);
					}
					Self::deposit_event(Event::Exited {
						pool_id,
						shares: amount,
						value,
						unlock_era,
					});
				}
			}
			Ok(())
		}

		fn weight(action: &Action) -> Weight {
			use pallet_nomination_pools::WeightInfo as _;
			match action {
				Action::Enter { .. } => <T as pools::Config>::WeightInfo::join()
					.max(<T as pools::Config>::WeightInfo::bond_extra_transfer())
					.saturating_add(
						T::DbWeight::get()
							.reads_writes(10u64.saturating_add(T::MaxPages::get().into()), 4),
					),
				Action::Exit { .. } => Self::release_weight(),
			}
		}

		fn redeem_fees(validator: &T::AccountId, asset_id: u32, amount: u128) -> DispatchResult {
			let pool_id = AssetPool::<T>::get(asset_id).ok_or(Error::<T>::WrongAsset)?;
			let mut private = Pools::<T>::get(pool_id).ok_or(Error::<T>::NotPrivate)?;
			// Fee shares worth nothing (the last holder took the pool's value) are
			// retired, so they never claim part of a later entry.
			if Self::value_of(pool_id, &private, amount) == 0 {
				ensure!(amount <= private.supply, Error::<T>::SharesExceedSupply);
				private.supply = private.supply.saturating_sub(amount);
				Pools::<T>::insert(pool_id, &private);
				return Ok(());
			}
			let (value, funded, unlock_era) = Self::release(pool_id, &mut private, amount, 0)?;
			Pools::<T>::insert(pool_id, &private);
			Self::push_fee(
				pool_id,
				unlock_era,
				FeeExit {
					validator: validator.clone(),
					value,
					funded,
				},
			)?;
			if funded == value && private.wind_down.is_some_and(|wind| wind.withdrawn) {
				Self::mark_funded(pool_id, unlock_era);
			}
			Ok(())
		}

		fn redeem_fees_weight() -> Weight {
			Self::release_weight()
		}
	}
}
