//! Removes staking's data of eras past the history, and of an era plan that will
//! not start, with no transactions.
//!
//! When an era starts, staking marks the one leaving `HistoryDepth` for pruning,
//! but only removes its data through `prune_era_step`, a free call that nobody
//! has a reason to make. This pallet makes that call from `on_idle`:
//!
//! - as many steps as fit [`Config::MaxBlockShare`] of the block and the weight
//!   transactions left, each counted at its worst case before it runs;
//! - never in a block that already carries staking's heavy work
//!   ([`Config::HeavyBlocks`]);
//! - through the runtime's call filter, as a manual call would: while the call
//!   is filtered, nothing is pruned;
//! - an era whose step fails is reported once ([`Event::PruningFailed`]) and
//!   tried again every [`Config::RetryAfter`] blocks ([`FailedEras`]); the
//!   other marked eras go on.
//!
//! A step removes up to `MaxPruningItems` storage items. A full era (100 000
//! voters backing 16 validators each) leaves about 25 000 exposure pages, some
//! 260 steps: a few blocks' worth, against an era of thousands of blocks.
//!
//! Before pruning, `on_idle` goes on removing the data of a stalled era plan
//! ([`StalledPlan`], `staking::recovery`), which is reset only once its data is
//! gone.
//!
//! Its genesis also turns staking's `AreNominatorsSlashable` off, which
//! staking's own genesis cannot set: only validators are slashed here
//! (`params::NOMINATOR_UNBOND_DURATION`). A chain started before spec 22 has it
//! turned off by `migrations::NominatorsUnslashable`.

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use alloc::vec::Vec;
	use frame_support::{
		dispatch::{GetDispatchInfo, PostDispatchInfo},
		pallet_prelude::*,
		traits::Contains,
		weights::WeightMeter,
	};
	use frame_system::pallet_prelude::*;
	use pallet_staking_async::{self as staking, EraPruningState};
	use sp_runtime::{
		traits::{Dispatchable, Saturating},
		Perbill,
	};
	use sp_staking::EraIndex;

	#[pallet::config]
	pub trait Config:
		frame_system::Config<RuntimeEvent: From<Event<Self>>> + pallet_staking_async::Config
	{
		/// The runtime's call, to dispatch `prune_era_step` through its filter.
		type RuntimeCall: From<staking::Call<Self>>
			+ GetDispatchInfo
			+ Dispatchable<RuntimeOrigin = Self::RuntimeOrigin, PostInfo = PostDispatchInfo>;
		/// Blocks pruning stays out of.
		type HeavyBlocks: Contains<BlockNumberFor<Self>>;
		/// Storage reads `HeavyBlocks` makes.
		type HeavyBlockReads: Get<u64>;
		/// Signs `prune_era_step`, which wants a signed origin. Never pays: the
		/// call is free and this pallet bypasses transaction payment.
		type Signer: Get<Self::AccountId>;
		/// Most of a block pruning may take, checks included.
		#[pallet::constant]
		type MaxBlockShare: Get<Perbill>;
		/// Blocks an era whose step failed waits before it is tried again.
		#[pallet::constant]
		type RetryAfter: Get<BlockNumberFor<Self>>;
	}

	/// Most failed eras remembered; one failing beyond them is reported each
	/// time it fails.
	pub const MAX_FAILED_ERAS: u32 = 16;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// The planned era of a stalled plan whose data is still being removed.
	#[pallet::storage]
	pub type StalledPlan<T> = StorageValue<_, EraIndex, OptionQuery>;

	/// Eras whose step failed, each with the block from which it is tried
	/// again. Each was reported once.
	#[pallet::storage]
	pub type FailedEras<T: Config> = StorageValue<
		_,
		BoundedVec<(EraIndex, BlockNumberFor<T>), ConstU32<MAX_FAILED_ERAS>>,
		ValueQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A pruning step of `era` failed. Reported once; the era is tried again
		/// every `RetryAfter` blocks while the others go on.
		PruningFailed { era: EraIndex, error: DispatchError },
	}

	/// Nothing to configure: building it turns nominator slashing off.
	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		#[serde(skip)]
		pub _config: core::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		/// Built after staking's genesis (pallet order), which leaves the default on.
		fn build(&self) {
			staking::AreNominatorsSlashable::<T>::put(false);
			// The genesis era starts without the copy staking takes at each era's start.
			let era = staking::ActiveEra::<T>::get().map_or(0, |era| era.index);
			staking::ErasNominatorsSlashable::<T>::insert(era, false);
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_idle(now: BlockNumberFor<T>, remaining: Weight) -> Weight {
			let check = Self::check_weight();
			let mut meter = WeightMeter::with_limit(remaining.min(Self::share()));
			if !meter.can_consume(Self::budget()) {
				return Weight::zero();
			}
			meter.consume(check);
			if T::HeavyBlocks::contains(&now) {
				return meter.consumed();
			}
			if !Self::clear_stalled_plan(&mut meter) {
				return meter.consumed();
			}
			let db = T::DbWeight::get();
			let flush = db.writes(1);
			let mut failed = FailedEras::<T>::get();
			let mut changed = false;
			// Failed eras still waiting, then those failing in this block.
			let mut skip: Vec<EraIndex> = failed
				.iter()
				.filter(|(_, retry)| *retry > now)
				.map(|(era, _)| *era)
				.collect();
			loop {
				// The marked eras read past the skipped ones, then a step at its worst.
				let reads = db.reads(1 + skip.len() as u64);
				if !meter.can_consume(
					reads
						.saturating_add(Self::step_weight())
						.saturating_add(flush),
				) {
					break;
				}
				meter.consume(reads);
				let next = EraPruningState::<T>::iter_keys().find(|era| !skip.contains(era));
				let Some(era) = next else {
					// The failed eras due again and not found were pruned meanwhile.
					let before = failed.len();
					failed.retain(|(era, _)| skip.contains(era));
					changed |= failed.len() != before;
					break;
				};
				let (used, result) = Self::prune_step(era);
				meter.consume(used);
				let known = failed.iter().position(|(e, _)| *e == era);
				match result {
					Ok(()) => {
						if let Some(i) = known {
							failed.remove(i);
							changed = true;
						}
					}
					Err(error) if error == frame_system::Error::<T>::CallFiltered.into() => break,
					Err(error) => {
						let retry = now.saturating_add(T::RetryAfter::get());
						match known {
							Some(i) => failed[i].1 = retry,
							None => {
								log::warn!(
									target: "runtime::staking::pruning",
									"era {era} not pruned: {error:?}",
								);
								Self::deposit_event(Event::PruningFailed { era, error });
								// Full: reported again when it next fails.
								let _ = failed.try_push((era, retry));
							}
						}
						changed = true;
						skip.push(era);
					}
				}
			}
			if changed {
				meter.consume(flush);
				FailedEras::<T>::put(failed);
			}
			meter.consumed()
		}

		fn integrity_test() {
			assert!(
				Self::budget().all_lte(Self::share()),
				"a pruning step's worst case exceeds `MaxBlockShare` of the block: \
				 pruning would never run"
			);
		}
	}

	impl<T: Config> Pallet<T> {
		/// The least a block needs to prune: the checks, one step at its worst
		/// and the write of [`FailedEras`].
		pub fn budget() -> Weight {
			Self::check_weight()
				.saturating_add(Self::step_budget())
				.saturating_add(T::DbWeight::get().writes(1))
		}

		/// The most a block's pruning takes: `MaxBlockShare` of the block.
		pub fn share() -> Weight {
			T::MaxBlockShare::get() * T::BlockWeights::get().max_block
		}

		/// `prune_era_step`'s declared weight: the worst of its steps.
		pub fn step_weight() -> Weight {
			staking::Call::<T>::prune_era_step { era: 0 }
				.get_dispatch_info()
				.call_weight
		}

		/// Removes up to `limit` storage items of what the planned era `era`
		/// stored: its exposures, pages, validator preferences and incentive
		/// weights. Returns the weight used and whether nothing is left.
		pub fn clear_plan(era: EraIndex, limit: u32) -> (Weight, bool) {
			let db = T::DbWeight::get();
			let mut left = limit;
			let mut weight = Weight::zero();
			let clears: [&dyn Fn(u32) -> sp_io::MultiRemovalResults; 4] = [
				&|n| staking::ErasStakersOverview::<T>::clear_prefix(era, n, None),
				&|n| staking::ErasStakersPaged::<T>::clear_prefix((era,), n, None),
				&|n| staking::ErasValidatorPrefs::<T>::clear_prefix(era, n, None),
				&|n| staking::ErasValidatorIncentiveWeight::<T>::clear_prefix(era, n, None),
			];
			for clear in clears {
				if left == 0 {
					return (weight, false);
				}
				let removed = clear(left);
				weight.saturating_accrue(
					db.reads_writes(u64::from(removed.loops), u64::from(removed.backend)),
				);
				left = left.saturating_sub(removed.backend);
				if removed.maybe_cursor.is_some() {
					return (weight, false);
				}
			}
			(weight, true)
		}

		/// Goes on removing a stalled plan's data within `meter`, while staking
		/// still has that era planned. Whether pruning may follow in this block.
		fn clear_stalled_plan(meter: &mut WeightMeter) -> bool {
			let db = T::DbWeight::get();
			let Some(era) = StalledPlan::<T>::get() else {
				return true;
			};
			meter.consume(db.reads(2));
			let active = staking::ActiveEra::<T>::get().map_or(0, |e| e.index);
			if staking::CurrentEra::<T>::get() != Some(era) || active >= era {
				meter.consume(db.writes(1));
				StalledPlan::<T>::kill();
				return true;
			}
			let item = db.reads_writes(1, 1);
			let limit = meter
				.remaining()
				.saturating_sub(db.writes(1))
				.checked_div_per_component(&item)
				.unwrap_or(0);
			let (used, done) = Self::clear_plan(era, limit.min(u64::from(u32::MAX)) as u32);
			meter.consume(used);
			if done {
				meter.consume(db.writes(1));
				StalledPlan::<T>::kill();
			}
			done
		}

		/// The heavy-block check and the reads of [`StalledPlan`] and
		/// [`FailedEras`].
		fn check_weight() -> Weight {
			T::DbWeight::get().reads(T::HeavyBlockReads::get().saturating_add(2))
		}

		/// One step at its worst: the read of the next marked era and the call.
		fn step_budget() -> Weight {
			T::DbWeight::get()
				.reads(1)
				.saturating_add(Self::step_weight())
		}

		/// One step of `era`, dispatched through the runtime's call filter.
		/// Staking checks the era is past the history.
		fn prune_step(era: EraIndex) -> (Weight, Result<(), DispatchError>) {
			let call: <T as Config>::RuntimeCall =
				staking::Call::<T>::prune_era_step { era }.into();
			let declared = call.get_dispatch_info().call_weight;
			let origin = frame_system::RawOrigin::Signed(T::Signer::get()).into();
			match call.dispatch(origin) {
				Ok(post) => (post.actual_weight.unwrap_or(declared), Ok(())),
				Err(e) => (e.post_info.actual_weight.unwrap_or(declared), Err(e.error)),
			}
		}
	}
}
