//! # Pallet Auto Payout
//!
//! Pays staking rewards automatically each era, so no one has to claim them.
//! It pays the same pages a manual `payout_stakers_by_page` would, to each
//! staker's own reward destination, spread across blocks so it never crowds out
//! transactions or slows block production.
//!
//! ## Pacing
//!
//! When an era closes it is queued. Its pages are priced with staking's own
//! weights, and paying them is spread over [`Config::PaymentWindow`] blocks:
//!
//! - `on_idle` pays from the weight the block's transactions left unused, up to
//!   [`PayoutLimits::idle`] of the block. On a quiet chain this pays an era in a
//!   fraction of the window.
//! - `on_initialize` pays only when the era falls behind its schedule (a busy
//!   chain left `on_idle` nothing), up to [`PayoutLimits::floor`], or
//!   [`PayoutLimits::catch_up`] while more than one era waits.
//!
//! Neither pays on the blocks the runtime already loads
//! ([`EraPayouts::is_heavy_block`]).
//!
//! Normal transactions keep their whole class limit: the guaranteed share is
//! mandatory weight, which counts against the block, not against them.
//!
//! ## Safety
//!
//! - Every step is priced before it runs and only runs if it fits the budget;
//!   `floor` is checked to fit the largest step, so a behind era always moves.
//! - A page staking refuses is skipped with [`Event::PayoutSkipped`]; a page
//!   someone already claimed is skipped silently. A refusal that holds for the
//!   rest of a validator's pages skips them all under one event, and one that
//!   holds for the era drops it ([`Event::EraExpired`]): neither spends a block's
//!   budget on calls staking will refuse. Nothing panics.
//! - Manual claims keep working; [`Pallet::pause`] stops automatic payment and
//!   leaves them as the only way to pay, until the oldest unpaid era nears the
//!   end of staking's history ([`Config::ExpiryMargin`]): then the pause lifts
//!   itself, so forgetting it cannot cost rewards.
//! - Each era, an unpaid era within that margin is reported
//!   ([`Event::ExpiryAtRisk`]), whatever holds it, days before it would expire. A call the runtime filters (a call
//!   filter or safe mode) is not paid either, nor skipped: the page waits until
//!   the runtime allows it again ([`PayoutOutcome::Blocked`]).
//! - Limits are capped in code ([`MAX_FLOOR`], [`MAX_CATCH_UP`], [`MAX_IDLE`]),
//!   whatever [`Config::AdminOrigin`] sets.
//!
//! ## Layout
//!
//! - [`types`]: the interface to staking ([`EraPayouts`]), the era being paid
//!   ([`EraState`]) and the limits ([`PayoutLimits`]).
//! - `engine`: the hooks' work, one module per concern (queue, expiry
//!   watchdog, budget, payment, invariants), and [`pacing`], the budget rules as
//!   pure functions.
//! - `benchmarking`: the benchmarks and the [`weights`] they produce.
//! - `tests`: the mock runtime and the tests.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod types;

mod benchmarking;
mod engine;

#[cfg(test)]
mod tests;

pub use benchmarking::weights;
pub use engine::pacing;

pub use pallet::*;
pub use types::{
	EraIndex, EraPayouts, EraState, LimitsError, MAX_CATCH_UP, MAX_FLOOR, MAX_IDLE, Page,
	PayoutLimits, PayoutOutcome, ValidatorPages,
};
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use sp_runtime::DispatchError;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Staking: which eras are payable, their validators, and paying a page.
		type Payouts: EraPayouts<Self::AccountId, BlockNumberFor<Self>>;

		/// May change the limits and pause automatic payment.
		type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Most validators elected in an era.
		#[pallet::constant]
		type MaxValidators: Get<u32>;

		/// Most eras waiting to be paid; at least staking's history depth.
		#[pallet::constant]
		type MaxQueuedEras: Get<u32>;

		/// Blocks over which an era's payment is spread.
		#[pallet::constant]
		type PaymentWindow: Get<BlockNumberFor<Self>>;

		/// Eras before the oldest unpaid era leaves staking's history at which the
		/// pallet warns ([`Event::ExpiryAtRisk`]) and lifts a pause so it is paid
		/// ([`Event::ResumedToAvoidExpiry`]). Positive, below the history depth.
		#[pallet::constant]
		type ExpiryMargin: Get<EraIndex>;

		/// The limits until [`Pallet::set_limits`] changes them.
		type DefaultLimits: Get<PayoutLimits>;

		type WeightInfo: WeightInfo;
	}

	pub type EraStateOf<T> = EraState<
		<T as frame_system::Config>::AccountId,
		BlockNumberFor<T>,
		<T as Config>::MaxValidators,
	>;

	/// The active era when last seen; a higher one means eras closed.
	#[pallet::storage]
	pub type LastActiveEra<T> = StorageValue<_, EraIndex, OptionQuery>;

	/// Closed eras waiting to be paid, oldest first.
	#[pallet::storage]
	pub type Queue<T: Config> = StorageValue<_, BoundedVec<EraIndex, T::MaxQueuedEras>, ValueQuery>;

	/// The era being paid.
	#[pallet::storage]
	pub type Current<T: Config> = StorageValue<_, EraStateOf<T>, OptionQuery>;

	#[pallet::storage]
	pub type Limits<T: Config> = StorageValue<_, PayoutLimits, ValueQuery, T::DefaultLimits>;

	/// While set, nothing is paid automatically; eras still queue.
	#[pallet::storage]
	pub type Paused<T> = StorageValue<_, bool, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// `era` closed and waits to be paid.
		EraQueued {
			era: EraIndex,
		},
		/// Payment of `era` started.
		EraStarted {
			era: EraIndex,
			validators: u32,
			pages: u32,
		},
		/// Every page of `era` was paid, or claimed by someone else, in `blocks`.
		EraPaid {
			era: EraIndex,
			blocks: BlockNumberFor<T>,
		},
		/// `era` left staking's history, or staking stopped paying it, before it was
		/// paid; claims are no longer possible.
		EraExpired {
			era: EraIndex,
		},
		/// Staking refused a page; it is skipped. When the refusal holds for the
		/// validator's later pages too, they are skipped with it, under this one event.
		PayoutSkipped {
			era: EraIndex,
			validator: T::AccountId,
			page: Page,
			error: DispatchError,
		},
		/// `era` fell behind its schedule; `on_initialize` pays it now.
		BehindSchedule {
			era: EraIndex,
		},
		/// The oldest unpaid `era` leaves staking's history in `eras_left` eras;
		/// reported each era until it is paid. Only a call filter can still hold
		/// it: a pause is lifted ([`Event::ResumedToAvoidExpiry`]).
		ExpiryAtRisk {
			era: EraIndex,
			eras_left: EraIndex,
		},
		/// A pause was lifted so `era` is paid before it leaves staking's history.
		ResumedToAvoidExpiry {
			era: EraIndex,
		},
		LimitsSet {
			limits: PayoutLimits,
		},
		Paused,
		Resumed,
	}

	#[pallet::error]
	pub enum Error<T> {
		/// A share is above its hard cap.
		LimitAboveCap,
		/// `catch_up` must be at least `floor`.
		CatchUpBelowFloor,
		/// `floor` cannot fit the largest step, so a behind era could stall.
		FloorBelowStep,
		AlreadyPaused,
		NotPaused,
		/// The oldest unpaid era is within `ExpiryMargin` eras of leaving
		/// staking's history: a pause would let it expire.
		ExpiryNear,
	}

	impl<T> From<LimitsError> for Error<T> {
		fn from(e: LimitsError) -> Self {
			match e {
				LimitsError::AboveCap => Error::LimitAboveCap,
				LimitsError::CatchUpBelowFloor => Error::CatchUpBelowFloor,
				LimitsError::FloorBelowStep => Error::FloorBelowStep,
			}
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(now: BlockNumberFor<T>) -> Weight {
			Self::on_initialize_block(now)
		}

		fn on_idle(now: BlockNumberFor<T>, remaining: Weight) -> Weight {
			Self::on_idle_block(now, remaining)
		}

		fn integrity_test() {
			use sp_runtime::traits::Zero;
			assert!(
				!T::PaymentWindow::get().is_zero(),
				"PaymentWindow must be positive"
			);
			assert!(
				T::MaxValidators::get() > 0,
				"MaxValidators must be positive"
			);
			assert!(
				T::MaxQueuedEras::get() >= T::Payouts::history_depth(),
				"MaxQueuedEras must cover staking's history depth"
			);
			assert!(T::Payouts::page_size() > 0, "page size must be positive");
			assert!(
				T::ExpiryMargin::get() > 0 && T::ExpiryMargin::get() < T::Payouts::history_depth(),
				"ExpiryMargin must be positive and below the history depth"
			);
			if let Err(e) = Self::check_limits(&T::DefaultLimits::get()) {
				panic!("DefaultLimits are invalid: {e:?}");
			}
		}

		#[cfg(feature = "try-runtime")]
		fn try_state(_: BlockNumberFor<T>) -> Result<(), sp_runtime::TryRuntimeError> {
			Self::do_try_state()
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Sets the shares of each block automatic payment may spend, within the
		/// caps in code and so that `floor` fits the largest step.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::set_limits())]
		pub fn set_limits(origin: OriginFor<T>, limits: PayoutLimits) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;
			Self::check_limits(&limits).map_err(Error::<T>::from)?;
			Limits::<T>::put(limits);
			Self::deposit_event(Event::LimitsSet { limits });
			Ok(())
		}

		/// Stops automatic payment. Eras keep queueing and manual claims keep
		/// working. A pause cannot cost rewards: it is lifted once the oldest
		/// unpaid era is [`Config::ExpiryMargin`] eras from leaving staking's
		/// history, and refused from then on until that era is paid. Holding
		/// payment past that takes a call filter.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::pause())]
		pub fn pause(origin: OriginFor<T>) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;
			ensure!(!Paused::<T>::get(), Error::<T>::AlreadyPaused);
			ensure!(!Self::expiry_is_near(), Error::<T>::ExpiryNear);
			Paused::<T>::put(true);
			Self::deposit_event(Event::Paused);
			Ok(())
		}

		/// Resumes automatic payment where it stopped.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::resume())]
		pub fn resume(origin: OriginFor<T>) -> DispatchResult {
			T::AdminOrigin::ensure_origin(origin)?;
			ensure!(Paused::<T>::get(), Error::<T>::NotPaused);
			Paused::<T>::kill();
			Self::deposit_event(Event::Resumed);
			Ok(())
		}
	}
}
