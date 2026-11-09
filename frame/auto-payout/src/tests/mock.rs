use crate::{
	self as pallet_auto_payout, EraIndex, EraPayouts, Page, PayoutLimits, PayoutOutcome,
	ValidatorPages,
};
use frame_support::{
	derive_impl, parameter_types,
	traits::{ConstU32, ConstU64, Hooks},
	weights::{RuntimeDbWeight, Weight},
};
use frame_system::limits::BlockWeights;
use sp_runtime::{BuildStorage, DispatchError, Perbill};
use std::{
	cell::RefCell,
	collections::{BTreeMap, BTreeSet},
};

pub type AccountId = u64;
pub type BlockNumber = u64;

/// A block's maximum weight: 10^9 ref-time.
pub const MAX_BLOCK: u64 = 1_000_000_000;
pub const PAGE_SIZE: u32 = 4;
pub const HISTORY_DEPTH: u32 = 10;
pub const WINDOW: u64 = 100;
pub const EXPIRY_MARGIN: u32 = 2;

/// A page of `n` nominators: 5 ms plus 1 ms each, so a full page is 0.9 %.
pub fn page_weight(n: u32) -> Weight {
	Weight::from_parts(5_000_000 + u64::from(n) * 1_000_000, 0)
}

// ── Mock staking ─────────────────────────────────────────────────────────────

#[derive(Default)]
struct Staking {
	active: Option<EraIndex>,
	/// The latest era planned, when past the active one.
	planned: Option<EraIndex>,
	eras: BTreeMap<EraIndex, Vec<ValidatorPages<AccountId>>>,
	/// Pages someone claimed: paying them again is refused as already paid.
	claimed: BTreeSet<(EraIndex, AccountId, Page)>,
	/// Pages staking refuses.
	refused: BTreeSet<(EraIndex, AccountId, Page)>,
	/// Validators staking no longer pays, from any page.
	unpayable_validators: BTreeSet<(EraIndex, AccountId)>,
	/// Eras staking no longer pays.
	unpayable_eras: BTreeSet<EraIndex>,
	/// Every call `pay` received, paid or not.
	calls: u32,
	/// The era of every call `pay` received.
	tried: Vec<EraIndex>,
	/// The runtime filters every payout call.
	blocked: bool,
	/// Paid pages report the weight of a page with no nominator paid, as staking
	/// does when its nominators' payee is `None`.
	cheap_refund: bool,
	/// Every page `pay` paid, in order.
	paid: Vec<(EraIndex, AccountId, Page)>,
	heavy: BTreeSet<BlockNumber>,
}

thread_local! {
	static STAKING: RefCell<Staking> = RefCell::new(Staking::default());
}

fn with<R>(f: impl FnOnce(&mut Staking) -> R) -> R {
	STAKING.with(|s| f(&mut s.borrow_mut()))
}

pub fn set_active_era(era: EraIndex) {
	with(|s| s.active = Some(era));
}

/// Staking plans `era`, as when the next era's election starts.
pub fn plan_era(era: EraIndex) {
	with(|s| s.planned = Some(era));
}

/// Elects `validators` for `era`: `(stash, nominators)`, each with its own stake.
pub fn elect(era: EraIndex, validators: &[(AccountId, u32)]) {
	let pages = validators
		.iter()
		.map(|&(stash, nominators)| ValidatorPages {
			stash,
			pages: nominators.div_ceil(PAGE_SIZE).max(1),
			nominators,
		})
		.collect();
	with(|s| s.eras.insert(era, pages));
}

pub fn claim(era: EraIndex, validator: AccountId, page: Page) {
	with(|s| s.claimed.insert((era, validator, page)));
}

pub fn refuse(era: EraIndex, validator: AccountId, page: Page) {
	with(|s| s.refused.insert((era, validator, page)));
}

pub fn refuse_validator(era: EraIndex, validator: AccountId) {
	with(|s| s.unpayable_validators.insert((era, validator)));
}

pub fn refuse_era(era: EraIndex) {
	with(|s| s.unpayable_eras.insert(era));
}

pub fn set_blocked(blocked: bool) {
	with(|s| s.blocked = blocked);
}

pub fn set_cheap_refund(cheap: bool) {
	with(|s| s.cheap_refund = cheap);
}

/// How many times `pay` was called.
pub fn pay_calls() -> u32 {
	with(|s| s.calls)
}

/// Whether `pay` was called for a page of `era`.
pub fn tried(era: EraIndex) -> bool {
	with(|s| s.tried.contains(&era))
}

pub fn set_heavy(block: BlockNumber) {
	with(|s| s.heavy.insert(block));
}

pub fn paid() -> Vec<(EraIndex, AccountId, Page)> {
	with(|s| s.paid.clone())
}

/// Every page of `era` was paid or claimed.
pub fn era_settled(era: EraIndex) -> bool {
	with(|s| {
		s.eras.get(&era).is_some_and(|validators| {
			validators.iter().all(|v| {
				(0..v.pages).all(|p| {
					let key = (era, v.stash, p);
					s.claimed.contains(&key) || s.refused.contains(&key)
				})
			})
		})
	})
}

pub struct MockStaking;
impl EraPayouts<AccountId, BlockNumber> for MockStaking {
	fn active_era() -> Option<EraIndex> {
		with(|s| s.active)
	}

	fn planned_era() -> Option<EraIndex> {
		with(|s| s.planned.max(s.active))
	}

	fn history_depth() -> u32 {
		HISTORY_DEPTH
	}

	fn page_size() -> u32 {
		PAGE_SIZE
	}

	fn era_validators(era: EraIndex, max: u32) -> Vec<ValidatorPages<AccountId>> {
		with(|s| {
			s.eras
				.get(&era)
				.map(|v| v.iter().take(max as usize).cloned().collect())
				.unwrap_or_default()
		})
	}

	fn page_weight(nominators: u32) -> Weight {
		page_weight(nominators)
	}

	fn pay(era: EraIndex, validator: &AccountId, page: Page) -> (PayoutOutcome, Weight) {
		with(|s| {
			s.calls += 1;
			s.tried.push(era);
			if s.blocked {
				return (PayoutOutcome::Blocked, Weight::zero());
			}
			let key = (era, *validator, page);
			// As staking: only eras within the planned era's history.
			let planned = s.planned.max(s.active).unwrap_or(0);
			if s.unpayable_eras.contains(&era) || era.saturating_add(HISTORY_DEPTH) < planned {
				return (
					PayoutOutcome::EraUnpayable(DispatchError::Other("era")),
					page_weight(PAGE_SIZE),
				);
			}
			if s.unpayable_validators.contains(&(era, *validator)) {
				return (
					PayoutOutcome::ValidatorUnpayable(DispatchError::Other("validator")),
					page_weight(PAGE_SIZE),
				);
			}
			if s.refused.contains(&key) {
				// Staking prices a refused call at its declared full page.
				return (
					PayoutOutcome::Failed(DispatchError::Other("refused")),
					page_weight(PAGE_SIZE),
				);
			}
			if !s.claimed.insert(key) {
				return (PayoutOutcome::AlreadyPaid, page_weight(0));
			}
			s.paid.push(key);
			let nominators = s
				.eras
				.get(&era)
				.and_then(|v| v.iter().find(|v| v.stash == *validator))
				.map_or(0, |v| v.nominators_on(page, PAGE_SIZE));
			let reported = if s.cheap_refund { 0 } else { nominators };
			(PayoutOutcome::Paid, page_weight(reported))
		})
	}

	fn is_heavy_block(now: BlockNumber) -> bool {
		with(|s| s.heavy.contains(&now))
	}
}

// ── Runtime ──────────────────────────────────────────────────────────────────

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		AutoPayout: pallet_auto_payout,
	}
);

parameter_types! {
	pub TestBlockWeights: BlockWeights =
		BlockWeights::with_sensible_defaults(Weight::from_parts(MAX_BLOCK, u64::MAX), Perbill::from_percent(75));
	pub const TestDbWeight: RuntimeDbWeight = RuntimeDbWeight { read: 1_000, write: 2_000 };
	pub DefaultLimits: PayoutLimits = PayoutLimits {
		floor: Perbill::from_percent(2),
		catch_up: Perbill::from_percent(4),
		idle: Perbill::from_percent(10),
	};
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = sp_runtime::traits::IdentityLookup<AccountId>;
	type BlockWeights = TestBlockWeights;
	type DbWeight = TestDbWeight;
}

impl pallet_auto_payout::Config for Test {
	type Payouts = MockStaking;
	type AdminOrigin = frame_system::EnsureRoot<AccountId>;
	type MaxValidators = ConstU32<8>;
	type MaxQueuedEras = ConstU32<HISTORY_DEPTH>;
	type PaymentWindow = ConstU64<WINDOW>;
	type ExpiryMargin = ConstU32<EXPIRY_MARGIN>;
	type DefaultLimits = DefaultLimits;
	type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	STAKING.with(|s| *s.borrow_mut() = Staking::default());
	let storage = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.expect("genesis");
	let mut ext = sp_io::TestExternalities::new(storage);
	ext.execute_with(|| System::set_block_number(1));
	ext
}

/// Runs block `n`: `on_initialize`, then `on_idle` with `idle` weight left.
/// Returns the weight each hook reported.
pub fn run_block(n: BlockNumber, idle: Weight) -> (Weight, Weight) {
	System::set_block_number(n);
	let init = AutoPayout::on_initialize(n);
	let idle = AutoPayout::on_idle(n, idle);
	AutoPayout::do_try_state().expect("invariants hold");
	(init, idle)
}

/// A quiet block: transactions left most of it unused.
pub fn quiet() -> Weight {
	Weight::from_parts(MAX_BLOCK / 2, u64::MAX)
}

/// A full block: nothing left for `on_idle`.
pub fn full() -> Weight {
	Weight::zero()
}

pub fn events() -> Vec<pallet_auto_payout::Event<Test>> {
	System::events()
		.into_iter()
		.filter_map(|r| match r.event {
			RuntimeEvent::AutoPayout(e) => Some(e),
			_ => None,
		})
		.collect()
}
