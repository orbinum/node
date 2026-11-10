use frame_support::{derive_impl, parameter_types, traits::ConstU64};
use sp_runtime::{BuildStorage, traits::IdentityLookup};

use crate as pallet_validator_set;

pub type AccountId = u64;

// ── Prerequisite mock controls ────────────────────────────────────────────────
//
// Tests toggle this thread-local to simulate missing session keys without
// needing real pallet-session state.

use std::cell::RefCell;

thread_local! {
	static MOCK_HAS_SESSION_KEYS: RefCell<bool> = const { RefCell::new(true) };
	static REMOVED_HOOK_CALLS: RefCell<Vec<AccountId>> = const { RefCell::new(Vec::new()) };
	static OPEN_MODE_ALLOWED: RefCell<bool> = const { RefCell::new(true) };
	static ACTIVE_VALIDATORS: RefCell<Option<Vec<AccountId>>> = const { RefCell::new(None) };
	static QUEUED_VALIDATORS: RefCell<Option<Vec<AccountId>>> = const { RefCell::new(None) };
	static DISABLED_VALIDATORS: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
	static INADMISSIBLE_CANDIDATES: RefCell<Vec<AccountId>> = const { RefCell::new(Vec::new()) };
}

/// Make `who` a candidate the runtime no longer admits.
pub fn set_inadmissible_candidate(who: AccountId) {
	INADMISSIBLE_CANDIDATES.with(|v| v.borrow_mut().push(who));
}

pub struct MockCandidacy;
impl pallet_validator_set::Candidacy<AccountId> for MockCandidacy {
	fn is_inadmissible_candidate(who: &AccountId) -> bool {
		INADMISSIBLE_CANDIDATES.with(|v| v.borrow().contains(who))
	}
}

/// Set what `Config::OpenModeGuard` answers.
pub fn set_open_mode_allowed(val: bool) {
	OPEN_MODE_ALLOWED.with(|v| *v.borrow_mut() = val);
}

/// Override the session's validators; `None` mirrors `ApprovedValidators`, as a
/// session fed by this pallet would.
pub fn set_active_validators(validators: Option<Vec<AccountId>>) {
	ACTIVE_VALIDATORS.with(|v| *v.borrow_mut() = validators);
}

pub struct MockOpenModeGuard;
impl pallet_validator_set::OpenModeGuard for MockOpenModeGuard {
	fn can_open() -> bool {
		OPEN_MODE_ALLOWED.with(|v| *v.borrow())
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_can_open() {
		set_open_mode_allowed(true);
	}
}

/// Override the validators queued for the next session; `None` mirrors the
/// active ones, as when the next session keeps the set.
pub fn set_queued_validators(validators: Option<Vec<AccountId>>) {
	QUEUED_VALIDATORS.with(|v| *v.borrow_mut() = validators);
}

/// Disables the active validators at `indices` for the session.
pub fn set_disabled_validators(indices: Vec<u32>) {
	DISABLED_VALIDATORS.with(|d| *d.borrow_mut() = indices);
}

pub struct MockDisabledValidators;
impl frame_support::traits::DisabledValidators for MockDisabledValidators {
	fn is_disabled(index: u32) -> bool {
		DISABLED_VALIDATORS.with(|d| d.borrow().contains(&index))
	}
	fn disabled_validators() -> Vec<u32> {
		DISABLED_VALIDATORS.with(|d| d.borrow().clone())
	}
}

pub struct MockQueuedValidators;
impl frame_support::traits::Get<Vec<AccountId>> for MockQueuedValidators {
	fn get() -> Vec<AccountId> {
		QUEUED_VALIDATORS
			.with(|v| v.borrow().clone())
			.unwrap_or_else(MockActiveValidators::get)
	}
}

pub struct MockActiveValidators;
impl frame_support::traits::Get<Vec<AccountId>> for MockActiveValidators {
	fn get() -> Vec<AccountId> {
		ACTIVE_VALIDATORS
			.with(|v| v.borrow().clone())
			.unwrap_or_else(|| pallet_validator_set::ApprovedValidators::<Test>::get().into_inner())
	}
}

/// Set whether `MockPrerequisites::has_session_keys` returns `true` or `false`.
pub fn set_mock_session_keys(val: bool) {
	MOCK_HAS_SESSION_KEYS.with(|v| *v.borrow_mut() = val);
}

/// Accounts passed to `OnValidatorRemoved`, in call order.
pub fn removed_hook_calls() -> Vec<AccountId> {
	REMOVED_HOOK_CALLS.with(|v| v.borrow().clone())
}

pub struct MockPrerequisites;
impl pallet_validator_set::ValidatorPrerequisites<AccountId> for MockPrerequisites {
	fn has_session_keys(_who: &AccountId) -> bool {
		MOCK_HAS_SESSION_KEYS.with(|v| *v.borrow())
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_session_keys(_who: &AccountId) {}
}

/// Records every removal so tests can assert the hook fired.
pub struct MockOnValidatorRemoved;
impl pallet_validator_set::OnValidatorRemoved<AccountId> for MockOnValidatorRemoved {
	fn on_validator_removed(who: &AccountId) {
		REMOVED_HOOK_CALLS.with(|v| v.borrow_mut().push(*who));
		INADMISSIBLE_CANDIDATES.with(|v| v.borrow_mut().retain(|c| c != who));
	}

	/// A candidate without keys: the runtime's state for an inadmissible one.
	#[cfg(feature = "runtime-benchmarks")]
	fn setup_removal_state(who: &AccountId) {
		set_inadmissible_candidate(*who);
	}
}

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		ValidatorSet: pallet_validator_set,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl frame_system::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = frame_system::mocking::MockBlock<Self>;
	type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
	type Balance = u64;
	type ExistentialDeposit = ConstU64<1>;
}

parameter_types! {
	pub const MaxValidators: u32 = 10;
}

parameter_types! {
	pub const QuorumWindow: u64 = 100;
}

std::thread_local! {
	static BLOCK_AUTHOR: core::cell::RefCell<Option<AccountId>> = const { core::cell::RefCell::new(None) };
}

/// Makes `who` the author of the blocks that follow.
pub fn set_block_author(who: Option<AccountId>) {
	BLOCK_AUTHOR.with(|a| *a.borrow_mut() = who);
}

pub struct MockFindAuthor;
impl frame_support::traits::FindAuthor<AccountId> for MockFindAuthor {
	fn find_author<'a, I>(_digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (frame_support::ConsensusEngineId, &'a [u8])>,
	{
		BLOCK_AUTHOR.with(|a| *a.borrow())
	}
}

impl pallet_validator_set::Config for Test {
	type AddRemoveOrigin = frame_system::EnsureRoot<AccountId>;
	type MaxValidators = MaxValidators;
	type Prerequisites = MockPrerequisites;
	type OnValidatorRemoved = MockOnValidatorRemoved;
	type OpenModeGuard = MockOpenModeGuard;
	type Candidacy = MockCandidacy;
	type ActiveValidators = MockActiveValidators;
	type QueuedValidators = MockQueuedValidators;
	type DisabledValidators = MockDisabledValidators;
	type FindAuthor = MockFindAuthor;
	type QuorumWindow = QuorumWindow;
	type WeightInfo = ();
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = MockBenchmarkHelper;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct MockBenchmarkHelper;
#[cfg(feature = "runtime-benchmarks")]
impl pallet_validator_set::traits::BenchmarkHelper<AccountId> for MockBenchmarkHelper {
	fn set_active_validators(validators: Vec<AccountId>) {
		set_active_validators(Some(validators));
		set_queued_validators(None);
	}
}

// ── Test externalities builder ───────────────────────────────────────────────

pub struct ExtBuilder {
	initial_validators: Vec<AccountId>,
}

impl Default for ExtBuilder {
	fn default() -> Self {
		Self {
			initial_validators: vec![1, 2, 3],
		}
	}
}

impl ExtBuilder {
	pub fn validators(mut self, validators: Vec<AccountId>) -> Self {
		self.initial_validators = validators;
		self
	}

	pub fn build(self) -> sp_io::TestExternalities {
		// Thread-locals outlive externalities and tests share a thread, so reset
		// them here: otherwise a test that flips the session-key gate leaks into
		// whichever test happens to run next.
		MOCK_HAS_SESSION_KEYS.with(|v| *v.borrow_mut() = true);
		REMOVED_HOOK_CALLS.with(|v| v.borrow_mut().clear());
		set_open_mode_allowed(true);
		set_active_validators(None);
		set_queued_validators(None);
		set_block_author(None);
		INADMISSIBLE_CANDIDATES.with(|v| v.borrow_mut().clear());

		let mut storage = frame_system::GenesisConfig::<Test>::default()
			.build_storage()
			.unwrap();

		pallet_validator_set::GenesisConfig::<Test> {
			initial_validators: self.initial_validators,
		}
		.assimilate_storage(&mut storage)
		.unwrap();

		// Pre-fund well-known test accounts so they exist and can dispatch.
		pallet_balances::GenesisConfig::<Test> {
			balances: vec![
				(10u64, 10_000),
				(20u64, 10_000),
				(30u64, 10_000),
				(42u64, 10_000),
				(99u64, 10_000),
				(100u64, 10_000),
				(200u64, 10_000),
			],
			dev_accounts: None,
		}
		.assimilate_storage(&mut storage)
		.unwrap();

		let mut ext = sp_io::TestExternalities::new(storage);
		ext.execute_with(|| System::set_block_number(1));
		ext
	}
}
