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
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_removal_state(_who: &AccountId) {}
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

impl pallet_validator_set::Config for Test {
	type AddRemoveOrigin = frame_system::EnsureRoot<AccountId>;
	type MaxValidators = MaxValidators;
	type Prerequisites = MockPrerequisites;
	type OnValidatorRemoved = MockOnValidatorRemoved;
	type WeightInfo = ();
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
