//! Mock runtime for pallet-relayer tests.

use crate as pallet_relayer;
use frame_support::{derive_impl, parameter_types};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Relayer: pallet_relayer,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

parameter_types! {
	pub const DefaultMinRelayFee: u128 = 1_000_000_000_000_000u128; // 1e15 planck
	pub const MaxAllowedSelectors: u32 = 8;
	pub const MaxMinRelayFee: u128 = 1_000_000_000_000_000_000u128; // 1 ORB

}

/// Static block author — always Alice (account 1).
pub struct MockBlockAuthor;
impl frame_support::traits::Get<Option<u64>> for MockBlockAuthor {
	fn get() -> Option<u64> {
		Some(1u64)
	}
}

// ── Validator gate mock ───────────────────────────────────────────────────────
//
// Tests declare which accounts count as active validators. Empty by default, so
// a test that forgets to opt in sees the gate reject — the same way a runtime
// that forgets to wire `Config::ValidatorSet` does.

use std::cell::RefCell;

thread_local! {
	static MOCK_VALIDATORS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// Mark `who` as an active validator for the rest of the test.
pub fn set_mock_validator(who: u64) {
	MOCK_VALIDATORS.with(|v| v.borrow_mut().push(who));
}

/// Remove `who` from the mock validator set, so tests can exercise what happens
/// to an account that was approved and then removed.
pub fn clear_mock_validator(who: u64) {
	MOCK_VALIDATORS.with(|v| v.borrow_mut().retain(|x| *x != who));
}

pub struct MockValidatorSet;
impl pallet_validator_set::ValidatorSetInterface<u64> for MockValidatorSet {
	fn is_active_validator(who: &u64) -> bool {
		MOCK_VALIDATORS.with(|v| v.borrow().contains(who))
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_validator(who: &u64) {
		set_mock_validator(*who);
	}
}

impl pallet_relayer::Config for Test {
	type BlockAuthor = MockBlockAuthor;
	type DefaultMinRelayFee = DefaultMinRelayFee;
	type MaxMinRelayFee = MaxMinRelayFee;
	type ManageOrigin = frame_system::EnsureRoot<u64>;
	type MaxAllowedSelectors = MaxAllowedSelectors;
	type ValidatorSet = MockValidatorSet;
	type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	// Thread-locals outlive externalities; reset so tests do not leak into each other.
	MOCK_VALIDATORS.with(|v| v.borrow_mut().clear());
	let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap()
		.into();
	// Events are not registered at block 0 — advance to block 1.
	ext.execute_with(|| System::set_block_number(1));
	ext
}

/// Register `who`'s relay address with a valid ownership proof.
///
/// Tests that are not about the proof itself use this so the signature never
/// obscures what they are actually asserting. The address is derived from the
/// signing key, so each distinct `seed` yields a distinct address.
pub fn register_with_proof(
	who: u64,
	seed: &[u8; 32],
) -> (sp_core::H160, frame_support::pallet_prelude::DispatchResult) {
	let (evm_address, signature) = crate::test_signing::signed_binding_with::<Test>(&who, seed);
	let result = Relayer::register_relayer(RuntimeOrigin::signed(who), evm_address, signature);
	(evm_address, result)
}

/// The EVM address `seed` controls, without registering anything.
pub fn address_for_seed(who: u64, seed: &[u8; 32]) -> sp_core::H160 {
	crate::test_signing::signed_binding_with::<Test>(&who, seed).0
}

/// The address `seed` controls, plus a signature proving it, bound to `who`.
///
/// Returned as a pair so a test can deliberately mismatch them — signing with
/// one key while claiming another's address is the attack the proof exists to
/// stop, and it needs to be expressible.
pub fn proof_for(who: u64, seed: &[u8; 32]) -> (sp_core::H160, crate::EvmSignature) {
	crate::test_signing::signed_binding_with::<Test>(&who, seed)
}

/// Distinct signing keys, so accounts can hold distinct EVM addresses.
///
/// Named after the account that conventionally uses them; nothing enforces the
/// pairing, and a test that needs a key nobody owns can pass any other seed.
pub mod seeds {
	pub const ALICE: &[u8; 32] = &[0xb0; 32];
	pub const BOB: &[u8; 32] = &[0xb1; 32];
	pub const CAROL: &[u8; 32] = &[0xb2; 32];
}
