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
}

/// Static block author — always Alice (account 1).
pub struct MockBlockAuthor;
impl frame_support::traits::Get<Option<u64>> for MockBlockAuthor {
	fn get() -> Option<u64> {
		Some(1u64)
	}
}

/// Accounts with ID >= 100 are treated as validator nodes in tests.
pub struct MockValidators;
impl frame_support::traits::Contains<u64> for MockValidators {
	fn contains(who: &u64) -> bool {
		*who >= 100
	}
}

impl pallet_relayer::Config for Test {
	type BlockAuthor = MockBlockAuthor;
	type DefaultMinRelayFee = DefaultMinRelayFee;
	type IsValidator = MockValidators;
	type ManageOrigin = frame_system::EnsureRoot<u64>;
	type MaxAllowedSelectors = MaxAllowedSelectors;
	type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap()
		.into();
	// Events are not registered at block 0 — advance to block 1.
	ext.execute_with(|| System::set_block_number(1));
	ext
}

/// EVM address helpers for tests.
pub mod addr {
	use sp_core::H160;

	pub fn alice_evm() -> H160 {
		H160::from_low_u64_be(0xA11CE)
	}

	pub fn bob_evm() -> H160 {
		H160::from_low_u64_be(0xB0B)
	}
}
