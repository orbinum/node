//! Mock runtime for testing pallet-zk-verifier

use crate as pallet_zk_verifier;
use frame_support::{derive_impl, parameter_types};

type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		ZkVerifier: pallet_zk_verifier,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
}

parameter_types! {
	pub const MaxProofSize: u32 = 256;
	pub const MaxPublicInputs: u32 = 16;
}

impl pallet_zk_verifier::Config for Test {
	type MaxProofSize = MaxProofSize;
	type MaxPublicInputs = MaxPublicInputs;
	type WeightInfo = crate::weights::SubstrateWeight<Test>;
}

#[cfg(feature = "runtime-benchmarks")]
pub fn new_test_ext() -> sp_io::TestExternalities {
	let storage = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.expect("mock storage should build");
	sp_io::TestExternalities::new(storage)
}
