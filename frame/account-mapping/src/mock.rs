use crate::{self as pallet_account_mapping, PrivateLinkVerifierPort};
use frame_support::{derive_impl, parameter_types};
use sp_core::H160;
use sp_keystore::{testing::MemoryKeystore, KeystoreExt};
use sp_runtime::{
	traits::{BlakeTwo256, Convert, IdentityLookup},
	BuildStorage,
};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		AccountMapping: pallet_account_mapping,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type RuntimeEvent = RuntimeEvent;
	type RuntimeTask = RuntimeTask;
	type Hash = sp_core::H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Nonce = u64;
	type BlockHashCount = frame_support::traits::ConstU64<250>;
	type DbWeight = frame_support::weights::constants::RocksDbWeight;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type BaseCallFilter = frame_support::traits::Everything;
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
}

pub struct TestEvmAddress;
impl Convert<u64, Option<H160>> for TestEvmAddress {
	fn convert(account: u64) -> Option<H160> {
		if account == 42 {
			None
		} else {
			Some(H160::from_low_u64_be(account % 2))
		}
	}
}

parameter_types! {
	pub const TestAliasDeposit: u64 = 100;
	pub const TestMaxAliasLength: u32 = 32;
}

impl pallet_account_mapping::Config for Test {
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type AccountIdToEvmAddress = TestEvmAddress;
	type AliasDeposit = TestAliasDeposit;
	type MaxAliasLength = TestMaxAliasLength;
	type WeightInfo = pallet_account_mapping::weights::SubstrateWeight<Test>;
	type PrivateLinkVerifier = MockPrivateLinkVerifier;
}

pub struct MockPrivateLinkVerifier;
impl PrivateLinkVerifierPort for MockPrivateLinkVerifier {
	fn verify(_commitment: &[u8; 32], _call_hash: &[u8; 32], proof: &[u8]) -> bool {
		proof.first().copied() == Some(0x01)
	}
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();
	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(1, 10_000), (2, 10_000), (3, 10_000), (42, 10_000)],
		dev_accounts: None,
	}
	.assimilate_storage(&mut t)
	.unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.register_extension(KeystoreExt::new(MemoryKeystore::new()));
	ext.execute_with(|| System::set_block_number(1));
	ext
}
