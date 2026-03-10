//! Mock runtime for testing pallet-shielded-pool

use crate as pallet_shielded_pool;
use frame_support::{PalletId, derive_impl, parameter_types, traits::ConstU128};
use pallet_zk_verifier::ZkVerifierPort;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		ZkVerifier: pallet_zk_verifier,
		ShieldedPool: pallet_shielded_pool,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountData = pallet_balances::AccountData<u128>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
	type Balance = u128;
	type ExistentialDeposit = ConstU128<1>;
}

parameter_types! {
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shldpool");
	pub const MaxTreeDepth: u32 = 32;
	pub const MaxHistoricRoots: u32 = 100;
	pub const MinShieldAmount: u128 = 100;
	pub const MaxProofSize: u32 = 256;
	pub const MaxPublicInputs: u32 = 10;
	pub const RequestExpiration: u64 = 1000;
}

impl pallet_zk_verifier::Config for Test {
	type MaxProofSize = MaxProofSize;
	type MaxPublicInputs = MaxPublicInputs;
	type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Test>;
}

/// Mock ZK verifier for testing - always returns true
///
/// ⚠️ WARNING: This mock bypasses all ZK proof validation!
/// Use only for testing business logic, not cryptographic correctness.
pub struct MockZkVerifier;

impl ZkVerifierPort for MockZkVerifier {
	fn verify_transfer_proof(
		proof: &[u8],
		_merkle_root: &[u8; 32],
		_nullifiers: &[[u8; 32]],
		_commitments: &[[u8; 32]],
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Validate basic format (proof should not be empty)
		if proof.is_empty() {
			return Err(sp_runtime::DispatchError::Other("Empty proof"));
		}
		// Always return true for testing (bypass ZK verification)
		Ok(true)
	}

	fn verify_unshield_proof(
		proof: &[u8],
		_merkle_root: &[u8; 32],
		_nullifier: &[u8; 32],
		_amount: u128,
		_recipient: &[u8; 32],
		_asset_id: u32,
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Validate basic format
		if proof.is_empty() {
			return Err(sp_runtime::DispatchError::Other("Empty proof"));
		}
		// Always return true for testing (bypass ZK verification)
		Ok(true)
	}

	fn verify_disclosure_proof(
		proof: &[u8],
		public_signals: &[u8],
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Validate basic format
		if proof.is_empty() {
			return Err(sp_runtime::DispatchError::Other("Empty proof"));
		}
		if public_signals.len() != 76 {
			return Err(sp_runtime::DispatchError::Other(
				"Invalid public signals length",
			));
		}
		// Always return true for testing (bypass ZK verification)
		Ok(true)
	}

	fn batch_verify_disclosure_proofs(
		proofs: &[sp_std::vec::Vec<u8>],
		public_signals: &[sp_std::vec::Vec<u8>],
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Validate basic format
		if proofs.len() != public_signals.len() {
			return Err(sp_runtime::DispatchError::Other("Mismatched array lengths"));
		}
		// Always return true for testing (bypass ZK verification)
		Ok(true)
	}

	fn verify_private_link_proof(
		proof: &[u8],
		_commitment: &[u8; 32],
		_call_hash_fe: &[u8; 32],
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Validate basic format
		if proof.is_empty() {
			return Err(sp_runtime::DispatchError::Other("Empty proof"));
		}
		// Always return true for testing (bypass ZK verification)
		Ok(true)
	}
}

impl pallet_shielded_pool::Config for Test {
	type Currency = Balances;
	type ZkVerifier = MockZkVerifier;
	type PalletId = ShieldedPoolPalletId;
	type MaxTreeDepth = MaxTreeDepth;
	type MaxHistoricRoots = MaxHistoricRoots;
	type MinShieldAmount = MinShieldAmount;
	type WeightInfo = ();
}

/// Build genesis storage for testing
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();

	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(1, 1_000_000), (2, 1_000_000), (3, 1_000_000)],
		..Default::default()
	}
	.assimilate_storage(&mut t)
	.unwrap();

	// Initialize ShieldedPool genesis
	crate::GenesisConfig::<Test> {
		initial_root: [0u8; 32],
		_phantom: Default::default(),
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1));
	ext
}
