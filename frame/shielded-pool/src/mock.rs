//! Mock runtime for testing pallet-shielded-pool

use crate as pallet_shielded_pool;
use frame_support::{
	PalletId, derive_impl, parameter_types,
	traits::{ConstU32, ConstU128},
};
use frame_system::EnsureRoot;
use pallet_zk_verifier::ZkVerifierPort;
use sp_runtime::{AccountId32, BuildStorage, traits::IdentityLookup};

type Block = frame_system::mocking::MockBlock<Test>;
type AccountId = AccountId32;

/// Build a deterministic 32-byte test account (mirrors production `AccountId32`).
pub fn acc(n: u8) -> AccountId {
	AccountId32::new([n; 32])
}

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		ZkVerifier: pallet_zk_verifier,
		Relayer: pallet_relayer,
		ShieldedPool: pallet_shielded_pool,
	}
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountData = pallet_balances::AccountData<u128>;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<AccountId>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
	type AccountStore = System;
	type Balance = u128;
	type ExistentialDeposit = ConstU128<1>;
}

parameter_types! {
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shldpool");
	pub const MaxTreeDepth: u32 = 20;
	/// Safety cap on queue length, not the retention window. Sized well above
	/// what a test inserts within one window so the cap branch stays the
	/// exceptional path here, as it is in production.
	pub const MaxHistoricRoots: u32 = 4096;
	/// Above `TX_LONGEVITY` (64), as `integrity_test` requires. Small enough that
	/// a test can advance past it to exercise expiry.
	pub const RootRetentionBlocks: u64 = 128;
	pub const MaxLeavesPerTree: u32 = 8;
	pub const MaxProofSize: u32 = 256;
	pub const MaxPublicInputs: u32 = 10;
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
		_asset_id: u32,
		_fee: u128,
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Validate basic format (proof should not be empty)
		if proof.is_empty() {
			return Err(sp_runtime::DispatchError::Other("Empty proof"));
		}
		// Always return true for testing (bypass ZK verification)
		Ok(true)
	}

	#[allow(clippy::too_many_arguments)]
	fn verify_unshield_proof(
		proof: &[u8],
		_merkle_root: &[u8; 32],
		_nullifier: &[u8; 32],
		_amount: u128,
		_recipient: &[u8; 32],
		_asset_id: u32,
		_fee: u128,
		_change_commitment: &[u8; 32],
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		// Validate basic format
		if proof.is_empty() {
			return Err(sp_runtime::DispatchError::Other("Empty proof"));
		}
		// Always return true for testing (bypass ZK verification)
		Ok(true)
	}

	fn verify_value_proof(
		proof: &[u8],
		_public_signals: &[u8],
		_version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		if proof.is_empty() {
			return Err(sp_runtime::DispatchError::Other("Empty proof"));
		}
		if proof[0] == 0x00 {
			return Ok(false);
		}
		Ok(true)
	}

	fn is_supported_version(_circuit_id: u32, version: u32) -> bool {
		version != 0
	}
}

/// Block-author provider for the real `pallet-relayer` in tests.
///
/// Returns `None` when the raw `b"mock:no_author"` flag is set (see
/// `mock_clear_block_author`), otherwise `Some(acc(1))` (Alice) — preserving the
/// behavior the previous `MockRelayer` exposed.
pub struct MockBlockAuthor;
impl frame_support::traits::Get<Option<AccountId>> for MockBlockAuthor {
	fn get() -> Option<AccountId> {
		if sp_io::storage::get(b"mock:no_author").is_some() {
			None
		} else {
			Some(acc(1))
		}
	}
}

impl pallet_relayer::Config for Test {
	type BlockAuthor = MockBlockAuthor;
	type DefaultMinRelayFee = ConstU128<0>;
	type ManageOrigin = EnsureRoot<AccountId>;
	type MaxAllowedSelectors = ConstU32<16>;
	type WeightInfo = ();
}

impl pallet_shielded_pool::Config for Test {
	type Currency = Balances;
	type ZkVerifier = MockZkVerifier;
	type PalletId = ShieldedPoolPalletId;
	type MaxTreeDepth = MaxTreeDepth;
	type MaxHistoricRoots = MaxHistoricRoots;
	type RootRetentionBlocks = RootRetentionBlocks;
	type MaxLeavesPerTree = MaxLeavesPerTree;
	type WeightInfo = ();
	type Relayer = pallet_relayer::Pallet<Test>;
}

// ── Relayer test helpers ─────────────────────────────────────────────────────
//
// These drive the REAL `pallet-relayer` storage so `mock::Test` exercises the
// same code path as the runtime. Signatures are unchanged from the previous
// `MockRelayer` helpers, so callers stay the same.

/// Read a pending-fee balance from `pallet-relayer`.
pub fn mock_pending_fees_get(who: AccountId, asset_id: u32) -> u128 {
	pallet_relayer::PendingRelayerFees::<Test>::get(who, asset_id)
}

/// Write a pending-fee balance into `pallet-relayer`.
pub fn mock_pending_fees_set(who: AccountId, asset_id: u32, amount: u128) {
	pallet_relayer::PendingRelayerFees::<Test>::insert(who, asset_id, amount);
}

/// Read the registered EVM address for an account from `pallet-relayer`'s
/// reverse index.
#[allow(dead_code)]
pub fn mock_evm_address_get(who: AccountId) -> Option<sp_core::H160> {
	pallet_relayer::RelayerByAccount::<Test>::get(who)
}

/// Set the minimum relay fee in `pallet-relayer`.
/// Defaults to 0 (`DefaultMinRelayFee = ConstU128<0>`); call this to raise the floor.
pub fn mock_set_min_relay_fee(fee: u128) {
	pallet_relayer::MinRelayFee::<Test>::put(fee);
}

/// Register an EVM address → account mapping so `resolve_relayer` returns `Some`.
/// Writes directly into `pallet-relayer`'s registry for tests.
pub fn mock_register_relayer(who: AccountId, addr: sp_core::H160) {
	pallet_relayer::RelayerRegistry::<Test>::insert(addr, who);
}

/// Force the relayer's `block_author()` to return `None` (default is `Some(acc(1))`),
/// to test the no-fee-recipient path. Read by `MockBlockAuthor`.
pub fn mock_clear_block_author() {
	sp_io::storage::set(b"mock:no_author", &[1u8]);
}

/// Build genesis storage for testing
pub fn new_test_ext() -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default()
		.build_storage()
		.unwrap();

	pallet_balances::GenesisConfig::<Test> {
		balances: vec![
			(acc(1), 1_000_000),
			(acc(2), 1_000_000),
			(acc(3), 1_000_000),
		],
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
