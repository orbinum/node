//! Mock runtime for testing pallet-shielded-pool

use crate as pallet_shielded_pool;
use frame_support::{
	PalletId, derive_impl, parameter_types,
	traits::{ConstU32, ConstU64, ConstU128},
};
use frame_system::EnsureRoot;
use pallet_zk_verifier::{TransferStatement, UnshieldStatement, ZkVerifierPort};
use sp_runtime::{AccountId32, BuildStorage, traits::IdentityLookup};

type Block = frame_system::mocking::MockBlock<Test>;
pub type AccountId = AccountId32;

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
	/// Cut at level 2 with `MaxLeavesPerTree = 8`: levels 1..2 are pruned and
	/// level 3+ kept, so a test can seal a tree and exercise both the pruned and
	/// the stored branch of `get_merkle_path`.
	pub const SealedTreePrunedBelowLevel: u8 = 2;
	pub const MaxLeavesPerTree: u32 = 8;
	pub const MaxProofSize: u32 = 256;
	pub const MaxPublicInputs: u32 = 10;
}

impl pallet_zk_verifier::Config for Test {
	type MaxProofSize = MaxProofSize;
	type MaxPublicInputs = MaxPublicInputs;
	type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Test>;
}

/// Accepts every non-empty proof (unless told otherwise with
/// [`set_mock_proof_valid`]) and records the statement it was asked to check,
/// so tests can assert what reaches the verifier.
///
/// Bypasses all cryptography: tests with it cover business logic only.
pub struct MockZkVerifier;

/// A statement [`MockZkVerifier`] was asked to verify, with its version.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VerifiedStatement {
	Transfer(TransferStatement, Option<u32>),
	Unshield(UnshieldStatement, Option<u32>),
}

std::thread_local! {
	static VERIFIED: core::cell::RefCell<Vec<VerifiedStatement>> = const { core::cell::RefCell::new(Vec::new()) };
	static PROOF_VALID: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
}

/// Make every later verification in this test return `valid`.
#[cfg_attr(feature = "skip-proof-verification", allow(dead_code))]
pub fn set_mock_proof_valid(valid: bool) {
	PROOF_VALID.with(|v| v.set(valid));
}

/// Statements verified so far in this test, oldest first.
pub fn verified_statements() -> Vec<VerifiedStatement> {
	VERIFIED.with(|v| v.borrow().clone())
}

fn record(proof: &[u8], statement: VerifiedStatement) -> Result<bool, sp_runtime::DispatchError> {
	if proof.is_empty() {
		return Err(sp_runtime::DispatchError::Other("Empty proof"));
	}
	VERIFIED.with(|v| v.borrow_mut().push(statement));
	Ok(PROOF_VALID.with(|v| v.get()))
}

impl ZkVerifierPort for MockZkVerifier {
	fn verify_transfer_proof(
		proof: &[u8],
		statement: &TransferStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		record(
			proof,
			VerifiedStatement::Transfer(statement.clone(), version),
		)
	}

	fn verify_unshield_proof(
		proof: &[u8],
		statement: &UnshieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError> {
		record(proof, VerifiedStatement::Unshield(*statement, version))
	}

	fn is_supported_version(_circuit_id: u32, version: u32) -> bool {
		version != 0
	}

	fn verification_weight() -> frame_support::weights::Weight {
		frame_support::weights::Weight::from_parts(11_700_000_000, 0)
	}
}

/// `H160 ++ [0u8; 12]`, the runtime's EVM address mapping.
pub struct MirrorAccount;

impl sp_runtime::traits::Convert<sp_core::H160, AccountId> for MirrorAccount {
	fn convert(address: sp_core::H160) -> AccountId {
		let mut bytes = [0u8; 32];
		bytes[..20].copy_from_slice(address.as_bytes());
		AccountId::from(bytes)
	}
}

/// Block-author provider for the real `pallet-relayer` in tests.
///
/// Returns `None` when the raw `b"mock:no_author"` flag is set (see
/// `mock_clear_block_author`), otherwise `Some(acc(1))`.
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
	type MaxMinRelayFee = ConstU128<{ u128::MAX }>;
	type ManageOrigin = EnsureRoot<AccountId>;
	type MaxAllowedSelectors = ConstU32<16>;
	type ValidatorSet = ();
	type CommitTtl = ConstU64<10>;
	type MaxCommitsPerRelayerPerBlock = ConstU32<64>;
	type WeightInfo = ();
}

impl pallet_shielded_pool::Config for Test {
	type Currency = Balances;
	type ZkVerifier = MockZkVerifier;
	type PalletId = ShieldedPoolPalletId;
	type MaxTreeDepth = MaxTreeDepth;
	type MaxHistoricRoots = MaxHistoricRoots;
	type RootRetentionBlocks = RootRetentionBlocks;
	type SealedTreePrunedBelowLevel = SealedTreePrunedBelowLevel;
	type MaxLeavesPerTree = MaxLeavesPerTree;
	type WeightInfo = ();
	type Relayer = pallet_relayer::Pallet<Test>;
	type EvmAccount = MirrorAccount;
}

// ── Relayer test helpers ─────────────────────────────────────────────────────
//
// These drive the REAL `pallet-relayer` storage so `mock::Test` exercises the
// same code path as the runtime.

/// Read a pending-fee balance from `pallet-relayer`.
pub fn mock_pending_fees_get(who: AccountId, asset_id: u32) -> u128 {
	pallet_relayer::PendingRelayerFees::<Test>::get(who, asset_id)
}

/// Write a pending-fee balance into `pallet-relayer`.
pub fn mock_pending_fees_set(who: AccountId, asset_id: u32, amount: u128) {
	pallet_relayer::PendingRelayerFees::<Test>::insert(who, asset_id, amount);
}

/// Set the minimum relay fee in `pallet-relayer`.
/// Defaults to 0 (`DefaultMinRelayFee = ConstU128<0>`); call this to raise the floor.
pub fn mock_set_min_relay_fee(fee: u128) {
	pallet_relayer::MinRelayFee::<Test>::put(fee);
}

/// Register an EVM address → account mapping so `resolve_relayer` returns `Some`.
/// Writes directly into `pallet-relayer`'s registry for tests.
pub fn mock_register_relayer(who: AccountId, addr: sp_core::H160) {
	pallet_relayer::RelayerRegistry::<Test>::insert(addr, who.clone());
	// Both indexes: fee crediting and EVM claims resolve H160 -> account, while
	// signed relayer calls resolve account -> H160. `register_relayer` writes
	// both, so a helper that wrote only one would let a test pass against state
	// the runtime cannot produce.
	pallet_relayer::RelayerByAccount::<Test>::insert(who, addr);
}

/// Force the relayer's `block_author()` to return `None` (default is `Some(acc(1))`),
/// to test the no-fee-recipient path. Read by `MockBlockAuthor`.
pub fn mock_clear_block_author() {
	sp_io::storage::set(b"mock:no_author", &[1u8]);
}

/// Build genesis storage for testing
pub fn new_test_ext() -> sp_io::TestExternalities {
	VERIFIED.with(|v| v.borrow_mut().clear());
	PROOF_VALID.with(|v| v.set(true));
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
