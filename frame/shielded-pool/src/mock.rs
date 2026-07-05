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
	type Relayer = MockRelayer;
}

/// Mock implementation of `RelayerInterface` for unit tests.
///
/// - `min_relay_fee()` → 0 (no minimum in tests; set higher when testing fee enforcement)
/// - `block_author()` → `Some(1u64)` (Alice)
/// - Fee tracking is backed by raw `TestExternalities` storage (auto-reset per test).
pub struct MockRelayer;

/// Read a pending-fee balance from raw test storage.
pub fn mock_pending_fees_get(who: u64, asset_id: u32) -> u128 {
	use parity_scale_codec::{Decode, Encode};
	let key = [
		b"mock:fees:".as_ref(),
		who.encode().as_slice(),
		asset_id.encode().as_slice(),
	]
	.concat();
	sp_io::storage::get(&key)
		.and_then(|v| u128::decode(&mut &v[..]).ok())
		.unwrap_or(0)
}

/// Write a pending-fee balance to raw test storage.
pub fn mock_pending_fees_set(who: u64, asset_id: u32, amount: u128) {
	use parity_scale_codec::Encode;
	let key = [
		b"mock:fees:".as_ref(),
		who.encode().as_slice(),
		asset_id.encode().as_slice(),
	]
	.concat();
	sp_io::storage::set(&key, &amount.encode());
}

/// Read the registered EVM address for an account from raw test storage.
pub fn mock_evm_address_get(who: u64) -> Option<sp_core::H160> {
	use parity_scale_codec::{Decode, Encode};
	let key = [b"mock:evm:".as_ref(), who.encode().as_slice()].concat();
	sp_io::storage::get(&key)
		.and_then(|v| <[u8; 20]>::decode(&mut &v[..]).ok())
		.map(sp_core::H160::from)
}

/// Write a minimum relay fee to raw test storage.
/// By default `MockRelayer::min_relay_fee()` returns 0; call this to raise the floor.
pub fn mock_set_min_relay_fee(fee: u128) {
	use parity_scale_codec::Encode;
	sp_io::storage::set(b"mock:min_relay_fee", &fee.encode());
}

/// Register an EVM address → account mapping so `resolve_relayer` returns `Some`.
/// Mirrors the governance-gated registry in `pallet-relayer` for tests.
pub fn mock_register_relayer(who: u64, addr: sp_core::H160) {
	use parity_scale_codec::Encode;
	let key = [b"mock:resolve:".as_ref(), addr.as_bytes()].concat();
	sp_io::storage::set(&key, &who.encode());
}

impl pallet_relayer::RelayerInterface for MockRelayer {
	type AccountId = u64;

	fn resolve_relayer(evm_address: &sp_core::H160) -> Option<u64> {
		// Reads the test registry seeded by `mock_register_relayer`; unregistered
		// addresses return None so fees fall back to block_author.
		use parity_scale_codec::Decode;
		let key = [b"mock:resolve:".as_ref(), evm_address.as_bytes()].concat();
		sp_io::storage::get(&key).and_then(|v| u64::decode(&mut &v[..]).ok())
	}

	fn min_relay_fee() -> u128 {
		use parity_scale_codec::Decode;
		sp_io::storage::get(b"mock:min_relay_fee")
			.and_then(|v| u128::decode(&mut &v[..]).ok())
			.unwrap_or(0)
	}

	fn allowed_selectors() -> sp_std::vec::Vec<[u8; 4]> {
		sp_std::vec![]
	}

	fn block_author() -> Option<u64> {
		Some(1u64)
	}

	fn accumulate_relay_fee(author: &u64, asset_id: u32, amount: u128) {
		let current = mock_pending_fees_get(*author, asset_id);
		mock_pending_fees_set(*author, asset_id, current.saturating_add(amount));
	}

	fn pending_relay_fees(who: &u64, asset_id: u32) -> u128 {
		mock_pending_fees_get(*who, asset_id)
	}

	fn consume_relay_fee(
		who: &u64,
		asset_id: u32,
		amount: u128,
	) -> frame_support::dispatch::DispatchResult {
		let balance = mock_pending_fees_get(*who, asset_id);
		if balance >= amount {
			mock_pending_fees_set(*who, asset_id, balance - amount);
			Ok(())
		} else {
			Err(sp_runtime::DispatchError::Other("InsufficientPendingFees"))
		}
	}

	fn registered_evm_address(who: &u64) -> Option<sp_core::H160> {
		mock_evm_address_get(*who)
	}
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
