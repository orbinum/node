//! Unit tests for the pallet's extrinsics and operations, one file per concern,
//! and the fixtures they share.
//!
//! - [`origin`] — which origins may spend and call the relayer extrinsics
//! - [`unshield`] — `UnshieldOperation`: validation, settlement, fee routing
//! - [`private_transfer`] — `PrivateTransferOperation`: the same for transfers
//! - [`fees`] — relay op hashes, fee crediting and `claim_relay_fees`
//! - [`commit_relay`] — the `commit_relay` extrinsic
//!
//! Lower-level modules (merkle, storage, validate_unsigned, …) keep their tests
//! next to their code and use the fixtures below too.

mod commit_relay;
mod fees;
mod origin;
mod private_transfer;
mod unshield;

use crate::{
	mock::{Balances, Test, acc},
	operations::assets::AssetOperation,
	storage::PoolBalanceRepository,
	types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Nullifier},
};
use frame_support::{BoundedVec, assert_ok, pallet_prelude::ConstU32, traits::Currency};
use pallet_relayer::RelayerInterface as _;
use sp_core::H160;

/// A root the tests register as known before spending against it.
pub(crate) const KNOWN_ROOT: [u8; 32] = [0xAA; 32];

/// A distinct, canonical 32-byte field value for `seed`.
///
/// The seed goes in the low byte rather than filling all 32: a repeated high
/// byte puts the value above the BN254 modulus (`p` starts at 0x30), which
/// the canonicity guard refuses. Real nullifiers and commitments come out of
/// Poseidon and are always canonical.
pub(crate) fn canonical_bytes(seed: u8) -> [u8; 32] {
	let mut b = [0u8; 32];
	b[0] = seed;
	b[1] = 0xA5;
	b
}

pub(crate) fn nullifier(seed: u8) -> Nullifier {
	Nullifier::new(canonical_bytes(seed))
}

pub(crate) fn commitment(seed: u8) -> Commitment {
	Commitment::new(canonical_bytes(seed))
}

/// One nullifier per seed, in order.
pub(crate) fn nullifiers_of(seeds: &[u8]) -> BoundedVec<Nullifier, ConstU32<2>> {
	seeds
		.iter()
		.map(|&s| nullifier(s))
		.collect::<Vec<_>>()
		.try_into()
		.unwrap()
}

/// One commitment per seed, in order.
pub(crate) fn commitments_of(seeds: &[u8]) -> BoundedVec<Commitment, ConstU32<2>> {
	seeds
		.iter()
		.map(|&s| commitment(s))
		.collect::<Vec<_>>()
		.try_into()
		.unwrap()
}

/// A full-size memo filled with `byte`.
pub(crate) fn memo(byte: u8) -> EncryptedMemo {
	EncryptedMemo::from_bytes(&[byte; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap()
}

/// A 32-byte memo: non-empty but too short to hold a note's secrets.
pub(crate) fn short_memo() -> EncryptedMemo {
	EncryptedMemo::new(vec![0x01u8; 32]).unwrap()
}

/// A proof the mock verifier accepts (any non-empty bytes).
pub(crate) fn proof() -> BoundedVec<u8, ConstU32<512>> {
	BoundedVec::try_from(vec![0x01u8; 72]).unwrap()
}

pub(crate) fn evm(byte: u8) -> H160 {
	H160::repeat_byte(byte)
}

/// Register an asset without verifying it, returning its id.
pub(crate) fn register_asset() -> u32 {
	let name = BoundedVec::try_from(b"Orbinum".to_vec()).unwrap();
	let symbol = BoundedVec::try_from(b"ORB".to_vec()).unwrap();
	AssetOperation::register_asset::<Test>(name, symbol, 18, None, acc(1)).unwrap()
}

/// The asset pool operations can move: the native one, verified at genesis.
pub(crate) fn setup_asset() -> u32 {
	crate::types::NATIVE_ASSET_ID
}

/// Fund the pool both physically and in the ledger, as a shield would.
pub(crate) fn fund_pool(asset_id: u32, amount: u128) {
	Balances::make_free_balance_be(&crate::Pallet::<Test>::pool_account_id(), amount);
	PoolBalanceRepository::set_asset_balance::<Test>(asset_id, amount);
}

/// Record `relayer`'s relay commit for `op_hash`, as `commit_relay` would.
pub(crate) fn commit(relayer: H160, op_hash: &[u8; 32]) {
	assert_ok!(pallet_relayer::Pallet::<Test>::record_relay_commits(
		&relayer,
		&[pallet_relayer::relay_commit_hash(op_hash, &relayer)],
	));
}
