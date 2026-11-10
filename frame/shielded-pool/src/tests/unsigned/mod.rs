//! Pool admission of `private_transfer` and `unshield`: rejection codes, pool
//! tags, the fee floor, solvency, memo shape and the proof.

use crate::{
	operations::{private_transfer::TransferRequest, unshield::UnshieldRequest},
	storage::{MerkleRepository, NullifierRepository, PoolBalanceRepository},
	tests::{
		mock::{Test, acc, new_test_ext},
		util::{KNOWN_ROOT, memo, nullifier, nullifiers_of, proof},
	},
	types::{Commitment, EncryptedMemo, Hash, Nullifier},
	validate_unsigned::{self as admit, TX_LONGEVITY, codes},
};
use frame_support::{BoundedVec, pallet_prelude::ConstU32};
use sp_runtime::transaction_validity::TransactionValidity;

/// A full memo, the only shape a spend's outputs accept.
fn full_memo() -> EncryptedMemo {
	memo(0x0A)
}

/// A well-formed transfer with the given public values: two canonical
/// commitments with a full memo each, and a dummy second input when only one
/// nullifier is given. The outputs follow from the input notes, in any order,
/// so unrelated spends never create the same note.
fn transfer_request(
	merkle_root: &Hash,
	nullifiers: &BoundedVec<Nullifier, ConstU32<2>>,
	fee: u128,
	circuit_version: u32,
) -> TransferRequest<Test> {
	let mut nullifiers = nullifiers.clone();
	while nullifiers.len() < 2 {
		nullifiers.try_push(Nullifier::new([0u8; 32])).unwrap();
	}
	let inputs = nullifiers.iter().fold(0u8, |x, n| x ^ n.0[0]);
	let commitment = |i: u8| {
		let mut bytes = [0u8; 32];
		bytes[0] = i + 1;
		bytes[1] = 0xC0;
		bytes[2] = inputs;
		Commitment::new(bytes)
	};
	TransferRequest {
		merkle_roots: [*merkle_root; 2],
		nullifiers,
		commitments: vec![commitment(0), commitment(1)].try_into().unwrap(),
		memos: vec![full_memo(); 2].try_into().unwrap(),
		asset_id: 0,
		fee,
		circuit_version,
	}
}

/// A well-formed total unshield with the given public values.
fn unshield_request(
	merkle_root: &Hash,
	nullifier: &Nullifier,
	asset_id: u32,
	amount: u128,
	fee: u128,
	circuit_version: u32,
) -> UnshieldRequest<Test> {
	UnshieldRequest {
		merkle_root: *merkle_root,
		nullifier: *nullifier,
		asset_id,
		amount,
		recipient: acc(2),
		fee,
		change_commitment: [0u8; 32],
		change_memo: EncryptedMemo::default(),
		circuit_version,
	}
}

/// Pool admission, proof included.
fn validate_private_transfer(
	merkle_root: &Hash,
	nullifiers: &BoundedVec<Nullifier, ConstU32<2>>,
	fee: &u128,
	circuit_version: u32,
) -> TransactionValidity {
	let req = transfer_request(merkle_root, nullifiers, *fee, circuit_version);
	admit::validate_private_transfer(Some(&proof()), &req)
}

/// Pool admission, proof included.
fn validate_unshield(
	merkle_root: &Hash,
	nullifier: &Nullifier,
	asset_id: &u32,
	amount: &u128,
	fee: &u128,
	circuit_version: u32,
) -> TransactionValidity {
	let req = unshield_request(
		merkle_root,
		nullifier,
		*asset_id,
		*amount,
		*fee,
		circuit_version,
	);
	admit::validate_unshield(Some(&proof()), &req)
}

fn rejected_with(result: TransactionValidity, code: u8) -> bool {
	use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
	result
		== Err(TransactionValidityError::Invalid(
			InvalidTransaction::Custom(code),
		))
}

mod admission;
mod rejection_codes;
mod solvency;
mod spam;
mod tags;
mod transfer;
mod unshield;
