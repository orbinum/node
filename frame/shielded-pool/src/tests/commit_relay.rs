//! The `commit_relay` extrinsic: who may record commits, and for which address.

use super::{KNOWN_ROOT, evm, fund_pool, nullifier, proof, setup_asset};
use crate::{
	MAX_RELAY_COMMITS_PER_CALL, RawOrigin,
	mock::{RuntimeOrigin, ShieldedPool, Test, acc, mock_register_relayer, new_test_ext},
	pallet::Error,
};
use frame_support::{
	BoundedVec, assert_noop, assert_ok, pallet_prelude::ConstU32, sp_runtime::traits::BadOrigin,
};
use sp_core::H256;

fn commits(seeds: &[u8]) -> BoundedVec<H256, ConstU32<MAX_RELAY_COMMITS_PER_CALL>> {
	seeds
		.iter()
		.map(|s| H256::repeat_byte(*s))
		.collect::<Vec<_>>()
		.try_into()
		.unwrap()
}

fn recorded(commit: u8) -> bool {
	pallet_relayer::RelayCommits::<Test>::contains_key(H256::repeat_byte(commit))
}

#[test]
fn a_registered_signer_commits_under_its_registered_address() {
	new_test_ext().execute_with(|| {
		mock_register_relayer(acc(7), evm(0xB7));
		assert_ok!(ShieldedPool::commit_relay(
			RuntimeOrigin::signed(acc(7)),
			commits(&[1, 2])
		));
		assert!(recorded(1) && recorded(2));
		let index = pallet_relayer::CommitsByRelayer::<Test>::iter_values()
			.next()
			.unwrap();
		assert_eq!(index.len(), 2);
	});
}

#[test]
fn an_unregistered_signer_is_rejected() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ShieldedPool::commit_relay(RuntimeOrigin::signed(acc(8)), commits(&[1])),
			Error::<Test>::RelayerNotRegistered
		);
	});
}

#[test]
fn a_registered_evm_caller_commits_through_the_precompile_origin() {
	new_test_ext().execute_with(|| {
		mock_register_relayer(acc(7), evm(0xB7));
		assert_ok!(ShieldedPool::commit_relay(
			RawOrigin::Relayed(evm(0xB7)).into(),
			commits(&[3])
		));
		assert!(recorded(3));
	});
}

#[test]
fn an_unregistered_evm_caller_is_rejected_by_the_relayer_pallet() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ShieldedPool::commit_relay(RawOrigin::Relayed(evm(0xEE)).into(), commits(&[4])),
			pallet_relayer::Error::<Test>::NotRegistered
		);
	});
}

#[test]
fn unsigned_and_root_are_bad_origins() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			ShieldedPool::commit_relay(RuntimeOrigin::none(), commits(&[5])),
			BadOrigin
		);
		assert_noop!(
			ShieldedPool::commit_relay(RuntimeOrigin::root(), commits(&[5])),
			BadOrigin
		);
	});
}

#[test]
fn an_empty_batch_is_rejected() {
	new_test_ext().execute_with(|| {
		mock_register_relayer(acc(7), evm(0xB7));
		assert_noop!(
			ShieldedPool::commit_relay(RuntimeOrigin::signed(acc(7)), commits(&[])),
			Error::<Test>::EmptyBatch
		);
	});
}

#[test]
fn past_the_per_block_quota_nothing_is_written() {
	new_test_ext().execute_with(|| {
		mock_register_relayer(acc(7), evm(0xB7));
		let full: Vec<u8> = (1..=64).collect();
		assert_ok!(ShieldedPool::commit_relay(
			RuntimeOrigin::signed(acc(7)),
			commits(&full)
		));
		assert_noop!(
			ShieldedPool::commit_relay(RuntimeOrigin::signed(acc(7)), commits(&[200, 201])),
			pallet_relayer::Error::<Test>::TooManyCommits
		);
		assert!(!recorded(200) && !recorded(201));
	});
}

/// The whole path through extrinsics only: commit in one block, an unsigned
/// unshield in the next credits the committed relayer, and its claim pays out,
/// with the pool ledger and the pool's balance moving together.
#[test]
fn commit_then_spend_then_claim() {
	use crate::{
		mock::{Balances, MirrorAccount, System},
		operations::unshield::UnshieldRequest,
		pallet::PoolBalancePerAsset,
		storage::MerkleRepository,
		types::EncryptedMemo,
	};
	use sp_runtime::traits::Convert;
	new_test_ext().execute_with(|| {
		let asset_id = setup_asset();
		let pool = crate::Pallet::<Test>::pool_account_id();
		fund_pool(asset_id, 1_000);
		let root = KNOWN_ROOT;
		MerkleRepository::add_historic_poseidon_root::<Test>(root);
		mock_register_relayer(acc(7), evm(0xB7));

		let request = UnshieldRequest::<Test> {
			merkle_root: root,
			nullifier: nullifier(0x4E),
			asset_id,
			amount: 100,
			recipient: acc(9),
			fee: 30,
			change_commitment: [0u8; 32],
			change_memo: EncryptedMemo::default(),
			circuit_version: 1,
		};
		let commit = pallet_relayer::relay_commit_hash(&request.op_hash().unwrap(), &evm(0xB7));
		System::set_block_number(1);
		assert_ok!(ShieldedPool::commit_relay(
			RawOrigin::Relayed(evm(0xB7)).into(),
			vec![commit].try_into().unwrap()
		));

		System::set_block_number(2);
		assert_ok!(ShieldedPool::unshield(
			RuntimeOrigin::none(),
			proof(),
			root,
			request.nullifier,
			asset_id,
			100,
			acc(9),
			30,
			[0u8; 32],
			Default::default(),
			1,
		));
		assert_eq!(
			pallet_relayer::PendingRelayerFees::<Test>::get(acc(7), asset_id),
			30
		);
		assert_eq!(PoolBalancePerAsset::<Test>::get(asset_id), 900);
		assert_eq!(Balances::free_balance(&pool), 900);

		assert_ok!(ShieldedPool::claim_relay_fees(
			RawOrigin::Relayed(evm(0xB7)).into(),
			asset_id,
			30
		));
		assert_eq!(
			pallet_relayer::PendingRelayerFees::<Test>::get(acc(7), asset_id),
			0
		);
		assert_eq!(
			Balances::free_balance(MirrorAccount::convert(evm(0xB7))),
			30
		);
		assert_eq!(PoolBalancePerAsset::<Test>::get(asset_id), 870);
		assert_eq!(Balances::free_balance(&pool), 870);
	});
}
