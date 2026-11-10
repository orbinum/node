//! What admission checks so dispatch cannot fail: the memo's shape and the proof.

use super::*;

// ── memo shape ───────────────────────────────────────────────────────────────

#[test]
fn transfer_memos_must_be_one_full_memo_per_output() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let base = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01, 0x02]), 0, 1);
		let short = EncryptedMemo::new(vec![0x0A; 179]).unwrap();
		for memos in [vec![full_memo()], vec![full_memo(), short]] {
			let req = TransferRequest {
				memos: memos.try_into().unwrap(),
				..base.clone()
			};
			assert!(rejected_with(
				admit::validate_private_transfer::<Test>(Some(&proof()), &req),
				codes::INVALID_MEMO
			));
		}
		assert!(admit::validate_private_transfer::<Test>(Some(&proof()), &base).is_ok());
	});
}

#[test]
fn unshield_change_memo_is_absent_for_total_and_full_for_partial() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		let total = unshield_request(&KNOWN_ROOT, &nullifier(0x31), 0, 100, 0, 1);
		let mut change = [0u8; 32];
		change[1] = 0xCC;
		let partial = UnshieldRequest {
			change_commitment: change,
			..total.clone()
		};
		let short = EncryptedMemo::new(vec![0x0A; 7]).unwrap();

		let cases = [
			(
				UnshieldRequest {
					change_memo: full_memo(),
					..total.clone()
				},
				false,
			),
			(partial.clone(), false),
			(
				UnshieldRequest {
					change_memo: short,
					..partial.clone()
				},
				false,
			),
			(
				UnshieldRequest {
					change_memo: full_memo(),
					..partial
				},
				true,
			),
			(total, true),
		];
		for (req, ok) in cases {
			let result = admit::validate_unshield::<Test>(Some(&proof()), &req);
			if ok {
				assert!(result.is_ok(), "{req:?}");
			} else {
				assert!(rejected_with(result, codes::INVALID_MEMO), "{req:?}");
			}
		}
	});
}
// ── proof at admission, not in the block ─────────────────────────────────────

#[test]
#[cfg(not(feature = "skip-proof-verification"))]
fn an_invalid_proof_is_refused_at_admission() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		crate::tests::mock::set_mock_proof_valid(false);
		assert!(rejected_with(
			validate_private_transfer(&KNOWN_ROOT, &nullifiers_of(&[0x01]), &0u128, 1),
			codes::INVALID_PROOF
		));
		assert!(rejected_with(
			validate_unshield(&KNOWN_ROOT, &nullifier(0x41), &0, &100, &0, 1),
			codes::INVALID_PROOF
		));
	});
}

#[test]
#[cfg(not(feature = "skip-proof-verification"))]
fn admission_verifies_the_statement_the_extrinsic_would() {
	use crate::tests::mock::{VerifiedStatement, verified_statements};
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		let transfer = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01]), 0, 2);
		let unshield = unshield_request(&KNOWN_ROOT, &nullifier(0x42), 0, 100, 0, 2);
		assert!(admit::validate_private_transfer::<Test>(Some(&proof()), &transfer).is_ok());
		assert!(admit::validate_unshield::<Test>(Some(&proof()), &unshield).is_ok());
		assert_eq!(
			verified_statements(),
			vec![
				VerifiedStatement::Transfer(transfer.statement(), Some(2)),
				VerifiedStatement::Unshield(unshield.statement().unwrap(), Some(2)),
			]
		);
	});
}

/// In a block the dispatchable verifies; `pre_dispatch` must not pay a second
/// pairing the extrinsic weight does not cover.
#[test]
#[cfg(not(feature = "skip-proof-verification"))]
#[allow(deprecated)] // `ValidateUnsigned`, see `lib.rs`
fn pre_dispatch_runs_the_cheap_checks_only() {
	use crate::{Call, Pallet, tests::mock::verified_statements};
	use sp_runtime::traits::ValidateUnsigned;
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		crate::tests::mock::set_mock_proof_valid(false);
		let call = Call::<Test>::unshield {
			proof: proof(),
			merkle_root: KNOWN_ROOT,
			nullifier: nullifier(0x43),
			asset_id: 0,
			amount: 100,
			recipient: acc(2),
			fee: 0,
			change_commitment: [0u8; 32],
			change_encrypted_memo: EncryptedMemo::default(),
			circuit_version: 1,
		};
		assert!(Pallet::<Test>::pre_dispatch(&call).is_ok());
		assert!(verified_statements().is_empty());
		assert!(rejected_with(
			Pallet::<Test>::validate_unsigned(
				sp_runtime::transaction_validity::TransactionSource::External,
				&call
			),
			codes::INVALID_PROOF
		));
	});
}
// ── nothing admitted may fail at dispatch ────────────────────────────────────

/// A spend that passes admission but fails in the block keeps its nullifier
/// unspent and pays nothing: free, repeatable block filler.
#[test]
fn transfers_the_dispatch_would_refuse_are_refused_at_admission() {
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		let base = transfer_request(&KNOWN_ROOT, &nullifiers_of(&[0x01, 0x02]), 0, 1);
		let twins = TransferRequest {
			commitments: vec![base.commitments[0]; 2].try_into().unwrap(),
			..base.clone()
		};
		assert!(rejected_with(
			admit::validate_private_transfer::<Test>(Some(&proof()), &twins),
			codes::INVALID_SPEND
		));

		crate::merkle::MerkleTreeService::insert_leaf::<Test>(base.commitments[1]).unwrap();
		assert!(rejected_with(
			admit::validate_private_transfer::<Test>(Some(&proof()), &base),
			codes::INVALID_SPEND
		));
	});
}

#[test]
fn unshields_the_dispatch_would_refuse_are_refused_at_admission() {
	use crate::Pallet;
	new_test_ext().execute_with(|| {
		MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
		PoolBalanceRepository::set_asset_balance::<Test>(0, 1_000);
		let base = unshield_request(&KNOWN_ROOT, &nullifier(0x51), 0, 100, 0, 1);
		let mut existing = [0u8; 32];
		existing[1] = 0xEE;
		crate::merkle::MerkleTreeService::insert_leaf::<Test>(Commitment::new(existing)).unwrap();

		let dead = [
			UnshieldRequest {
				amount: 0,
				fee: 100,
				..base.clone()
			},
			UnshieldRequest {
				recipient: Pallet::<Test>::pool_account_id(),
				..base.clone()
			},
			UnshieldRequest {
				recipient: sp_runtime::AccountId32::new([0u8; 32]),
				..base.clone()
			},
			UnshieldRequest {
				change_commitment: existing,
				change_memo: full_memo(),
				..base.clone()
			},
			UnshieldRequest {
				asset_id: 99,
				..base.clone()
			},
		];
		for req in dead {
			let result = admit::validate_unshield::<Test>(Some(&proof()), &req);
			assert!(result.is_err(), "{req:?} was admitted");
		}
		assert!(admit::validate_unshield::<Test>(Some(&proof()), &base).is_ok());
	});
}
