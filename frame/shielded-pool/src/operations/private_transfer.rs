use crate::{
	merkle::MerkleTreeService,
	pallet::{Config, Error, Event, Pallet},
	storage::{AssetRepository, CommitmentRepository, MerkleRepository, NullifierRepository},
	types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Nullifier},
};
use frame_support::{BoundedVec, pallet_prelude::*, traits::Currency};
use pallet_relayer::RelayerInterface as _;
#[cfg(not(feature = "skip-proof-verification"))]
use pallet_zk_verifier::ZkVerifierPort;
use sp_runtime::{SaturatedConversion, traits::Zero};

pub struct PrivateTransferOperation;

impl PrivateTransferOperation {
	#[allow(clippy::too_many_arguments)]
	pub fn execute<T: Config>(
		proof: BoundedVec<u8, ConstU32<512>>,
		merkle_root: [u8; 32],
		nullifiers: BoundedVec<Nullifier, ConstU32<2>>,
		commitments: BoundedVec<Commitment, ConstU32<2>>,
		encrypted_memos: BoundedVec<EncryptedMemo, ConstU32<2>>,
		asset_id: u32,
		fee: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		relayer_evm: Option<sp_core::H160>,
		circuit_version: u32,
	) -> DispatchResult {
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);

		ensure!(
			nullifiers.len() == commitments.len(),
			Error::<T>::TooManyInputsOrOutputs
		);
		ensure!(
			encrypted_memos.len() == commitments.len(),
			Error::<T>::MemoCommitmentMismatch
		);

		for memo in encrypted_memos.iter() {
			ensure!(
				memo.0.len() == MAX_ENCRYPTED_MEMO_SIZE as usize,
				Error::<T>::InvalidMemoSize
			);
		}

		ensure!(
			MerkleRepository::is_known_root::<T>(&merkle_root),
			Error::<T>::UnknownMerkleRoot
		);

		for nullifier in nullifiers.iter() {
			if nullifier.0 == [0u8; 32] {
				continue; // dummy input — skipped by circuit, no nullifier to check
			}
			ensure!(nullifier.is_canonical(), Error::<T>::InvalidPublicSignals);
			ensure!(
				!NullifierRepository::is_used::<T>(nullifier),
				Error::<T>::NullifierAlreadyUsed
			);
		}

		let non_dummy: sp_std::vec::Vec<&Nullifier> =
			nullifiers.iter().filter(|n| n.0 != [0u8; 32]).collect();
		if non_dummy.len() == 2 {
			ensure!(
				non_dummy[0] != non_dummy[1],
				Error::<T>::NullifierAlreadyUsed
			);
		}

		for commitment in commitments.iter() {
			ensure!(commitment.is_canonical(), Error::<T>::InvalidPublicSignals);
			ensure!(commitment.is_valid(), Error::<T>::InvalidPublicSignals);
		}

		let all_dummy = nullifiers.iter().all(|n| n.0 == [0u8; 32]);
		ensure!(!all_dummy, Error::<T>::InvalidAmount);

		let nullifier_arrays: sp_std::vec::Vec<[u8; 32]> = nullifiers.iter().map(|n| n.0).collect();
		let commitment_arrays: sp_std::vec::Vec<[u8; 32]> =
			commitments.iter().map(|c| c.0).collect();

		let min_fee: <T::Currency as Currency<T::AccountId>>::Balance =
			T::Relayer::min_relay_fee().saturated_into();
		ensure!(fee >= min_fee, Error::<T>::FeeTooLow);
		let fee_u128: u128 = fee.saturated_into();

		#[cfg(not(feature = "skip-proof-verification"))]
		{
			let valid = T::ZkVerifier::verify_transfer_proof(
				&proof,
				&merkle_root,
				&nullifier_arrays,
				&commitment_arrays,
				asset_id,
				fee_u128,
				Some(circuit_version),
			)?;

			ensure!(valid, Error::<T>::ProofVerificationFailed);
		}
		#[cfg(feature = "skip-proof-verification")]
		let _ = circuit_version;

		#[cfg(feature = "skip-proof-verification")]
		{
			let _ = nullifier_arrays;
			let _ = commitment_arrays;
			let _ = asset_id;
			let _ = fee_u128;
			let _ = &proof;
		}

		let current_block = frame_system::Pallet::<T>::block_number();
		for nullifier in nullifiers.iter() {
			if nullifier.0 == [0u8; 32] {
				continue; // dummy input — nullifier zero is never inserted in the set
			}
			NullifierRepository::mark_as_used::<T>(*nullifier, current_block);
		}

		let mut leaf_indices: BoundedVec<u32, ConstU32<2>> = BoundedVec::new();
		for (commitment, memo) in commitments.iter().zip(encrypted_memos.iter()) {
			let index = MerkleTreeService::insert_leaf::<T>(*commitment)?;
			CommitmentRepository::store_memo::<T>(*commitment, memo.clone());
			leaf_indices
				.try_push(index)
				.map_err(|_| Error::<T>::TooManyInputsOrOutputs)?;
		}

		if fee > <T::Currency as Currency<T::AccountId>>::Balance::zero() {
			crate::operations::fees::credit_relay_fee::<T>(relayer_evm, asset_id, fee_u128)?;
		}

		Pallet::<T>::deposit_event(Event::NullifiersSpent {
			nullifiers: nullifiers.clone(),
		});
		Pallet::<T>::deposit_event(Event::CommitmentsInserted {
			commitments,
			encrypted_memos,
			leaf_indices,
		});

		Ok(())
	}

	pub fn is_nullifier_used<T: Config>(nullifier: &Nullifier) -> bool {
		NullifierRepository::is_used::<T>(nullifier)
	}

	pub fn is_merkle_root_known<T: Config>(root: &[u8; 32]) -> bool {
		MerkleRepository::is_known_root::<T>(root)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, acc, new_test_ext},
		pallet::Event as PalletEvent,
		storage::{CommitmentRepository, MerkleRepository, NullifierRepository},
		types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Nullifier},
	};
	use frame_support::{assert_err, assert_noop, assert_ok};

	// ── helpers ───────────────────────────────────────────────────────────────

	const KNOWN_ROOT: [u8; 32] = [0xBBu8; 32];

	fn proof() -> BoundedVec<u8, ConstU32<512>> {
		BoundedVec::try_from(vec![0x01u8; 72]).unwrap()
	}

	fn canonical_bytes(seed: u8) -> [u8; 32] {
		let mut b = [0u8; 32];
		b[0] = seed;
		b[1] = 0xA5; // keep values apart without touching the high bytes
		b
	}

	fn make_nullifier(seed: u8) -> Nullifier {
		Nullifier::new(canonical_bytes(seed))
	}

	fn make_commitment(seed: u8) -> Commitment {
		Commitment::new(canonical_bytes(seed))
	}

	fn make_memo() -> EncryptedMemo {
		EncryptedMemo::from_bytes(&[0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap()
	}

	fn short_memo() -> EncryptedMemo {
		// 32 bytes — too short (not 180)
		EncryptedMemo::new(vec![0x01u8; 32]).unwrap()
	}

	fn nullifiers_of(seeds: &[u8]) -> BoundedVec<Nullifier, ConstU32<2>> {
		let mut v: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
		for &s in seeds {
			v.try_push(make_nullifier(s)).ok();
		}
		v
	}

	fn commitments_of(seeds: &[u8]) -> BoundedVec<Commitment, ConstU32<2>> {
		let mut v: BoundedVec<Commitment, ConstU32<2>> = BoundedVec::new();
		for &s in seeds {
			v.try_push(make_commitment(s)).ok();
		}
		v
	}

	fn memos_of(count: usize) -> BoundedVec<EncryptedMemo, ConstU32<2>> {
		let mut v: BoundedVec<EncryptedMemo, ConstU32<2>> = BoundedVec::new();
		for _ in 0..count {
			v.try_push(make_memo()).ok();
		}
		v
	}

	// ── execute ───────────────────────────────────────────────────────────────

	#[test]
	fn execute_works_single_note() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x01]),
				commitments_of(&[0x02]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
			));
		});
	}

	#[test]
	fn execute_works_two_notes() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0xA1, 0xA2]),
				commitments_of(&[0xB1, 0xB2]),
				memos_of(2),
				0u32,
				0u128,
				None,
				1,
			));
		});
	}

	#[test]
	fn execute_unknown_root_fails() {
		new_test_ext().execute_with(|| {
			// root never added
			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					[0xFFu8; 32],
					nullifiers_of(&[0x01]),
					commitments_of(&[0x02]),
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
				),
				crate::pallet::Error::<Test>::UnknownMerkleRoot
			);
		});
	}

	#[test]
	fn execute_nullifier_already_used_fails() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let n = make_nullifier(0x20);
			NullifierRepository::mark_as_used::<Test>(n, 1u64);

			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x20]),
					commitments_of(&[0x30]),
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
				),
				crate::pallet::Error::<Test>::NullifierAlreadyUsed
			);
		});
	}

	#[test]
	fn execute_two_equal_nullifiers_fails() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// The same non-dummy nullifier in both slots would spend one input
			// twice: neither is in the used set yet, so both clear that check.
			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x20, 0x20]),
					commitments_of(&[0x30, 0x31]),
					memos_of(2),
					0u32,
					0u128,
					None,
					1,
				),
				crate::pallet::Error::<Test>::NullifierAlreadyUsed
			);
		});
	}

	#[test]
	fn execute_memo_commitment_mismatch_fails() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// 2 nullifiers + commitments but only 1 memo
			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0xA1, 0xA2]),
					commitments_of(&[0xB1, 0xB2]),
					memos_of(1), // mismatch: 1 ≠ 2
					0u32,
					0u128,
					None,
					1,
				),
				crate::pallet::Error::<Test>::MemoCommitmentMismatch
			);
		});
	}

	#[test]
	fn execute_invalid_memo_size_fails() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut memos: BoundedVec<EncryptedMemo, ConstU32<2>> = BoundedVec::new();
			memos.try_push(short_memo()).unwrap(); // 32 bytes, not 104

			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x01]),
					commitments_of(&[0x02]),
					memos,
					0u32,
					0u128,
					None,
					1,
				),
				crate::pallet::Error::<Test>::InvalidMemoSize
			);
		});
	}

	#[test]
	fn execute_marks_nullifiers_used() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let n1 = make_nullifier(0xC1);
			let n2 = make_nullifier(0xC2);

			assert!(!PrivateTransferOperation::is_nullifier_used::<Test>(&n1));
			assert!(!PrivateTransferOperation::is_nullifier_used::<Test>(&n2));

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0xC1, 0xC2]),
				commitments_of(&[0xD1, 0xD2]),
				memos_of(2),
				0u32,
				0u128,
				None,
				1,
			));

			assert!(PrivateTransferOperation::is_nullifier_used::<Test>(&n1));
			assert!(PrivateTransferOperation::is_nullifier_used::<Test>(&n2));
		});
	}

	#[test]
	fn execute_stores_commitment_memos() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let c = make_commitment(0xE1);

			assert!(!CommitmentRepository::exists::<Test>(&c));

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0xE0]),
				commitments_of(&[0xE1]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
			));

			assert!(CommitmentRepository::exists::<Test>(&c));
		});
	}

	#[test]
	fn execute_emits_private_transfer_event() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let nullifiers = nullifiers_of(&[0xF1]);
			let commitments = commitments_of(&[0xF2]);

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers.clone(),
				commitments.clone(),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
			));

			let events = frame_system::Pallet::<Test>::events();
			let found_nullifiers = events.iter().any(|r| {
				matches!(
					&r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::NullifiersSpent {
						nullifiers: en,
					}) if en == &nullifiers
				)
			});
			assert!(found_nullifiers, "NullifiersSpent event not emitted");

			let found_commitments = events.iter().any(|r| {
				matches!(
					&r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::CommitmentsInserted {
						commitments: ec,
						..
					}) if ec == &commitments
				)
			});
			assert!(found_commitments, "CommitmentsInserted event not emitted");
		});
	}

	#[test]
	fn execute_accumulates_fee_to_block_author_when_nonzero() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let fee = 25u128;

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x10]),
				commitments_of(&[0x11]),
				memos_of(1),
				0u32,
				fee,
				None,
				1,
			));

			// MockRelayer block_author = Some(1)
			let pending = crate::mock::mock_pending_fees_get(acc(1), 0u32);
			assert_eq!(pending, fee);
		});
	}

	#[test]
	fn execute_no_fee_accumulated_when_zero() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x12]),
				commitments_of(&[0x13]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
			));

			let pending = crate::mock::mock_pending_fees_get(acc(1), 0u32);
			assert_eq!(pending, 0u128);
		});
	}

	// ── query helpers ─────────────────────────────────────────────────────────

	#[test]
	fn is_nullifier_used_false_by_default() {
		new_test_ext().execute_with(|| {
			assert!(!PrivateTransferOperation::is_nullifier_used::<Test>(
				&make_nullifier(0xAB)
			));
		});
	}

	#[test]
	fn is_merkle_root_known_returns_correct_values() {
		new_test_ext().execute_with(|| {
			assert!(!PrivateTransferOperation::is_merkle_root_known::<Test>(
				&KNOWN_ROOT
			));
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			assert!(PrivateTransferOperation::is_merkle_root_known::<Test>(
				&KNOWN_ROOT
			));
		});
	}

	#[test]
	fn execute_with_dummy_nullifier_only_real_inserted() {
		// A transfer with 1 real note + 1 dummy (nullifier = [0u8;32]) must succeed
		// and only insert the real nullifier into the set.
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let real = make_nullifier(0x55);
			let dummy = Nullifier::new([0u8; 32]);

			let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			nullifiers.try_push(real).ok();
			nullifiers.try_push(dummy).ok();

			assert!(!PrivateTransferOperation::is_nullifier_used::<Test>(&real));

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers,
				commitments_of(&[0x56, 0x57]),
				memos_of(2),
				0u32,
				0u128,
				None,
				1,
			));

			// Real nullifier must be marked used
			assert!(PrivateTransferOperation::is_nullifier_used::<Test>(&real));
			// Dummy nullifier [0;32] must NOT be inserted
			assert!(!PrivateTransferOperation::is_nullifier_used::<Test>(&dummy));
		});
	}

	#[test]
	fn execute_dummy_nullifier_not_rejected_as_double_spend() {
		// Two transactions, both with dummy nullifier [0u8;32] in slot 1.
		// The second must not be rejected as double-spend of the dummy.
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut nullifiers_tx1: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			nullifiers_tx1.try_push(make_nullifier(0x61)).ok();
			nullifiers_tx1.try_push(Nullifier::new([0u8; 32])).ok();

			let mut nullifiers_tx2: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			nullifiers_tx2.try_push(make_nullifier(0x71)).ok();
			nullifiers_tx2.try_push(Nullifier::new([0u8; 32])).ok();

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_tx1,
				commitments_of(&[0x62, 0x63]),
				memos_of(2),
				0u32,
				0u128,
				None,
				1,
			));

			// Second tx with a different real nullifier but same dummy — must succeed
			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_tx2,
				commitments_of(&[0x72, 0x73]),
				memos_of(2),
				0u32,
				0u128,
				None,
				1,
			));
		});
	}

	#[test]
	fn execute_rejects_all_dummy_nullifiers() {
		// Both nullifiers are [0u8;32] → total value = 0, no real input note.
		// Must be rejected as InvalidAmount to prevent free Merkle tree spam.
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut nullifiers: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			nullifiers.try_push(Nullifier::new([0u8; 32])).ok();
			nullifiers.try_push(Nullifier::new([0u8; 32])).ok();

			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers,
					commitments_of(&[0x10, 0x11]),
					memos_of(2),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::InvalidAmount
			);
		});
	}

	#[test]
	fn execute_nullifier_commitment_count_mismatch_fails() {
		// 1 nullifier but 2 output commitments: structurally inconsistent with the
		// fixed 2-in/2-out circuit. Must be rejected by the pallet before the ZK check
		// so that benchmark mode (no verifier) cannot break value conservation.
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0xF1]),        // 1 nullifier
					commitments_of(&[0xF2, 0xF3]), // 2 commitments
					memos_of(2),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::TooManyInputsOrOutputs
			);
		});
	}

	// ── private_transfer must leave the pool ledger untouched ─────────────────

	/// A transfer moves value note-to-note; nothing enters or leaves the pool
	/// physically, so PoolBalancePerAsset must not change. The fee becomes a
	/// pending number backed by tokens already inside the pool.
	#[test]
	fn transfer_preserves_pool_ledger() {
		use crate::storage::PoolBalanceRepository;
		use frame_support::traits::Currency;
		use sp_runtime::AccountId32;

		new_test_ext().execute_with(|| {
			let asset_id = 0u32;
			// Seed a pool ledger/physical balance the transfer must not disturb.
			let pool = crate::Pallet::<Test>::pool_account_id();
			let _ = <pallet_balances::Pallet<Test> as Currency<AccountId32>>::deposit_creating(
				&pool, 1000,
			);
			PoolBalanceRepository::set_asset_balance::<Test>(asset_id, 1000);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let ledger_before = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
			let physical_before =
				<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&pool);
			let fee = 25u128;

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x40]),
				commitments_of(&[0x41]),
				memos_of(1),
				asset_id,
				fee,
				None,
				1,
			));

			assert_eq!(
				PoolBalanceRepository::get_asset_balance::<Test>(asset_id),
				ledger_before,
				"transfer must not change the pool ledger"
			);
			assert_eq!(
				<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&pool),
				physical_before,
				"transfer must not move physical pool tokens"
			);
			assert_eq!(crate::mock::mock_pending_fees_get(acc(1), asset_id), fee);
		});
	}

	// ── relay-fee attribution ────────────────────────────────────────────────

	/// A registered relayer receives the transfer fee; an unregistered attacker
	/// address cannot credit itself (falls back to block author).
	#[test]
	fn transfer_fee_attribution_registered_vs_unregistered() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let relayer_acct = acc(7);
			crate::mock::mock_register_relayer(
				relayer_acct.clone(),
				sp_core::H160::from([0xAA; 20]),
			);

			// Registered relayer 0xAA → fee to account 7.
			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x70]),
				commitments_of(&[0x71]),
				memos_of(1),
				0u32,
				30u128,
				Some(sp_core::H160::from([0xAA; 20])),
				1,
			));
			assert_eq!(crate::mock::mock_pending_fees_get(relayer_acct, 0u32), 30);

			// Unregistered 0xBB → falls back to block author (1), never the attacker.
			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x72]),
				commitments_of(&[0x73]),
				memos_of(1),
				0u32,
				20u128,
				Some(sp_core::H160::from([0xBB; 20])),
				1,
			));
			assert_eq!(crate::mock::mock_pending_fees_get(acc(1), 0u32), 20);
		});
	}

	/// A non-zero fee with no resolvable recipient errors, mirroring unshield.
	#[test]
	fn transfer_nonzero_fee_without_recipient_errors() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			crate::mock::mock_clear_block_author();

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x80]),
					commitments_of(&[0x81]),
					memos_of(1),
					0u32,
					25u128,
					None,
					1,
				),
				Error::<Test>::FeeRecipientUnavailable
			);
		});
	}

	// ── asset state-machine gate ─────────────────────────────────────────────

	/// Unverifying an asset freezes in-pool transfers too, mirroring the
	/// shield/unshield freeze (no path escapes the emergency kill-switch).
	#[test]
	fn transfer_frozen_asset_fails() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			crate::operations::assets::AssetOperation::unverify::<Test>(0u32).unwrap();

			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x90]),
					commitments_of(&[0x91]),
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::AssetNotVerified
			);
		});
	}

	/// A transfer on an unregistered asset id is rejected before any effect.
	#[test]
	fn transfer_unknown_asset_fails() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_noop!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x92]),
					commitments_of(&[0x93]),
					memos_of(1),
					999u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::InvalidAssetId
			);
		});
	}

	// ── weight scales with outputs ───────────────────────────────────────────

	/// A 2-output transfer inserts two leaves and must be weighted heavier than a
	/// 1-output one (guards against the flat weight that under-priced the second
	/// insert).
	#[test]
	fn private_transfer_weight_scales_with_outputs() {
		use crate::weights::WeightInfo;
		let one = <() as WeightInfo>::private_transfer(1);
		let two = <() as WeightInfo>::private_transfer(2);
		assert!(
			two.ref_time() > one.ref_time(),
			"two outputs must cost more ref_time than one"
		);
		assert!(
			two.proof_size() > one.proof_size(),
			"two outputs must cost more proof_size than one"
		);
	}

	// ── adversarial battery ──────────────────────────────────────────────────
	//
	// Each of these is an attempt to BREAK an invariant, not a demonstration
	// that it holds. They are written from the attacker's side: assume the ZK
	// proof is satisfiable (the mock skips verification) and ask what the
	// non-cryptographic checks still have to stop on their own.

	/// Double-spend inside ONE extrinsic, same nullifier twice.
	///
	/// The set check cannot catch this: neither nullifier is in storage yet when
	/// the loop runs, so only the explicit pairwise comparison stands between
	/// this and spending one note twice in a single call.
	#[test]
	fn attack_same_nullifier_twice_in_one_extrinsic_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			nulls.try_push(make_nullifier(0x77)).unwrap();
			nulls.try_push(make_nullifier(0x77)).unwrap(); // same note, twice

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nulls,
					commitments_of(&[0xC1, 0xC2]),
					memos_of(2),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::NullifierAlreadyUsed
			);
		});
	}

	/// The dummy nullifier is exempt from the "already used" check by design.
	/// Two dummies in one call must therefore NOT be readable as a duplicate
	/// pair — but the all-dummy guard has to reject the call outright, or a
	/// transfer with no real input mints two free leaves.
	#[test]
	fn attack_two_dummy_nullifiers_cannot_mint_free_leaves() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			nulls.try_push(Nullifier::new([0u8; 32])).unwrap();
			nulls.try_push(Nullifier::new([0u8; 32])).unwrap();

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nulls,
					commitments_of(&[0xD1, 0xD2]),
					memos_of(2),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::InvalidAmount
			);
		});
	}

	/// Replay of a nullifier already spent in an EARLIER block.
	#[test]
	fn attack_replaying_a_spent_nullifier_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x51]),
				commitments_of(&[0x52]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
			));

			// Same nullifier, different outputs — the note is already gone.
			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x51]),
					commitments_of(&[0x53]),
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::NullifierAlreadyUsed
			);
		});
	}

	/// Non-canonical field elements: bytes above the BN254 modulus that reduce
	/// to a DIFFERENT, already-spent value. Accepting them would give every
	/// nullifier a second spelling and defeat the double-spend set entirely.
	#[test]
	fn attack_non_canonical_nullifier_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// modulus + 1, little-endian — reduces to 1, which is canonical.
			let mut over = [0u8; 32];
			over[0] = 0x02;
			over[31] = 0xFF;
			assert!(
				!Nullifier::new(over).is_canonical(),
				"fixture must actually be non-canonical or the test proves nothing"
			);

			let mut nulls: BoundedVec<Nullifier, ConstU32<2>> = BoundedVec::new();
			nulls.try_push(Nullifier::new(over)).unwrap();

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nulls,
					commitments_of(&[0xE1]),
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::InvalidPublicSignals
			);
		});
	}

	/// Same, on the output side: a non-canonical commitment would land a leaf
	/// whose second spelling could collide with a real one.
	#[test]
	fn attack_non_canonical_commitment_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut over = [0u8; 32];
			over[0] = 0x02;
			over[31] = 0xFF;
			assert!(!Commitment::new(over).is_canonical());

			let mut comms: BoundedVec<Commitment, ConstU32<2>> = BoundedVec::new();
			comms.try_push(Commitment::new(over)).unwrap();

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x61]),
					comms,
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::InvalidPublicSignals
			);
		});
	}

	/// A forged Merkle root the attacker made up: it lets them prove membership
	/// of a note that was never in the tree.
	#[test]
	fn attack_unknown_merkle_root_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					[0xEEu8; 32], // never added
					nullifiers_of(&[0x71]),
					commitments_of(&[0x72]),
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::UnknownMerkleRoot
			);
		});
	}

	/// Array-length confusion: more commitments than nullifiers would insert an
	/// output nothing paid for.
	#[test]
	fn attack_more_commitments_than_nullifiers_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x81]),        // 1 input
					commitments_of(&[0x82, 0x83]), // 2 outputs
					memos_of(2),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::TooManyInputsOrOutputs
			);
		});
	}

	/// Memo count out of step with the outputs: a missing memo would leave a
	/// commitment nobody can ever open, and the zip() that stores them would
	/// silently drop the extra output.
	#[test]
	fn attack_memo_count_mismatch_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x91, 0x92]),
					commitments_of(&[0x93, 0x94]),
					memos_of(1), // one memo for two outputs
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::MemoCommitmentMismatch
			);
		});
	}

	/// A wrong-sized memo must not reach storage: the wallet's decrypt path
	/// slices fixed offsets, so a short memo is a note nobody can open.
	#[test]
	fn attack_undersized_memo_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut memos: BoundedVec<EncryptedMemo, ConstU32<2>> = BoundedVec::new();
			memos.try_push(short_memo()).unwrap();

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0xA9]),
					commitments_of(&[0xAA]),
					memos,
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::InvalidMemoSize
			);
		});
	}

	/// The zero commitment is the tree's empty-leaf sentinel. Inserting it as a
	/// real output would corrupt the Merkle structure.
	#[test]
	fn attack_zero_commitment_is_refused() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut comms: BoundedVec<Commitment, ConstU32<2>> = BoundedVec::new();
			comms.try_push(Commitment::new([0u8; 32])).unwrap();

			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0xB9]),
					comms,
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
				),
				Error::<Test>::InvalidPublicSignals
			);
		});
	}

	/// A fee below the relay minimum must be refused BEFORE any state changes —
	/// otherwise the pool subsidizes the spam it is meant to price out.
	#[test]
	fn attack_fee_below_minimum_is_refused_without_spending_the_nullifier() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			let min = <Test as Config>::Relayer::min_relay_fee();
			if min == 0 {
				return; // mock has no minimum; nothing to prove here
			}

			let n = make_nullifier(0xC9);
			assert_err!(
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0xC9]),
					commitments_of(&[0xCA]),
					memos_of(1),
					0u32,
					min.saturating_sub(1),
					None,
					1,
				),
				Error::<Test>::FeeTooLow
			);
			// And the note must still be spendable — a rejected call that burned
			// the nullifier would destroy funds.
			assert!(!NullifierRepository::is_used::<Test>(&n));
		});
	}

	/// Duplicate commitments inside ONE call, checked for real.
	///
	/// The duplicate guard reads `CommitmentMemos`, which is only populated
	/// AFTER each insert by `store_memo`. Within a single call the loop runs
	/// insert→store_memo per output, so by the time the second (identical)
	/// output is inserted the first one's memo IS stored and the guard fires.
	/// If that ordering ever changes, one note would take two leaves in one
	/// transaction — this pins the outcome, not the mechanism.
	#[test]
	fn attack_duplicate_commitments_in_one_call_cannot_take_two_leaves() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let mut comms: BoundedVec<Commitment, ConstU32<2>> = BoundedVec::new();
			comms.try_push(make_commitment(0xF1)).unwrap();
			comms.try_push(make_commitment(0xF1)).unwrap(); // same leaf twice

			let before = MerkleRepository::get_tree_size::<Test>();

			// Run inside a storage transaction, the way a dispatchable executes:
			// FRAME rolls the whole extrinsic back on error, so the partial leaf
			// from the first (accepted) output must not survive. Calling
			// `execute` bare would leave that write in place — an artefact of the
			// test harness, not of the runtime.
			let result = frame_support::storage::with_storage_layer(|| {
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0xF2, 0xF3]),
					comms,
					memos_of(2),
					0u32,
					0u128,
					None,
					1,
				)
			});

			assert!(result.is_err(), "a duplicated output must not be accepted");
			let after = MerkleRepository::get_tree_size::<Test>();
			assert_eq!(
				before, after,
				"the rejected call must leave no leaf behind once rolled back"
			);
		});
	}

	/// The memo is opaque to the chain, and must stay that way.
	///
	/// `sourcePk` lives at plaintext bytes [84,116) INSIDE the ciphertext — the
	/// pallet holds no key and must never gate on memo contents. This pins that:
	/// two transfers whose memos differ only in those bytes are equally valid on
	/// chain. A pallet that could tell them apart would mean the memo was not
	/// actually encrypted.
	#[test]
	fn attack_memo_contents_never_gate_admission() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// Two memos, same length, different bytes where sourcePk would sit.
			let mut a = [0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
			let mut b = [0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
			for byte in a[84..116].iter_mut() {
				*byte = 0x00;
			}
			for byte in b[84..116].iter_mut() {
				*byte = 0xAB;
			}

			for (i, bytes) in [a, b].into_iter().enumerate() {
				let mut memos: BoundedVec<EncryptedMemo, ConstU32<2>> = BoundedVec::new();
				memos
					.try_push(EncryptedMemo::from_bytes(&bytes).unwrap())
					.unwrap();
				let seed = 0x80 + i as u8 * 2;
				assert_ok!(PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[seed]),
					commitments_of(&[seed + 1]),
					memos,
					0u32,
					0u128,
					None,
					1,
				));
			}
		});
	}
}
