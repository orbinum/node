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
			ensure!(
				!NullifierRepository::is_used::<T>(nullifier),
				Error::<T>::NullifierAlreadyUsed
			);
		}

		// Prevent both inputs being dummy (all-zero nullifiers = value 0+0).
		// A 2-dummy transfer creates 2 commitments in the Merkle tree at zero cost,
		// enabling spam without any economic disincentive.
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
				None,
			)?;

			ensure!(valid, Error::<T>::ProofVerificationFailed);
		}

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
			let recipient_account = relayer_evm
				.and_then(|addr| T::Relayer::resolve_relayer(&addr))
				.or_else(T::Relayer::block_author)
				.ok_or(Error::<T>::FeeRecipientUnavailable)?;
			T::Relayer::accumulate_relay_fee(&recipient_account, asset_id, fee_u128);
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

	fn make_nullifier(seed: u8) -> Nullifier {
		Nullifier::new([seed; 32])
	}

	fn make_commitment(seed: u8) -> Commitment {
		Commitment::new([seed; 32])
	}

	fn make_memo() -> EncryptedMemo {
		EncryptedMemo::from_bytes(&[0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap()
	}

	fn short_memo() -> EncryptedMemo {
		// 32 bytes — too short (not 168)
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
}
