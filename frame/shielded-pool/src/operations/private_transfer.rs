//! `private_transfer` — spending shielded notes into new shielded notes.
//!
//! Nothing about the amounts is public: the ZK proof attests that inputs equal
//! outputs plus fee. What the pallet checks is everything the proof does NOT
//! cover — that the inputs exist, are unspent, and are spelled canonically, and
//! that the arrays line up.
//!
//! ## Order of steps
//!
//! Numbered below. The split matters: every validation (steps 1–6) runs BEFORE
//! any state changes (steps 7–9), and the expensive proof verification (step 6)
//! runs LAST among the checks, so a transaction that fails a cheap structural
//! test never costs a pairing.
//!
//! | # | Step                              | Touches state |
//! |---|-----------------------------------|---------------|
//! | 1 | asset registered and verified     | no            |
//! | 2 | arrays line up, memos exact-sized | no            |
//! | 3 | Merkle root known                 | no            |
//! | 4 | nullifiers canonical and unspent  | no            |
//! | 5 | commitments canonical and non-zero| no            |
//! | 6 | fee floor, then verify the proof  | no            |
//! | 7 | burn the inputs (mark nullifiers) | yes           |
//! | 8 | insert outputs, store memos       | yes           |
//! | 9 | accrue the relay fee, emit events | yes           |
//!
//! Every check here is also enforced at pool admission
//! ([`crate::validate_unsigned::transfer`]), which may reject more but never
//! less: admission can be skipped by a malicious block author, so this is the
//! authority.

use crate::{
	merkle::MerkleTreeService,
	pallet::{Config, Error, Event, Pallet},
	storage::{AssetRepository, CommitmentRepository, MerkleRepository, NullifierRepository},
	types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Nullifier, OvkBlob},
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
		ovk_blob: OvkBlob,
	) -> DispatchResult {
		// ── 1. Asset ─────────────────────────────────────────────────────────
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);

		// ── 2. Array arity and memo size ─────────────────────────────────────
		// The three arrays run in parallel — input i, output i, memo i — so a
		// mismatch is a call that cannot mean anything. Memos are exact-sized,
		// never merely bounded: the wallet slices them at fixed offsets, so a
		// short one is a note nobody can open.
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

		// ── 3. Merkle root ───────────────────────────────────────────────────
		// Membership is proven against a root the chain published; the retention
		// window outlives `TX_LONGEVITY`, so a root valid at admission is still
		// valid here.
		ensure!(
			MerkleRepository::is_known_root::<T>(&merkle_root),
			Error::<T>::UnknownMerkleRoot
		);

		// ── 4. Nullifiers ────────────────────────────────────────────────────
		// The dummy sentinel (all zeros) pads a single-input spend and is never
		// inserted, so it is skipped rather than checked. For the rest:
		//   - canonical, because `n` and `n + p` are DIFFERENT storage keys for
		//     the same field element — two spellings would mean two spends;
		//   - unspent against the on-chain set.
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

		// Two EQUAL real nullifiers would spend one input twice inside a single
		// call: neither is in the set yet when the loop above runs, and the
		// second `mark_as_used` is idempotent, so only this comparison catches
		// it. The proof is expected to bind the inputs distinct; the chain does
		// not rely on that.
		let non_dummy: sp_std::vec::Vec<&Nullifier> =
			nullifiers.iter().filter(|n| n.0 != [0u8; 32]).collect();
		if non_dummy.len() == 2 {
			ensure!(
				non_dummy[0] != non_dummy[1],
				Error::<T>::NullifierAlreadyUsed
			);
		}

		// ── 5. Commitments ───────────────────────────────────────────────────
		// Canonical for the same reason as the nullifiers; non-zero because zero
		// is the tree's empty-leaf sentinel.
		for commitment in commitments.iter() {
			ensure!(commitment.is_canonical(), Error::<T>::InvalidPublicSignals);
			ensure!(commitment.is_valid(), Error::<T>::InvalidPublicSignals);
		}

		// All-dummy means no note is being spent, so the outputs would be minted
		// out of nothing — free value, not just free tree growth.
		let all_dummy = nullifiers.iter().all(|n| n.0 == [0u8; 32]);
		ensure!(!all_dummy, Error::<T>::InvalidAmount);

		// ── 6. Fee floor, then the proof ─────────────────────────────────────
		// The fee compare is cheap and goes first; proof verification is the
		// most expensive thing in the call, so it runs only once everything
		// structural has passed. The fee is a PUBLIC input to the circuit, which
		// is what stops a relayer from inflating it after the fact.
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

		// ── 7. Burn the inputs ───────────────────────────────────────────────
		// From here on the call mutates state. Nullifiers are marked FIRST: if
		// anything below fails, the runtime rolls the whole extrinsic back, but
		// ordering the burn ahead of the mint keeps the invariant obvious —
		// nothing is created before its input is consumed.
		let current_block = frame_system::Pallet::<T>::block_number();
		for nullifier in nullifiers.iter() {
			if nullifier.0 == [0u8; 32] {
				continue; // dummy input — nullifier zero is never inserted in the set
			}
			NullifierRepository::mark_as_used::<T>(*nullifier, current_block);
		}

		// ── 8. Mint the outputs ──────────────────────────────────────────────
		// `zip` pairs each commitment with its own memo — the arity check in
		// step 2 is what makes that pairing total rather than silently dropping
		// an output.
		let mut leaf_indices: BoundedVec<u32, ConstU32<2>> = BoundedVec::new();
		for (commitment, memo) in commitments.iter().zip(encrypted_memos.iter()) {
			let index = MerkleTreeService::insert_leaf::<T>(*commitment)?;
			CommitmentRepository::store_memo::<T>(*commitment, memo.clone());
			leaf_indices
				.try_push(index)
				.map_err(|_| Error::<T>::TooManyInputsOrOutputs)?;
		}

		// ── 9. Accrue the relay fee ──────────────────────────────────────────
		// The fee never leaves the pool as a transfer: it is credited to the
		// relayer's pending balance and claimed later via `claim_shielded_fees`,
		// which is what keeps the payout unlinkable from this transaction.
		// Falls back to the block author when no relayer is registered for the
		// caller's EVM address.
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
		// The blob belongs to the recipient output — commitments[0] by the
		// wallet's positional convention (output[0] = recipient, output[1] =
		// change). Nothing on chain enforces that ordering, so it is a contract
		// with the wallet, not an invariant the pallet can check.
		let ovk_commitment = commitments.first().copied();

		Pallet::<T>::deposit_event(Event::CommitmentsInserted {
			commitments,
			encrypted_memos,
			leaf_indices,
		});
		if let Some(commitment) = ovk_commitment {
			Pallet::<T>::deposit_event(Event::OutgoingBlobPublished {
				commitment,
				blob: ovk_blob,
			});
		}

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
		types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Nullifier, OvkBlob},
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

	fn test_blob() -> OvkBlob {
		OvkBlob([0x0Bu8; crate::types::OVK_BLOB_SIZE])
	}

	/// The 56 zeros a wallet must never emit — spelled out so a test that uses
	/// it is visibly asking for the forbidden value, not reaching for a default.
	fn zero_blob() -> OvkBlob {
		OvkBlob([0u8; crate::types::OVK_BLOB_SIZE])
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
				test_blob(),
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
				test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
				test_blob(),
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
				test_blob(),
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
				test_blob(),
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
				test_blob(),
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
				test_blob(),
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
				test_blob(),
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
				test_blob(),
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
				test_blob(),
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
					test_blob(),
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
					test_blob(),
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
				test_blob(),
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
				test_blob(),
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
				test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
				),
				Error::<Test>::InvalidAssetId
			);
		});
	}

	// ── weight scales with outputs ───────────────────────────────────────────

	// ── OVK blob ─────────────────────────────────────────────────────────────

	/// A valid transfer emits OutgoingBlobPublished bound to commitments[0]
	/// with the exact blob bytes.
	#[test]
	fn execute_emits_outgoing_blob_published() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let commitments = commitments_of(&[0xF4, 0xF5]);
			let expected_commitment = commitments[0];
			let blob = test_blob();

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0xF6, 0xF7]),
				commitments,
				memos_of(2),
				0u32,
				0u128,
				None,
				1,
				blob.clone(),
			));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					&r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::OutgoingBlobPublished {
						commitment,
						blob: eb,
					}) if *commitment == expected_commitment && eb == &blob
				)
			});
			assert!(found, "OutgoingBlobPublished event not emitted");
		});
	}

	/// The pallet does not judge blob contents — not even the 56 zeros the
	/// design forbids.
	///
	/// It cannot: the blob is ciphertext, and rejecting a specific value would
	/// mean the chain claims to know something about plaintext it cannot read.
	/// Keeping zeros out is the WALLET's job (it sends random bytes when the
	/// sender opts out), and `OvkBlob` has no `Default` so reaching them takes
	/// deliberate effort.
	#[test]
	fn execute_accepts_all_zero_blob() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x21]),
				commitments_of(&[0x22]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
				zero_blob(),
			));
		});
	}

	/// SCALE codec round-trip of the new type: 56 raw bytes, no length prefix.
	#[test]
	fn ovk_blob_codec_round_trip() {
		use parity_scale_codec::{Decode, Encode};

		let blob = test_blob();
		let encoded = blob.encode();
		assert_eq!(encoded.len(), 56, "fixed array must encode without prefix");
		let decoded = OvkBlob::decode(&mut &encoded[..]).unwrap();
		assert_eq!(decoded, blob);

		// Wrong length must not decode into the type.
		assert!(OvkBlob::decode(&mut &encoded[..55]).is_err());
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
					test_blob(),
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
					test_blob(),
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
				test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
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
					test_blob(),
				),
				Error::<Test>::FeeTooLow
			);
			// And the note must still be spendable — a rejected call that burned
			// the nullifier would destroy funds.
			assert!(!NullifierRepository::is_used::<Test>(&n));
		});
	}

	/// Two DIFFERENT transfers may legitimately carry the same blob bytes (a
	/// wallet opting out publishes random bytes each time, but nothing stops a
	/// repeat). The blob must never act as an identifier: it is opaque
	/// ciphertext and must not gate admission or dedup.
	#[test]
	fn attack_reusing_a_blob_across_transfers_is_allowed_and_harmless() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0xD9]),
				commitments_of(&[0xDA]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
				test_blob(),
			));
			// Same blob, different note — must succeed: the blob carries no
			// identity the chain is entitled to reason about.
			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0xDB]),
				commitments_of(&[0xDC]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
				test_blob(),
			));
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
					test_blob(),
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

	// ── adversarial: OVK blob & sourcePk, from the CHAIN's side ──────────────
	//
	// Every sourcePk protection built this cycle lives in the wallet, and the
	// chain cannot see it: the memo is ciphertext and the pallet has no key.
	// So the question here is not "does the pallet validate sourcePk" (it
	// cannot) but "what can an attacker who bypasses the SDK and submits raw
	// extrinsics actually achieve".

	/// An attacker must not be able to bind a blob to SOMEONE ELSE'S note.
	///
	/// The blob is bound to `commitments[0]` of the attacker's own call, and a
	/// commitment can only take a leaf once, so referencing a victim's existing
	/// commitment is refused outright. Without this, anyone could publish a blob
	/// against another wallet's output and plant history in it.
	#[test]
	fn attack_cannot_bind_a_blob_to_someone_elses_commitment() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// Victim's transfer lands first.
			let victim_output = make_commitment(0x5A);
			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x5B]),
				commitments_of(&[0x5A]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
				test_blob(),
			));

			// Attacker tries to publish THEIR blob against the victim's output.
			let attacker_blob = OvkBlob([0xEEu8; crate::types::OVK_BLOB_SIZE]);
			let result = frame_support::storage::with_storage_layer(|| {
				PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[0x5C]),
					commitments_of(&[0x5A]), // the victim's commitment
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
					attacker_blob,
				)
			});
			assert!(
				result.is_err(),
				"reusing a live commitment must be refused, or a blob can be planted on it"
			);

			// And the victim's binding is untouched: exactly one blob event for
			// that commitment, carrying the victim's bytes.
			let blobs: alloc::vec::Vec<_> = frame_system::Pallet::<Test>::events()
				.into_iter()
				.filter_map(|r| match r.event {
					crate::mock::RuntimeEvent::ShieldedPool(
						PalletEvent::OutgoingBlobPublished { commitment, blob },
					) if commitment == victim_output => Some(blob),
					_ => None,
				})
				.collect();
			assert_eq!(
				blobs.len(),
				1,
				"exactly one blob may ever bind to a commitment"
			);
			assert_eq!(
				blobs[0],
				test_blob(),
				"and it is the victim's, not the attacker's"
			);
		});
	}

	/// The blob binds to `commitments[0]`, so a 2-output transfer must never
	/// emit a second blob event or bind to the change output.
	#[test]
	fn attack_only_one_blob_event_per_transfer_bound_to_the_first_output() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x61, 0x62]),
				commitments_of(&[0x63, 0x64]),
				memos_of(2),
				0u32,
				0u128,
				None,
				1,
				test_blob(),
			));

			let bound: alloc::vec::Vec<_> = frame_system::Pallet::<Test>::events()
				.into_iter()
				.filter_map(|r| match r.event {
					crate::mock::RuntimeEvent::ShieldedPool(
						PalletEvent::OutgoingBlobPublished { commitment, .. },
					) => Some(commitment),
					_ => None,
				})
				.collect();
			assert_eq!(bound.len(), 1, "one transfer publishes exactly one blob");
			assert_eq!(
				bound[0],
				make_commitment(0x63),
				"bound to output[0] (recipient), never to the change output"
			);
		});
	}

	/// The chain must accept ANY 56 bytes as a blob — including all-zeros.
	///
	/// It cannot tell a real blob from random (that is the whole point of the
	/// opt-out design), so rejecting a value would be the chain pretending to
	/// validate ciphertext it holds no key for. Zeros are a WALLET-side smell,
	/// not a consensus rule: a pallet that rejected them would leak that the
	/// distinction is observable, and would break any future blob format whose
	/// encoding can legitimately be zero.
	#[test]
	fn attack_chain_stays_agnostic_about_blob_contents() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			for (label, blob) in [
				("all zeros", zero_blob()),
				("all 0xFF", OvkBlob([0xFFu8; crate::types::OVK_BLOB_SIZE])),
				("real-looking", test_blob()),
			] {
				let seed = label.len() as u8 + 0x70;
				assert_ok!(PrivateTransferOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifiers_of(&[seed]),
					commitments_of(&[seed + 1]),
					memos_of(1),
					0u32,
					0u128,
					None,
					1,
					blob,
				));
			}
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
					test_blob(),
				));
			}
		});
	}

	/// A transfer with NO change output still publishes a blob.
	///
	/// The exact-amount spend (change = 0) is the case only OVK can recover —
	/// there is no change note to infer the peer from. If the chain skipped the
	/// event here, that history would be unrecoverable, and the absence would
	/// itself mark which transfers were exact.
	#[test]
	fn attack_exact_amount_transfer_still_publishes_its_blob() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// One input, one output: no change.
			assert_ok!(PrivateTransferOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifiers_of(&[0x91]),
				commitments_of(&[0x92]),
				memos_of(1),
				0u32,
				0u128,
				None,
				1,
				test_blob(),
			));

			let count = frame_system::Pallet::<Test>::events()
				.into_iter()
				.filter(|r| {
					matches!(
						r.event,
						crate::mock::RuntimeEvent::ShieldedPool(
							PalletEvent::OutgoingBlobPublished { .. }
						)
					)
				})
				.count();
			assert_eq!(
				count, 1,
				"an exact-amount transfer must still publish its blob"
			);
		});
	}
}
