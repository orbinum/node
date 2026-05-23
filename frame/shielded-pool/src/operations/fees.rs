//! Fee-claiming operation — converts pending relay fees into a private note.

use crate::{
	pallet::{Assets, CommitmentMemos, Config, Error, Event, Pallet},
	types::{Commitment, EncryptedMemo},
};
use frame_support::{ensure, pallet_prelude::*};
use pallet_relayer::RelayerInterface as _;
#[cfg(not(feature = "runtime-benchmarks"))]
use pallet_zk_verifier::ZkVerifierPort;
use sp_runtime::SaturatedConversion;

pub type BalanceOf<T> = <<T as Config>::Currency as frame_support::traits::Currency<
	<T as frame_system::Config>::AccountId,
>>::Balance;

pub struct FeeOperation;

impl FeeOperation {
	/// Claim accumulated relay fees as a private shielded commitment.
	///
	/// Requires a `value_proof` (Groth16 over `value_proof.circom`) proving that
	/// the supplied `commitment` encodes exactly `(amount, asset_id, owner_pubkey,
	/// blinding)` via `Poseidon4`.  Without this proof a relayer could craft a
	/// commitment encoding an inflated amount and drain the pool on `unshield`.
	///
	/// # public_signals layout (76 bytes)
	/// `commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]`
	pub fn claim_shielded<T: Config>(
		validator: T::AccountId,
		commitment: Commitment,
		amount: BalanceOf<T>,
		asset_id: u32,
		memo: EncryptedMemo,
		proof: sp_std::vec::Vec<u8>,
		public_signals: sp_std::vec::Vec<u8>,
	) -> DispatchResult {
		ensure!(
			Assets::<T>::contains_key(asset_id),
			Error::<T>::InvalidAssetId
		);

		let amount_u128: u128 = amount.saturated_into();

		ensure!(!amount.is_zero(), Error::<T>::InvalidAmount);

		// amount must fit in u64 (circuit signal size)
		ensure!(amount_u128 <= u64::MAX as u128, Error::<T>::InvalidAmount);

		// Verify ZK value_proof (proves commitment = Poseidon4(amount, assetId, pk, r))
		ensure!(proof.len() == 128, Error::<T>::InvalidProof);
		ensure!(public_signals.len() == 76, Error::<T>::InvalidPublicSignals);

		#[cfg(not(feature = "runtime-benchmarks"))]
		{
			let is_valid = T::ZkVerifier::verify_value_proof(&proof, &public_signals, None)?;
			ensure!(is_valid, Error::<T>::InvalidProof);
		}

		// signals[0..32]: commitment must match the extrinsic argument
		ensure!(
			public_signals[0..32] == commitment.0,
			Error::<T>::InvalidPublicSignals
		);

		// signals[32..40]: revealed value (u64 LE) must match amount
		let sig_value_bytes: [u8; 8] = public_signals[32..40]
			.try_into()
			.map_err(|_| Error::<T>::InvalidPublicSignals)?;
		let sig_value = u64::from_le_bytes(sig_value_bytes) as u128;
		ensure!(sig_value == amount_u128, Error::<T>::InvalidPublicSignals);

		// signals[40..44]: revealed asset_id (u32 LE) must match asset_id
		let sig_asset_bytes: [u8; 4] = public_signals[40..44]
			.try_into()
			.map_err(|_| Error::<T>::InvalidPublicSignals)?;
		let sig_asset = u32::from_le_bytes(sig_asset_bytes);
		ensure!(sig_asset == asset_id, Error::<T>::InvalidPublicSignals);

		ensure!(
			T::Relayer::pending_relay_fees(&validator, asset_id) >= amount_u128,
			Error::<T>::InsufficientPendingFees
		);
		T::Relayer::consume_relay_fee(&validator, asset_id, amount_u128)?;

		let leaf_index = Pallet::<T>::insert_leaf(commitment)?;
		CommitmentMemos::<T>::insert(commitment, memo);

		Pallet::<T>::deposit_event(Event::ValidatorFeesClaimed {
			validator,
			asset_id,
			amount,
			commitment,
			leaf_index,
		});

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, mock_pending_fees_get, mock_pending_fees_set, new_test_ext},
		operations::assets::AssetOperation,
		pallet::Event as PalletEvent,
		storage::CommitmentRepository,
		types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
	};
	use frame_support::{assert_noop, assert_ok};

	// ── helpers ───────────────────────────────────────────────────────────────

	fn setup_asset() -> u32 {
		let name = frame_support::BoundedVec::try_from(b"ORB".to_vec()).unwrap();
		let sym = frame_support::BoundedVec::try_from(b"ORB".to_vec()).unwrap();
		AssetOperation::register_asset::<Test>(name, sym, 18, None, 1u64).unwrap()
	}

	fn make_commitment() -> Commitment {
		Commitment::new([0x11u8; 32])
	}

	fn make_memo() -> EncryptedMemo {
		EncryptedMemo::from_bytes(&[0x02u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap()
	}

	/// A valid non-empty 128-byte proof accepted by the mock verifier.
	fn make_proof() -> Vec<u8> {
		vec![0x01u8; 128]
	}

	/// Build the 76-byte public_signals buffer consistent with `commitment`, `amount`, `asset_id`.
	/// Layout: commitment[0..32] | value[32..40] | asset_id[40..44] | owner_hash[44..76]
	fn make_signals(commitment: &Commitment, amount: u128, asset_id: u32) -> Vec<u8> {
		let mut s = vec![0u8; 76];
		s[..32].copy_from_slice(&commitment.0);
		s[32..40].copy_from_slice(&(amount as u64).to_le_bytes());
		s[40..44].copy_from_slice(&asset_id.to_le_bytes());
		s
	}

	// ── claim_shielded ────────────────────────────────────────────────────────

	#[test]
	fn claim_shielded_works() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 200u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator,
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
			));
		});
	}

	#[test]
	fn claim_shielded_invalid_asset_fails() {
		new_test_ext().execute_with(|| {
			let commitment = make_commitment();
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					1u64,
					commitment,
					100u128,
					99u32, // not registered — fails before proof check
					make_memo(),
					make_proof(),
					make_signals(&commitment, 100u128, 99u32),
				),
				crate::pallet::Error::<Test>::InvalidAssetId
			);
		});
	}

	#[test]
	fn claim_shielded_insufficient_pending_fees_fails() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let commitment = make_commitment();
			let amount = 100u128;
			mock_pending_fees_set(validator, asset_id, 50u128); // only 50 available

			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					amount, // requesting 100
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, amount, asset_id),
				),
				crate::pallet::Error::<Test>::InsufficientPendingFees
			);
		});
	}

	#[test]
	fn claim_shielded_inserts_commitment_into_tree() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			assert!(!CommitmentRepository::exists::<Test>(&commitment));

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator,
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
			));

			assert!(CommitmentRepository::exists::<Test>(&commitment));
		});
	}

	#[test]
	fn claim_shielded_stores_memo() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			let memo = make_memo();
			mock_pending_fees_set(validator, asset_id, amount);

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator,
				commitment,
				amount,
				asset_id,
				memo.clone(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
			));

			let stored = CommitmentRepository::get_memo::<Test>(&commitment);
			assert_eq!(stored, Some(memo));
		});
	}

	#[test]
	fn claim_shielded_deducts_pending_fees() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let initial = 500u128;
			let claim = 200u128;
			mock_pending_fees_set(validator, asset_id, initial);

			let commitment = make_commitment();
			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator,
				commitment,
				claim,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, claim, asset_id),
			));

			let remaining = mock_pending_fees_get(validator, asset_id);
			assert_eq!(remaining, initial - claim);
		});
	}

	#[test]
	fn claim_shielded_emits_validator_fees_claimed_event() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 300u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator,
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
			));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					&r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::ValidatorFeesClaimed {
						validator: ev,
						asset_id: ea,
						amount: emo,
						commitment: ec,
						..
					}) if *ev == validator && *ea == asset_id && *emo == amount && *ec == commitment
				)
			});
			assert!(found, "ValidatorFeesClaimed event not emitted");
		});
	}

	#[test]
	fn claim_shielded_zero_amount_fails_with_insufficient() {
		new_test_ext().execute_with(|| {
			// pending fees = 0, amount = 0 would pass the check, but let's verify the boundary
			let validator: u64 = 2;
			let asset_id = setup_asset();
			mock_pending_fees_set(validator, asset_id, 0u128);

			// requesting 1 with 0 available → InsufficientPendingFees
			let commitment = make_commitment();
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					1u128,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, 1u128, asset_id),
				),
				crate::pallet::Error::<Test>::InsufficientPendingFees
			);
		});
	}

	#[test]
	fn claim_shielded_zero_amount_fails_with_invalid_amount() {
		// amount == 0 must be rejected before the ZK check. A value_proof that
		// encodes value=0 is cryptographically valid but inserts a worthless leaf into
		// the Merkle tree — cheap spam that wastes tree capacity.
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			mock_pending_fees_set(validator, asset_id, 500u128);

			let commitment = make_commitment();
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					0u128,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, 0u128, asset_id),
				),
				crate::pallet::Error::<Test>::InvalidAmount
			);
		});
	}

	// ── ZK proof / public_signals validation ─────────────────────────────────

	/// A proof of 128 zero bytes — the MockZkVerifier sentinel for "cryptographically
	/// rejected" (returns Ok(false)). Distinct from `make_proof()` (first byte 0x01)
	/// which the mock accepts.
	#[cfg(not(feature = "runtime-benchmarks"))]
	fn make_rejected_proof() -> Vec<u8> {
		vec![0x00u8; 128]
	}

	// T1 — Integration tests for claim_shielded ZK path
	//
	// These tests exercise the `ensure!(is_valid, Error::InvalidProof)` guard that
	// sits after the ZK verifier call — the path that fires when the verifier itself
	// returns Ok(false) (cryptographically invalid proof, correct format).
	// The MockZkVerifier returns Ok(false) for any proof whose first byte is 0x00.

	#[test]
	#[cfg(not(feature = "runtime-benchmarks"))]
	fn claim_shielded_with_cryptographically_invalid_proof_returns_invalid_proof_error() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			// Proof has correct length (128) and correct signals, but the mock
			// verifier returns Ok(false) for proofs starting with 0x00.
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_rejected_proof(), // Ok(false) from verifier
					make_signals(&commitment, amount, asset_id),
				),
				crate::pallet::Error::<Test>::InvalidProof
			);
		});
	}

	#[test]
	#[cfg(not(feature = "runtime-benchmarks"))]
	fn claim_shielded_rejected_proof_leaves_no_state_changes() {
		// A rejected proof must not insert the commitment or consume fees.
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 200u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			let _ = FeeOperation::claim_shielded::<Test>(
				validator,
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_rejected_proof(),
				make_signals(&commitment, amount, asset_id),
			);

			// Commitment must NOT be in the tree
			assert!(!CommitmentRepository::exists::<Test>(&commitment));
			// Pending fees must NOT have been consumed
			assert_eq!(mock_pending_fees_get(validator, asset_id), amount);
		});
	}

	#[test]
	fn claim_shielded_empty_proof_fails() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					amount,
					asset_id,
					make_memo(),
					vec![], // empty proof
					make_signals(&commitment, amount, asset_id),
				),
				crate::pallet::Error::<Test>::InvalidProof
			);
		});
	}

	#[test]
	fn claim_shielded_wrong_proof_length_fails() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					amount,
					asset_id,
					make_memo(),
					vec![0x01u8; 64], // wrong length (not 128)
					make_signals(&commitment, amount, asset_id),
				),
				crate::pallet::Error::<Test>::InvalidProof
			);
		});
	}

	#[test]
	fn claim_shielded_wrong_signals_length_fails() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_proof(),
					vec![0u8; 32], // wrong length (not 76)
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn claim_shielded_signals_commitment_mismatch_fails() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			let other_commitment = Commitment::new([0xAAu8; 32]);
			mock_pending_fees_set(validator, asset_id, amount);

			// signals have a different commitment than the extrinsic argument
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&other_commitment, amount, asset_id),
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn claim_shielded_signals_amount_mismatch_fails() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			// signals encode 999 but extrinsic claims 100
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, 999u128, asset_id),
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn claim_shielded_signals_asset_id_mismatch_fails() {
		new_test_ext().execute_with(|| {
			let validator: u64 = 1;
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator, asset_id, amount);

			// signals encode asset_id=999 but extrinsic claims registered asset_id
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator,
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, amount, 999u32),
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}
}
