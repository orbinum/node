//! Relay fee accounting: crediting the fee a call paid, and claiming it later.

use crate::{
	pallet::{Assets, CommitmentMemos, Config, Error, Event, Pallet},
	types::{Commitment, EncryptedMemo},
};
use frame_support::{ensure, pallet_prelude::*};
use pallet_relayer::RelayerInterface as _;
#[cfg(not(feature = "skip-proof-verification"))]
use pallet_zk_verifier::ZkVerifierPort;
use sp_runtime::SaturatedConversion;

pub type BalanceOf<T> = <<T as Config>::Currency as frame_support::traits::Currency<
	<T as frame_system::Config>::AccountId,
>>::Balance;

/// Credit `fee` to the submitting relayer, falling back to the block author.
///
/// `relayer_evm` comes from the dispatch origin, never from a call argument: the
/// ZK proof binds the fee *amount* but not its *recipient*, so an argument would
/// be an unauthenticated claim any resubmitter could rewrite. It is still resolved
/// through the registry rather than trusted, because the EVM address must map to
/// a substrate account. An address that resolves to nobody is not an error:
/// relaying is not gated on registration, and rejecting here would fail a user's
/// transaction because of someone else's misconfiguration. The fee goes to the
/// block author instead and [`Event::RelayFeeDiverted`] records that it did.
///
/// Both `unshield` and `private_transfer` route through here so the two cannot
/// drift apart on a security-relevant path.
pub fn credit_relay_fee<T: Config>(
	relayer_evm: Option<sp_core::H160>,
	asset_id: u32,
	fee: u128,
) -> Result<(), Error<T>> {
	let resolved = relayer_evm.and_then(|addr| T::Relayer::resolve_relayer(&addr));

	let resolved_to_author = resolved
		.as_ref()
		.is_some_and(|account| T::Relayer::block_author().as_ref() == Some(account));

	let recipient = match resolved {
		Some(account) => account,
		None => {
			let author = T::Relayer::block_author().ok_or(Error::<T>::FeeRecipientUnavailable)?;
			// Only report a diversion when an address was actually named: a call
			// with no relayer at all was never asking to credit anyone else.
			if let Some(requested) = relayer_evm {
				Pallet::<T>::deposit_event(Event::RelayFeeDiverted {
					requested,
					credited: author.clone(),
					asset_id,
					amount: fee,
				});
			}
			author
		}
	};

	// A validator relaying in its own slot is normal — with N authors it happens
	// about 1/N of the time by pure rotation — so this is a signal, never a
	// verdict. What it makes visible is the one residual attack: an author can
	// ignore its own pool ordering and include a copy of someone else's spend
	// submitted under its own key. That shows up as a self-relay rate materially
	// above 1/N, only detectable by watching the rate across many sessions.
	//
	// Gated on `resolved_to_author`, not on the final recipient: the fallback
	// credits the author on EVERY unrelayed call, and reporting those would bury
	// the signal in traffic that carries no claim about who relayed anything.
	if resolved_to_author {
		Pallet::<T>::deposit_event(Event::SelfRelayedFee {
			author: recipient.clone(),
			asset_id,
			amount: fee,
		});
	}

	T::Relayer::accumulate_relay_fee(&recipient, asset_id, fee);
	Ok(())
}

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
	#[allow(clippy::too_many_arguments)]
	pub fn claim_shielded<T: Config>(
		validator: T::AccountId,
		commitment: Commitment,
		amount: BalanceOf<T>,
		asset_id: u32,
		memo: EncryptedMemo,
		proof: sp_std::vec::Vec<u8>,
		public_signals: sp_std::vec::Vec<u8>,
		circuit_version: u32,
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

		#[cfg(not(feature = "skip-proof-verification"))]
		{
			let is_valid =
				T::ZkVerifier::verify_value_proof(&proof, &public_signals, Some(circuit_version))?;
			ensure!(is_valid, Error::<T>::InvalidProof);
		}
		#[cfg(feature = "skip-proof-verification")]
		let _ = circuit_version;

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
		mock::{
			Test, acc, mock_pending_fees_get, mock_pending_fees_set, mock_register_relayer,
			new_test_ext,
		},
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
		AssetOperation::register_asset::<Test>(name, sym, 18, None, acc(1)).unwrap()
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
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 200u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator.clone(),
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
				1,
			));
		});
	}

	#[test]
	fn claim_shielded_invalid_asset_fails() {
		new_test_ext().execute_with(|| {
			let commitment = make_commitment();
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					acc(1),
					commitment,
					100u128,
					99u32, // not registered — fails before proof check
					make_memo(),
					make_proof(),
					make_signals(&commitment, 100u128, 99u32),
					1,
				),
				crate::pallet::Error::<Test>::InvalidAssetId
			);
		});
	}

	#[test]
	fn claim_shielded_insufficient_pending_fees_fails() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let commitment = make_commitment();
			let amount = 100u128;
			mock_pending_fees_set(validator.clone(), asset_id, 50u128); // only 50 available

			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					amount, // requesting 100
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, amount, asset_id),
					1,
				),
				crate::pallet::Error::<Test>::InsufficientPendingFees
			);
		});
	}

	#[test]
	fn claim_shielded_inserts_commitment_into_tree() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			assert!(!CommitmentRepository::exists::<Test>(&commitment));

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator.clone(),
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
				1,
			));

			assert!(CommitmentRepository::exists::<Test>(&commitment));
		});
	}

	#[test]
	fn claim_shielded_stores_memo() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			let memo = make_memo();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator.clone(),
				commitment,
				amount,
				asset_id,
				memo.clone(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
				1,
			));

			let stored = CommitmentRepository::get_memo::<Test>(&commitment);
			assert_eq!(stored, Some(memo));
		});
	}

	#[test]
	fn claim_shielded_deducts_pending_fees() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let initial = 500u128;
			let claim = 200u128;
			mock_pending_fees_set(validator.clone(), asset_id, initial);

			let commitment = make_commitment();
			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator.clone(),
				commitment,
				claim,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, claim, asset_id),
				1,
			));

			let remaining = mock_pending_fees_get(validator, asset_id);
			assert_eq!(remaining, initial - claim);
		});
	}

	#[test]
	fn claim_shielded_emits_validator_fees_claimed_event() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 300u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator.clone(),
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
				1,
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
			let validator = acc(2);
			let asset_id = setup_asset();
			mock_pending_fees_set(validator.clone(), asset_id, 0u128);

			// requesting 1 with 0 available → InsufficientPendingFees
			let commitment = make_commitment();
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					1u128,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, 1u128, asset_id),
					1,
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
			let validator = acc(1);
			let asset_id = setup_asset();
			mock_pending_fees_set(validator.clone(), asset_id, 500u128);

			let commitment = make_commitment();
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					0u128,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, 0u128, asset_id),
					1,
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
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			// Proof has correct length (128) and correct signals, but the mock
			// verifier returns Ok(false) for proofs starting with 0x00.
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_rejected_proof(), // Ok(false) from verifier
					make_signals(&commitment, amount, asset_id),
					1,
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
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 200u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			let _ = FeeOperation::claim_shielded::<Test>(
				validator.clone(),
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_rejected_proof(),
				make_signals(&commitment, amount, asset_id),
				1,
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
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					amount,
					asset_id,
					make_memo(),
					vec![], // empty proof
					make_signals(&commitment, amount, asset_id),
					1,
				),
				crate::pallet::Error::<Test>::InvalidProof
			);
		});
	}

	#[test]
	fn claim_shielded_wrong_proof_length_fails() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					amount,
					asset_id,
					make_memo(),
					vec![0x01u8; 64], // wrong length (not 128)
					make_signals(&commitment, amount, asset_id),
					1,
				),
				crate::pallet::Error::<Test>::InvalidProof
			);
		});
	}

	#[test]
	fn claim_shielded_wrong_signals_length_fails() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_proof(),
					vec![0u8; 32], // wrong length (not 76)
					1,
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn claim_shielded_signals_commitment_mismatch_fails() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			let other_commitment = Commitment::new([0xAAu8; 32]);
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			// signals have a different commitment than the extrinsic argument
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&other_commitment, amount, asset_id),
					1,
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn claim_shielded_signals_amount_mismatch_fails() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			// signals encode 999 but extrinsic claims 100
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, 999u128, asset_id),
					1,
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn claim_shielded_signals_asset_id_mismatch_fails() {
		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 100u128;
			let commitment = make_commitment();
			mock_pending_fees_set(validator.clone(), asset_id, amount);

			// signals encode asset_id=999 but extrinsic claims registered asset_id
			assert_noop!(
				FeeOperation::claim_shielded::<Test>(
					validator.clone(),
					commitment,
					amount,
					asset_id,
					make_memo(),
					make_proof(),
					make_signals(&commitment, amount, 999u32),
					1,
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	// ── ledger invariant: claim must NOT change PoolBalancePerAsset ───────────

	#[test]
	fn claim_does_not_change_pool_balance() {
		use crate::storage::PoolBalanceRepository;
		use frame_support::traits::Currency;
		use sp_runtime::AccountId32;

		new_test_ext().execute_with(|| {
			let validator = acc(1);
			let asset_id = setup_asset();
			let amount = 200u128;
			let commitment = make_commitment();

			// Seed pending fee + a pool ledger/physical balance backing it.
			mock_pending_fees_set(validator.clone(), asset_id, amount);
			let pool = crate::Pallet::<Test>::pool_account_id();
			let _ = <pallet_balances::Pallet<Test> as Currency<AccountId32>>::deposit_creating(
				&pool, amount,
			);
			PoolBalanceRepository::set_asset_balance::<Test>(asset_id, amount);

			let before = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);

			assert_ok!(FeeOperation::claim_shielded::<Test>(
				validator.clone(),
				commitment,
				amount,
				asset_id,
				make_memo(),
				make_proof(),
				make_signals(&commitment, amount, asset_id),
				1,
			));

			// The claim swaps a pending number for a note; both are backed by the
			// same physical tokens already counted in the ledger. It must NOT move
			// PoolBalancePerAsset, and the ledger stays == physical balance.
			let after = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
			assert_eq!(after, before, "claim must not change the pool ledger");
			let physical =
				<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&pool);
			assert_eq!(after, physical, "ledger must equal physical pool balance");
			assert_eq!(mock_pending_fees_get(validator, asset_id), 0);
		});
	}

	// ── extrinsic input bounds (decode-before-reject guard) ──────────────────

	/// The `claim_shielded_fees` extrinsic takes `BoundedVec`, so an oversized
	/// proof/signals input is rejected by the codec bound before any body logic.
	#[test]
	fn claim_shielded_fees_inputs_are_bounded() {
		use frame_support::{BoundedVec, traits::ConstU32};

		// proof bound = 512: at-bound fits, over-bound rejected.
		assert!(BoundedVec::<u8, ConstU32<512>>::try_from(vec![0u8; 512]).is_ok());
		assert!(BoundedVec::<u8, ConstU32<512>>::try_from(vec![0u8; 513]).is_err());
		// signals bound = 128: the real 76-byte payload fits, over-bound rejected.
		assert!(BoundedVec::<u8, ConstU32<128>>::try_from(vec![0u8; 76]).is_ok());
		assert!(BoundedVec::<u8, ConstU32<128>>::try_from(vec![0u8; 129]).is_err());
	}

	// ── SelfRelayedFee ────────────────────────────────────────────────────────
	//
	// The mock's block author is `acc(1)` (see `MockBlockAuthor`).

	/// The signal that matters: a registered relayer that is also the author.
	#[test]
	fn a_relayer_that_authors_its_own_block_is_flagged() {
		new_test_ext().execute_with(|| {
			frame_system::Pallet::<Test>::set_block_number(1);
			let addr = sp_core::H160::repeat_byte(0xAA);
			mock_register_relayer(acc(1), addr); // acc(1) IS the block author

			assert_ok!(credit_relay_fee::<Test>(Some(addr), 0, 500));

			assert!(
				frame_system::Pallet::<Test>::events().iter().any(|r| matches!(
					&r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::SelfRelayedFee { .. })
				)),
				"a resolved relayer equal to the author must be reported"
			);
		});
	}

	/// A relayer that is not the author is ordinary traffic.
	#[test]
	fn a_relayer_that_is_not_the_author_is_not_flagged() {
		new_test_ext().execute_with(|| {
			frame_system::Pallet::<Test>::set_block_number(1);
			let addr = sp_core::H160::repeat_byte(0xBB);
			mock_register_relayer(acc(2), addr); // acc(2) != author acc(1)

			assert_ok!(credit_relay_fee::<Test>(Some(addr), 0, 500));

			assert!(
				!frame_system::Pallet::<Test>::events().iter().any(|r| matches!(
					&r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::SelfRelayedFee { .. })
				)),
				"a relayer other than the author must not be flagged"
			);
		});
	}

	/// The regression this event was silently failing: an unrelayed call credits
	/// the author by design, on EVERY such call. Reporting those would drown the
	/// signal in traffic that makes no claim about who relayed anything.
	#[test]
	fn the_block_author_fallback_is_not_flagged_as_self_relay() {
		new_test_ext().execute_with(|| {
			frame_system::Pallet::<Test>::set_block_number(1);

			// No relayer named at all.
			assert_ok!(credit_relay_fee::<Test>(None, 0, 500));
			// Named, but unregistered — resolves to nobody.
			assert_ok!(credit_relay_fee::<Test>(
				Some(sp_core::H160::repeat_byte(0xCC)),
				0,
				500
			));

			assert!(
				!frame_system::Pallet::<Test>::events().iter().any(|r| matches!(
					&r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::SelfRelayedFee { .. })
				)),
				"the fallback to the block author is not a self-relay"
			);
			// The fee still lands on the author both times.
			assert_eq!(mock_pending_fees_get(acc(1), 0), 1000);
		});
	}
}
