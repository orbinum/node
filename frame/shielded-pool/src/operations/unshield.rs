use crate::{
	merkle::MerkleTreeService,
	pallet::{CommitmentMemos, Config, Error, Event, Pallet},
	storage::{
		AssetRepository, CommitmentRepository, MerkleRepository, NullifierRepository,
		PoolBalanceRepository,
	},
	types::{Commitment, EncryptedMemo as FrameEncryptedMemo, Nullifier},
};
use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use pallet_relayer::RelayerInterface as _;
#[cfg(not(feature = "skip-proof-verification"))]
use pallet_zk_verifier::ZkVerifierPort;
#[cfg(not(feature = "skip-proof-verification"))]
use parity_scale_codec::Encode;
use sp_runtime::{SaturatedConversion, traits::Zero};

pub struct UnshieldOperation;

/// Encode a recipient account into the exact 32-byte field element bound into the
/// unshield proof. Orbinum's `AccountId` is always `AccountId32` (every signature
/// scheme — sr25519/ed25519/ECDSA/EVM, and future ones like Solana — unifies to a
/// 32-byte account). A non-32-byte encoding is rejected with `InvalidRecipient`
/// rather than silently binding a zeroed recipient.
#[cfg(not(feature = "skip-proof-verification"))]
fn recipient_to_field<T: Config>(
	recipient: &<T as frame_system::Config>::AccountId,
) -> Result<[u8; 32], Error<T>> {
	<[u8; 32]>::try_from(recipient.encode().as_slice()).map_err(|_| Error::<T>::InvalidRecipient)
}

impl UnshieldOperation {
	#[allow(clippy::too_many_arguments)]
	pub fn execute<T: Config>(
		#[cfg_attr(feature = "skip-proof-verification", allow(unused_variables))] proof: &[u8],
		merkle_root: [u8; 32],
		nullifier: Nullifier,
		asset_id: u32,
		amount: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		recipient: <T as frame_system::Config>::AccountId,
		fee: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		change_commitment: [u8; 32],
		change_encrypted_memo: FrameEncryptedMemo,
		relayer_evm: Option<sp_core::H160>,
	) -> DispatchResult {
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);
		ensure!(!amount.is_zero(), Error::<T>::InvalidAmount);
		ensure!(
			recipient != Pallet::<T>::pool_account_id(),
			Error::<T>::InvalidRecipient
		);
		ensure!(
			MerkleRepository::is_known_root::<T>(&merkle_root),
			Error::<T>::UnknownMerkleRoot
		);
		ensure!(
			!NullifierRepository::is_used::<T>(&nullifier),
			Error::<T>::NullifierAlreadyUsed
		);

		// If a change note is present, ensure its commitment is not already in the tree.
		let has_change = change_commitment != [0u8; 32];
		if has_change {
			let change_comm = Commitment::new(change_commitment);
			ensure!(
				!CommitmentRepository::exists::<T>(&change_comm),
				Error::<T>::CommitmentAlreadyExists
			);
			// For partial unshield, memo must be valid size (176 bytes).
			if !change_encrypted_memo.is_empty() {
				ensure!(
					change_encrypted_memo.is_valid_size(),
					Error::<T>::InvalidMemoSize
				);
			}
		} else {
			// For total unshield, memo must be empty.
			ensure!(
				change_encrypted_memo.is_empty(),
				Error::<T>::InvalidMemoSize
			);
		}

		let total = amount.checked_add(&fee).ok_or(Error::<T>::InvalidAmount)?;
		ensure!(
			PoolBalanceRepository::get_asset_balance::<T>(asset_id) >= total,
			Error::<T>::InsufficientPoolBalance
		);

		let min_fee: <T::Currency as Currency<T::AccountId>>::Balance =
			T::Relayer::min_relay_fee().saturated_into();
		ensure!(fee >= min_fee, Error::<T>::FeeTooLow);
		let fee_u128: u128 = fee.saturated_into();
		let amount_u128: u128 = amount.saturated_into();

		#[cfg(not(feature = "skip-proof-verification"))]
		{
			let recipient_bytes = recipient_to_field::<T>(&recipient)?;
			let valid = T::ZkVerifier::verify_unshield_proof(
				proof,
				&merkle_root,
				&nullifier.0,
				amount_u128,
				&recipient_bytes,
				asset_id,
				fee_u128,
				&change_commitment,
				None,
			)?;

			ensure!(valid, Error::<T>::ProofVerificationFailed);
		}

		#[cfg(feature = "skip-proof-verification")]
		{
			let _ = amount_u128;
			let _ = fee_u128;
		}

		T::Currency::transfer(
			&Pallet::<T>::pool_account_id(),
			&recipient,
			amount,
			ExistenceRequirement::AllowDeath,
		)?;

		if fee > <T::Currency as Currency<T::AccountId>>::Balance::zero() {
			let recipient_account = relayer_evm
				.and_then(|addr| T::Relayer::resolve_relayer(&addr))
				.or_else(T::Relayer::block_author)
				.ok_or(Error::<T>::FeeRecipientUnavailable)?;
			T::Relayer::accumulate_relay_fee(&recipient_account, asset_id, fee_u128);
		}

		// Decrement only `amount`: the `fee` tokens stay physically in the pool as
		// backing for the pending relayer fee, so the tracked balance must retain
		// them too. This is correct ONLY because the guard above requires
		// `>= amount + fee`; do not weaken it to `>= amount` or fees go unbacked.
		PoolBalanceRepository::decrease_balance::<T>(asset_id, amount);

		// Insert the change note commitment into the Merkle tree (partial unshield).
		let change_leaf_index = if has_change {
			let change_comm = Commitment::new(change_commitment);
			let idx = MerkleTreeService::insert_leaf::<T>(change_comm)?;

			// Store the encrypted memo for note recovery and audit.
			if !change_encrypted_memo.is_empty() {
				CommitmentMemos::<T>::insert(change_comm, change_encrypted_memo.clone());
			}

			Some(idx)
		} else {
			None
		};

		let current_block = frame_system::Pallet::<T>::block_number();
		NullifierRepository::mark_as_used::<T>(nullifier, current_block);

		Pallet::<T>::deposit_event(Event::Unshielded {
			nullifier,
			amount,
			recipient,
			change_commitment: if has_change {
				Some(change_commitment)
			} else {
				None
			},
			change_encrypted_memo: if has_change && !change_encrypted_memo.is_empty() {
				Some(change_encrypted_memo)
			} else {
				None
			},
			change_leaf_index,
		});

		Ok(())
	}

	pub fn is_nullifier_used<T: Config>(nullifier: &Nullifier) -> bool {
		NullifierRepository::is_used::<T>(nullifier)
	}

	pub fn is_merkle_root_known<T: Config>(root: &[u8; 32]) -> bool {
		MerkleRepository::is_known_root::<T>(root)
	}

	pub fn asset_exists<T: Config>(asset_id: u32) -> bool {
		AssetRepository::exists::<T>(asset_id)
	}

	pub fn is_asset_verified<T: Config>(asset_id: u32) -> bool {
		AssetRepository::get_asset::<T>(asset_id)
			.map(|asset| asset.is_verified)
			.unwrap_or(false)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, acc, new_test_ext},
		operations::assets::AssetOperation,
		pallet::Event as PalletEvent,
		storage::{
			CommitmentRepository, MerkleRepository, NullifierRepository, PoolBalanceRepository,
		},
		types::{Commitment, Nullifier},
	};
	use frame_support::{assert_err, assert_noop, assert_ok, traits::Currency};
	use sp_runtime::AccountId32;

	// ── helpers ──────────────────────────────────────────────────────────────

	const KNOWN_ROOT: [u8; 32] = [0xAAu8; 32];

	fn setup_asset() -> u32 {
		let name = frame_support::BoundedVec::try_from(b"Orbinum".to_vec()).unwrap();
		let symbol = frame_support::BoundedVec::try_from(b"ORB".to_vec()).unwrap();
		let id = AssetOperation::register_asset::<Test>(name, symbol, 18, None, acc(1)).unwrap();
		AssetOperation::verify::<Test>(id).unwrap();
		id
	}

	/// Fund pool account (currency + pool balance tracker).
	fn fund_pool(asset_id: u32, total: u128) {
		let pool = crate::Pallet::<Test>::pool_account_id();
		let _ = <pallet_balances::Pallet<Test> as Currency<AccountId32>>::deposit_creating(
			&pool, total,
		);
		PoolBalanceRepository::set_asset_balance::<Test>(asset_id, total);
	}

	fn nullifier(seed: u8) -> Nullifier {
		Nullifier::new([seed; 32])
	}

	fn proof() -> &'static [u8] {
		&[0x01u8; 72]
	}

	// ── execute ───────────────────────────────────────────────────────────────

	#[test]
	fn execute_works() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let amount = 500u128;
			let fee = 0u128;
			fund_pool(asset_id, amount + fee);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x01),
				asset_id,
				amount,
				acc(2), // recipient
				0u128,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));
		});
	}

	#[test]
	fn execute_invalid_asset_fails() {
		new_test_ext().execute_with(|| {
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(1),
					99u32,
					100u128,
					acc(2),
					0u128,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::InvalidAssetId
			);
		});
	}

	#[test]
	fn execute_asset_not_verified_fails() {
		new_test_ext().execute_with(|| {
			let name = frame_support::BoundedVec::try_from(b"T".to_vec()).unwrap();
			let sym = frame_support::BoundedVec::try_from(b"T".to_vec()).unwrap();
			let id = AssetOperation::register_asset::<Test>(name, sym, 18, None, acc(1)).unwrap();
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			fund_pool(id, 1_000u128);

			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(1),
					id,
					100u128,
					acc(2),
					0u128,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::AssetNotVerified
			);
		});
	}

	#[test]
	fn execute_zero_amount_fails() {
		// amount == 0 must be rejected before any ZK check so that benchmark mode
		// (which skips the verifier) cannot mark a nullifier as spent without moving
		// any funds.
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			fund_pool(asset_id, 1_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(0x77),
					asset_id,
					0u128,
					acc(2),
					0u128,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::InvalidAmount
			);
		});
	}

	#[test]
	fn execute_invalid_recipient_pool_account_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			fund_pool(asset_id, 1_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let pool = crate::Pallet::<Test>::pool_account_id();
			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(1),
					asset_id,
					100u128,
					pool, // recipient == pool → rejected
					0u128,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::InvalidRecipient
			);
		});
	}

	#[test]
	fn execute_unknown_root_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			fund_pool(asset_id, 1_000u128);
			// Root never added

			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					[0xBBu8; 32],
					nullifier(1),
					asset_id,
					100u128,
					acc(2),
					0u128,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::UnknownMerkleRoot
			);
		});
	}

	#[test]
	fn execute_nullifier_already_used_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			fund_pool(asset_id, 2_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let n = nullifier(0x02);
			NullifierRepository::mark_as_used::<Test>(n, 1u64);

			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					n,
					asset_id,
					500u128,
					acc(2),
					0u128,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::NullifierAlreadyUsed
			);
		});
	}

	#[test]
	fn execute_insufficient_pool_balance_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			// Pool has 50 but we want 100 + 0 = 100
			fund_pool(asset_id, 50u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(1),
					asset_id,
					100u128,
					acc(2),
					0u128,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::InsufficientPoolBalance
			);
		});
	}

	#[test]
	fn execute_marks_nullifier_used() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let n = nullifier(0x05);
			fund_pool(asset_id, 1_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert!(!UnshieldOperation::is_nullifier_used::<Test>(&n));
			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				n,
				asset_id,
				300u128,
				acc(2),
				0u128,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));
			assert!(UnshieldOperation::is_nullifier_used::<Test>(&n));
		});
	}

	#[test]
	fn execute_decreases_pool_balance() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let amount = 400u128;
			fund_pool(asset_id, 1_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x06),
				asset_id,
				amount,
				acc(2),
				0u128,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));

			let remaining = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
			assert_eq!(remaining, 1_000u128 - amount);
		});
	}

	#[test]
	fn execute_transfers_currency_to_recipient() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let recipient = acc(2);
			let amount = 300u128;
			fund_pool(asset_id, 1_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let before =
				<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&recipient);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x07),
				asset_id,
				amount,
				recipient.clone(),
				0u128,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));

			let after =
				<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(&recipient);
			assert_eq!(after - before, amount);
		});
	}

	#[test]
	fn execute_emits_unshielded_event() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let n = nullifier(0x08);
			fund_pool(asset_id, 1_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				n,
				asset_id,
				200u128,
				acc(2),
				0u128,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Unshielded {
						nullifier: en,
						amount: 200,
						recipient: ref er,
						change_commitment: None,
						change_encrypted_memo: None,
						change_leaf_index: None,
					}) if en == n && *er == acc(2)
				)
			});
			assert!(found, "Unshielded event not emitted");
		});
	}

	#[test]
	fn execute_accumulates_relay_fee_to_block_author() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let amount = 500u128;
			let fee = 50u128;
			fund_pool(asset_id, amount + fee);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x09),
				asset_id,
				amount,
				acc(2),
				fee,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));

			// MockRelayer block_author returns Some(1); fee should be accumulated there
			let pending = crate::mock::mock_pending_fees_get(acc(1), asset_id);
			assert_eq!(pending, fee);
		});
	}

	// ── partial unshield ─────────────────────────────────────────────────────

	#[test]
	fn execute_partial_unshield_creates_change_note() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			// Fund pool with the full note value (amount + change_value).
			fund_pool(asset_id, 1_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let change_comm_bytes = [0xCCu8; 32];
			let amount = 600u128;

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x10),
				asset_id,
				amount,
				acc(2),
				0u128,
				change_comm_bytes,
				FrameEncryptedMemo::default(),
				None,
			));

			// The change commitment must now exist as a leaf in the Merkle tree.
			assert_eq!(
				MerkleRepository::get_tree_size::<Test>(),
				1,
				"change commitment should have been inserted as a Merkle leaf"
			);
			assert!(
				MerkleRepository::find_leaf_index::<Test>(&Commitment::new(change_comm_bytes))
					.is_some(),
				"change commitment not found in Merkle tree leaves"
			);

			// Pool balance must have decreased only by `amount`, not by the full note value.
			let pool_bal = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
			assert_eq!(
				pool_bal,
				1_000u128 - amount,
				"pool balance should only decrease by amount"
			);

			// Event must carry the change_commitment.
			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					&r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Unshielded {
						change_commitment: Some(cc),
						..
					}) if cc == &change_comm_bytes
				)
			});
			assert!(found, "Unshielded event did not carry change_commitment");
		});
	}

	#[test]
	fn execute_total_unshield_with_zero_change_works() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let amount = 800u128;
			fund_pool(asset_id, amount);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x11),
				asset_id,
				amount,
				acc(2),
				0u128,
				[0u8; 32], // zero change_commitment = total unshield
				FrameEncryptedMemo::default(),
				None,
			));

			// Pool balance must be zero.
			let pool_bal = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
			assert_eq!(pool_bal, 0u128, "pool balance should be fully drained");

			// No change commitment in tree (tree size remains 0 since no insert happened).
			assert_eq!(
				MerkleRepository::get_tree_size::<Test>(),
				0,
				"tree should have no leaves for total unshield"
			);

			// Event carries change_commitment: None.
			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Unshielded {
						change_commitment: None,
						..
					})
				)
			});
			assert!(
				found,
				"Unshielded event should have change_commitment: None"
			);
		});
	}

	#[test]
	fn execute_change_commitment_duplicate_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			fund_pool(asset_id, 2_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let change_comm_bytes = [0xDDu8; 32];
			let change_comm = Commitment::new(change_comm_bytes);

			// Mark commitment as already existing in the pool.
			CommitmentRepository::store_memo::<Test>(change_comm, Default::default());

			// Attempting to reuse the same commitment as a change note must fail.
			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(0x12),
					asset_id,
					500u128,
					acc(2),
					0u128,
					change_comm_bytes,
					FrameEncryptedMemo::default(),
					None,
				),
				Error::<Test>::CommitmentAlreadyExists
			);
		});
	}

	// ── query helpers ─────────────────────────────────────────────────────────

	#[test]
	fn is_nullifier_used_false_by_default() {
		new_test_ext().execute_with(|| {
			assert!(!UnshieldOperation::is_nullifier_used::<Test>(&nullifier(
				0xCC
			)));
		});
	}

	#[test]
	fn is_merkle_root_known_returns_correct_values() {
		new_test_ext().execute_with(|| {
			assert!(!UnshieldOperation::is_merkle_root_known::<Test>(
				&KNOWN_ROOT
			));
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			assert!(UnshieldOperation::is_merkle_root_known::<Test>(&KNOWN_ROOT));
		});
	}

	// ── ledger-solvency invariant ────────────────────────────────────────────
	// Invariant (A): PoolBalancePerAsset[a] == Currency::free_balance(pool) for the
	// native asset. Fees stay physically in the pool until their note is unshielded,
	// so tracked and physical always move together.

	fn pool_physical() -> u128 {
		<pallet_balances::Pallet<Test> as Currency<AccountId32>>::free_balance(
			&crate::Pallet::<Test>::pool_account_id(),
		)
	}

	fn tracked(asset_id: u32) -> u128 {
		PoolBalanceRepository::get_asset_balance::<Test>(asset_id)
	}

	/// T2 — unshield with a fee decrements the ledger by `amount` only (the fee
	/// stays physical as backing), and ledger == physical afterwards.
	#[test]
	fn unshield_with_fee_decrements_amount_only() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let (amount, fee) = (500u128, 50u128);
			fund_pool(asset_id, amount + fee);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x21),
				asset_id,
				amount,
				acc(2),
				fee,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));

			// Only `amount` left the pool; `fee` stays as backing for pending fees.
			assert_eq!(tracked(asset_id), fee);
			assert_eq!(pool_physical(), fee);
			assert_eq!(tracked(asset_id), pool_physical());
			assert_eq!(crate::mock::mock_pending_fees_get(acc(1), asset_id), fee);
		});
	}

	/// T6 — the guard requires `>= amount + fee`: a pool covering only `amount`
	/// (fee unbacked) must be rejected; covering `amount + fee` must succeed.
	#[test]
	fn unshield_guard_requires_amount_plus_fee() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let (amount, fee) = (500u128, 50u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// Pool covers only `amount` → rejected.
			fund_pool(asset_id, amount);
			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(0x22),
					asset_id,
					amount,
					acc(2),
					fee,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::InsufficientPoolBalance
			);

			// Pool covers `amount + fee` → accepted.
			fund_pool(asset_id, amount + fee);
			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x23),
				asset_id,
				amount,
				acc(2),
				fee,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));
		});
	}

	/// T1 + T4 — full fee lifecycle keeps ledger == physical at every step:
	/// shield → unshield(with fee) → claim(mint fee note) → unshield(fee note).
	#[test]
	fn fee_lifecycle_preserves_ledger_invariant() {
		use crate::operations::{fees::FeeOperation, shield::ShieldOperation};

		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let memo = FrameEncryptedMemo::default();
			let depositor = acc(7);
			// Fund above the shield amount so KeepAlive leaves the ED intact.
			let _ = <pallet_balances::Pallet<Test> as Currency<AccountId32>>::deposit_creating(
				&depositor, 2000,
			);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// Step 1: shield 1000. Ledger and physical both +1000.
			assert_ok!(ShieldOperation::execute::<Test>(
				depositor,
				asset_id,
				1000u128,
				Commitment::new([0x31u8; 32]),
				FrameEncryptedMemo::from_bytes(&[0u8; 176]).unwrap(),
			));
			assert_eq!(tracked(asset_id), pool_physical());
			assert_eq!(tracked(asset_id), 1000);

			// Step 2: unshield amount=700 fee=50. Only `amount` leaves; fee stays.
			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x32),
				asset_id,
				700u128,
				acc(2),
				50u128,
				[0u8; 32],
				memo.clone(),
				None,
			));
			assert_eq!(tracked(asset_id), 300);
			assert_eq!(tracked(asset_id), pool_physical());
			assert_eq!(crate::mock::mock_pending_fees_get(acc(1), asset_id), 50);

			// Step 3: claim the 50 fee as a note. Ledger unchanged (same backing).
			let fee_note = Commitment::new([0x33u8; 32]);
			let mut signals = vec![0u8; 76];
			signals[..32].copy_from_slice(&fee_note.0);
			signals[32..40].copy_from_slice(&(50u64).to_le_bytes());
			signals[40..44].copy_from_slice(&asset_id.to_le_bytes());
			assert_ok!(FeeOperation::claim_shielded::<Test>(
				acc(1),
				fee_note,
				50u128,
				asset_id,
				crate::types::EncryptedMemo::from_bytes(&[0u8; 176]).unwrap(),
				vec![0x01u8; 128],
				signals,
			));
			assert_eq!(tracked(asset_id), 300);
			assert_eq!(tracked(asset_id), pool_physical());
			assert_eq!(crate::mock::mock_pending_fees_get(acc(1), asset_id), 0);

			// Step 4: unshield the 50 fee note (fee=0). Ledger and physical both −50.
			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x34),
				asset_id,
				50u128,
				acc(2),
				0u128,
				[0u8; 32],
				memo,
				None,
			));
			assert_eq!(tracked(asset_id), 250);
			assert_eq!(tracked(asset_id), pool_physical());
		});
	}

	// ── relay-fee attribution ────────────────────────────────────────────────
	// The `relayer` field steers the fee. resolve_relayer only maps
	// governance-registered addresses; an unregistered address falls back to the
	// block author, so an unregistered attacker can never credit themselves.

	fn block_author() -> sp_runtime::AccountId32 {
		acc(1)
	}

	fn evm(byte: u8) -> sp_core::H160 {
		sp_core::H160::from([byte; 20])
	}

	/// A registered relayer receives the fee it relayed.
	#[test]
	fn unshield_fee_lands_at_registered_relayer() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let (amount, fee) = (500u128, 50u128);
			fund_pool(asset_id, amount + fee);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let relayer_acct = acc(7);
			crate::mock::mock_register_relayer(relayer_acct.clone(), evm(0xAA));

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x51),
				asset_id,
				amount,
				acc(2),
				fee,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				Some(evm(0xAA)),
			));

			assert_eq!(
				crate::mock::mock_pending_fees_get(relayer_acct, asset_id),
				fee
			);
			assert_eq!(
				crate::mock::mock_pending_fees_get(block_author(), asset_id),
				0
			);
		});
	}

	/// An unregistered `relayer` address cannot credit itself — the fee falls back
	/// to the block author (griefing at worst, never theft).
	#[test]
	fn unshield_unregistered_relayer_falls_back_to_block_author() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let (amount, fee) = (500u128, 50u128);
			fund_pool(asset_id, amount + fee);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			// 0xBB is never registered → resolve_relayer returns None.
			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x52),
				asset_id,
				amount,
				acc(2),
				fee,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				Some(evm(0xBB)),
			));

			assert_eq!(
				crate::mock::mock_pending_fees_get(block_author(), asset_id),
				fee
			);
		});
	}

	/// `relayer = None` routes the fee to the block author.
	#[test]
	fn unshield_none_relayer_goes_to_block_author() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let (amount, fee) = (500u128, 50u128);
			fund_pool(asset_id, amount + fee);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x53),
				asset_id,
				amount,
				acc(2),
				fee,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));

			assert_eq!(
				crate::mock::mock_pending_fees_get(block_author(), asset_id),
				fee
			);
		});
	}

	/// A non-zero fee with no resolvable recipient (no relayer, no block author)
	/// errors instead of stranding the fee tokens in the pool.
	#[test]
	fn unshield_nonzero_fee_without_recipient_errors() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let (amount, fee) = (500u128, 50u128);
			fund_pool(asset_id, amount + fee);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			crate::mock::mock_clear_block_author();

			// assert_err (not assert_noop): the fee attribution runs after currency
			// effects; in a real extrinsic the dispatch rolls those back on Err. Here
			// we assert the error itself — the transactional rollback is Substrate's.
			assert_err!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(0x60),
					asset_id,
					amount,
					acc(2),
					fee,
					[0u8; 32],
					FrameEncryptedMemo::default(),
					None,
				),
				crate::pallet::Error::<Test>::FeeRecipientUnavailable
			);
		});
	}

	/// A zero fee with no recipient is fine — nothing to attribute.
	#[test]
	fn unshield_zero_fee_without_recipient_ok() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let amount = 500u128;
			fund_pool(asset_id, amount);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			crate::mock::mock_clear_block_author();

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x61),
				asset_id,
				amount,
				acc(2),
				0u128,
				[0u8; 32],
				FrameEncryptedMemo::default(),
				None,
			));
		});
	}
}
