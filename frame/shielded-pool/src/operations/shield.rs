use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};

use crate::{
	merkle::MerkleTreeService,
	pallet::{Config, Error, Event, Pallet},
	storage::{AssetRepository, CommitmentRepository, PoolBalanceRepository},
	types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
};

pub struct ShieldOperation;

impl ShieldOperation {
	pub fn execute<T: Config>(
		depositor: <T as frame_system::Config>::AccountId,
		asset_id: u32,
		amount: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		commitment: Commitment,
		encrypted_memo: EncryptedMemo,
	) -> DispatchResult {
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);
		ensure!(
			amount >= T::MinShieldAmount::get(),
			Error::<T>::AmountTooSmall
		);
		ensure!(
			encrypted_memo.0.len() == MAX_ENCRYPTED_MEMO_SIZE as usize,
			Error::<T>::InvalidMemoSize
		);

		ensure!(
			!CommitmentRepository::exists::<T>(&commitment),
			Error::<T>::CommitmentAlreadyExists
		);

		T::Currency::transfer(
			&depositor,
			&Pallet::<T>::pool_account_id(),
			amount,
			ExistenceRequirement::KeepAlive,
		)?;

		let leaf_index = MerkleTreeService::insert_leaf::<T>(commitment)?;
		CommitmentRepository::store_memo::<T>(commitment, encrypted_memo.clone());
		PoolBalanceRepository::increase_balance::<T>(asset_id, amount);

		Pallet::<T>::deposit_event(Event::Shielded {
			depositor,
			amount,
			commitment,
			encrypted_memo,
			leaf_index,
		});

		Ok(())
	}

	pub fn commitment_exists<T: Config>(commitment: &Commitment) -> bool {
		CommitmentRepository::exists::<T>(commitment)
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
		storage::{CommitmentRepository, PoolBalanceRepository},
		types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
	};
	use frame_support::{assert_noop, assert_ok};
	use sp_runtime::AccountId32;

	// ── helpers ──────────────────────────────────────────────────────────────

	/// Register and verify an asset, returning its ID.
	fn setup_asset() -> u32 {
		let name = frame_support::BoundedVec::try_from(b"Orbinum".to_vec()).unwrap();
		let symbol = frame_support::BoundedVec::try_from(b"ORB".to_vec()).unwrap();
		let id = AssetOperation::register_asset::<Test>(name, symbol, 18, None, acc(1)).unwrap();
		AssetOperation::verify::<Test>(id).unwrap();
		id
	}

	fn memo_valid() -> EncryptedMemo {
		EncryptedMemo::new(vec![0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap()
	}

	fn memo_short() -> EncryptedMemo {
		EncryptedMemo::new(vec![0x01u8; 32]).unwrap()
	}

	fn commitment(seed: u8) -> Commitment {
		Commitment::new([seed; 32])
	}

	// ── execute ───────────────────────────────────────────────────────────────

	#[test]
	fn execute_works() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let c = commitment(0x01);

			assert_ok!(ShieldOperation::execute::<Test>(
				acc(1),
				asset_id,
				500u128,
				c,
				memo_valid(),
			));
		});
	}

	#[test]
	fn execute_invalid_asset_fails() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				ShieldOperation::execute::<Test>(
					acc(1),
					99u32,
					500u128,
					commitment(1),
					memo_valid()
				),
				crate::pallet::Error::<Test>::InvalidAssetId
			);
		});
	}

	#[test]
	fn execute_asset_not_verified_fails() {
		new_test_ext().execute_with(|| {
			let name = frame_support::BoundedVec::try_from(b"Orbinum".to_vec()).unwrap();
			let symbol = frame_support::BoundedVec::try_from(b"ORB".to_vec()).unwrap();
			let id =
				AssetOperation::register_asset::<Test>(name, symbol, 18, None, acc(1)).unwrap();
			// Not verified

			assert_noop!(
				ShieldOperation::execute::<Test>(acc(1), id, 500u128, commitment(1), memo_valid()),
				crate::pallet::Error::<Test>::AssetNotVerified
			);
		});
	}

	#[test]
	fn execute_amount_too_small_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			// MinShieldAmount = 100; amount = 50 < 100
			assert_noop!(
				ShieldOperation::execute::<Test>(
					acc(1),
					asset_id,
					50u128,
					commitment(1),
					memo_valid()
				),
				crate::pallet::Error::<Test>::AmountTooSmall
			);
		});
	}

	#[test]
	fn execute_invalid_memo_size_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			assert_noop!(
				ShieldOperation::execute::<Test>(
					acc(1),
					asset_id,
					500u128,
					commitment(1),
					memo_short()
				),
				crate::pallet::Error::<Test>::InvalidMemoSize
			);
		});
	}

	#[test]
	fn execute_increases_pool_balance() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let before = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
			assert_ok!(ShieldOperation::execute::<Test>(
				acc(1),
				asset_id,
				500u128,
				commitment(0x02),
				memo_valid(),
			));
			let after = PoolBalanceRepository::get_asset_balance::<Test>(asset_id);
			assert_eq!(after - before, 500u128);
		});
	}

	#[test]
	fn execute_stores_commitment_memo() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let c = commitment(0x03);
			assert_ok!(ShieldOperation::execute::<Test>(
				acc(1),
				asset_id,
				200u128,
				c,
				memo_valid(),
			));
			assert!(CommitmentRepository::exists::<Test>(&c));
		});
	}

	#[test]
	fn execute_emits_shielded_event() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let c = commitment(0x04);
			assert_ok!(ShieldOperation::execute::<Test>(
				acc(1),
				asset_id,
				300u128,
				c,
				memo_valid(),
			));
			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Shielded {
						depositor: ref ed,
						amount: 300,
						commitment: ec,
						..
					}) if ec == c && *ed == acc(1)
				)
			});
			assert!(found, "Shielded event not emitted");
		});
	}

	#[test]
	fn execute_transfers_currency_to_pool() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let sender = acc(1);
			let pool = crate::Pallet::<Test>::pool_account_id();
			let balance_before =
				<pallet_balances::Pallet<Test> as frame_support::traits::Currency<AccountId32>>::free_balance(&sender);

			assert_ok!(ShieldOperation::execute::<Test>(
				sender.clone(),
				asset_id,
				1_000u128,
				commitment(0x05),
				memo_valid(),
			));

			let balance_after =
				<pallet_balances::Pallet<Test> as frame_support::traits::Currency<AccountId32>>::free_balance(&sender);
			let pool_balance = <pallet_balances::Pallet<Test> as frame_support::traits::Currency<
				AccountId32,
			>>::free_balance(&pool);

			assert_eq!(balance_before - balance_after, 1_000u128);
			assert_eq!(pool_balance, 1_000u128);
		});
	}

	// ── query helpers ─────────────────────────────────────────────────────────

	#[test]
	fn commitment_exists_false_before_shield() {
		new_test_ext().execute_with(|| {
			assert!(!ShieldOperation::commitment_exists::<Test>(&commitment(
				0xAA
			)));
		});
	}

	#[test]
	fn commitment_exists_true_after_shield() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let c = commitment(0xBB);
			assert_ok!(ShieldOperation::execute::<Test>(
				acc(1),
				asset_id,
				200u128,
				c,
				memo_valid(),
			));
			assert!(ShieldOperation::commitment_exists::<Test>(&c));
		});
	}

	#[test]
	fn asset_exists_returns_correct_values() {
		new_test_ext().execute_with(|| {
			let id = setup_asset();
			assert!(ShieldOperation::asset_exists::<Test>(id));
			assert!(!ShieldOperation::asset_exists::<Test>(99u32));
		});
	}

	#[test]
	fn is_asset_verified_returns_correct_values() {
		new_test_ext().execute_with(|| {
			let id = setup_asset();
			assert!(ShieldOperation::is_asset_verified::<Test>(id));
			// Unverified asset
			let name = frame_support::BoundedVec::try_from(b"Other".to_vec()).unwrap();
			let sym = frame_support::BoundedVec::try_from(b"OTH".to_vec()).unwrap();
			let id2 = AssetOperation::register_asset::<Test>(name, sym, 6, None, acc(2)).unwrap();
			assert!(!ShieldOperation::is_asset_verified::<Test>(id2));
		});
	}

	#[test]
	fn execute_duplicate_commitment_fails() {
		// A second shield call with the same commitment bytes must be rejected to prevent
		// Merkle-tree spam: an attacker could flood the tree with duplicate leaves,
		// consuming tree capacity while the associated notes remain unspendable (a single
		// nullifier can only be used once).
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let c = commitment(0xDE);

			assert_ok!(ShieldOperation::execute::<Test>(
				acc(1),
				asset_id,
				500u128,
				c,
				memo_valid(),
			));

			assert_noop!(
				ShieldOperation::execute::<Test>(acc(1), asset_id, 500u128, c, memo_valid()),
				crate::pallet::Error::<Test>::CommitmentAlreadyExists
			);
		});
	}
}
