use crate::{
	pallet::{Config, Error, Event, Pallet},
	storage::{AssetRepository, MerkleRepository, NullifierRepository, PoolBalanceRepository},
	types::Nullifier,
};
use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use pallet_relayer::RelayerInterface as _;
#[cfg(not(feature = "runtime-benchmarks"))]
use pallet_zk_verifier::ZkVerifierPort;
#[cfg(not(feature = "runtime-benchmarks"))]
use parity_scale_codec::Encode;
use sp_runtime::{SaturatedConversion, traits::Zero};

pub struct UnshieldOperation;

impl UnshieldOperation {
	#[allow(clippy::too_many_arguments)]
	pub fn execute<T: Config>(
		#[cfg_attr(feature = "runtime-benchmarks", allow(unused_variables))] proof: &[u8],
		merkle_root: [u8; 32],
		nullifier: Nullifier,
		asset_id: u32,
		amount: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		recipient: <T as frame_system::Config>::AccountId,
		fee: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		relayer_evm: Option<sp_core::H160>,
	) -> DispatchResult {
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);
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

		#[cfg(not(feature = "runtime-benchmarks"))]
		{
			let recipient_bytes: [u8; 32] = recipient.encode().try_into().unwrap_or([0u8; 32]);
			let valid = T::ZkVerifier::verify_unshield_proof(
				proof,
				&merkle_root,
				&nullifier.0,
				amount_u128,
				&recipient_bytes,
				asset_id,
				fee_u128,
				None,
			)?;

			ensure!(valid, Error::<T>::ProofVerificationFailed);
		}

		#[cfg(feature = "runtime-benchmarks")]
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
			let fee_recipient: Option<T::AccountId> = relayer_evm
				.and_then(|addr| T::Relayer::resolve_relayer(&addr))
				.or_else(T::Relayer::block_author);
			if let Some(recipient_account) = fee_recipient {
				T::Relayer::accumulate_relay_fee(&recipient_account, asset_id, fee_u128);
			}
		}

		PoolBalanceRepository::decrease_balance::<T>(asset_id, amount);

		let current_block = frame_system::Pallet::<T>::block_number();
		NullifierRepository::mark_as_used::<T>(nullifier, current_block);

		Pallet::<T>::deposit_event(Event::Unshielded {
			nullifier,
			amount,
			recipient,
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
		mock::{Test, new_test_ext},
		operations::assets::AssetOperation,
		pallet::Event as PalletEvent,
		storage::{MerkleRepository, NullifierRepository, PoolBalanceRepository},
		types::Nullifier,
	};
	use frame_support::{assert_noop, assert_ok, traits::Currency};

	// ── helpers ──────────────────────────────────────────────────────────────

	const KNOWN_ROOT: [u8; 32] = [0xAAu8; 32];

	fn setup_asset() -> u32 {
		let name = frame_support::BoundedVec::try_from(b"Orbinum".to_vec()).unwrap();
		let symbol = frame_support::BoundedVec::try_from(b"ORB".to_vec()).unwrap();
		let id = AssetOperation::register_asset::<Test>(name, symbol, 18, None, 1u64).unwrap();
		AssetOperation::verify::<Test>(id).unwrap();
		id
	}

	/// Fund pool account (currency + pool balance tracker).
	fn fund_pool(asset_id: u32, total: u128) {
		let pool = crate::Pallet::<Test>::pool_account_id();
		let _ = <pallet_balances::Pallet<Test> as Currency<u64>>::deposit_creating(&pool, total);
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
				2u64, // recipient
				fee,
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
					2u64,
					0u128,
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
			let id = AssetOperation::register_asset::<Test>(name, sym, 18, None, 1u64).unwrap();
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);
			fund_pool(id, 1_000u128);

			assert_noop!(
				UnshieldOperation::execute::<Test>(
					proof(),
					KNOWN_ROOT,
					nullifier(1),
					id,
					100u128,
					2u64,
					0u128,
					None,
				),
				crate::pallet::Error::<Test>::AssetNotVerified
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
					2u64,
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
					2u64,
					0u128,
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
					2u64,
					0u128,
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
				2u64,
				0u128,
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
				2u64,
				0u128,
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
			let recipient: u64 = 2;
			let amount = 300u128;
			fund_pool(asset_id, 1_000u128);
			MerkleRepository::add_historic_poseidon_root::<Test>(KNOWN_ROOT);

			let before = <pallet_balances::Pallet<Test> as Currency<u64>>::free_balance(&recipient);

			assert_ok!(UnshieldOperation::execute::<Test>(
				proof(),
				KNOWN_ROOT,
				nullifier(0x07),
				asset_id,
				amount,
				recipient,
				0u128,
				None,
			));

			let after = <pallet_balances::Pallet<Test> as Currency<u64>>::free_balance(&recipient);
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
				2u64,
				0u128,
				None,
			));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Unshielded {
						nullifier: en,
						amount: 200,
						recipient: 2,
					}) if en == n
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
				2u64,
				fee,
				None,
			));

			// MockRelayer block_author returns Some(1); fee should be accumulated there
			let pending = crate::mock::mock_pending_fees_get(1u64, asset_id);
			assert_eq!(pending, fee);
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
}
