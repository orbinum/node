use crate::{
	pallet::{Config, Error, Event, Pallet},
	storage::AssetRepository,
	types::AssetMetadata,
};
use frame_support::{BoundedVec, ensure, pallet_prelude::*};
use frame_system::pallet_prelude::BlockNumberFor;
use sp_runtime::traits::AccountIdConversion;

pub struct AssetOperation;

impl AssetOperation {
	pub fn register<T: Config>(
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		contract_address: Option<[u8; 20]>,
	) -> Result<u32, DispatchError> {
		let creator = T::PalletId::get().into_account_truncating();
		Self::register_asset::<T>(name, symbol, decimals, contract_address, creator)
	}

	pub fn register_asset<T: Config>(
		name: BoundedVec<u8, ConstU32<64>>,
		symbol: BoundedVec<u8, ConstU32<16>>,
		decimals: u8,
		contract_address: Option<[u8; 20]>,
		creator: T::AccountId,
	) -> Result<u32, DispatchError> {
		Self::validate_metadata::<T>(&name, &symbol, decimals)?;

		let asset_id = AssetRepository::increment_asset_id::<T>();
		let current_block = frame_system::Pallet::<T>::block_number();

		let metadata = AssetMetadata {
			id: asset_id,
			name,
			symbol,
			decimals,
			is_verified: false,
			contract_address,
			created_at: current_block,
			creator,
		};

		AssetRepository::store_asset::<T>(asset_id, metadata);
		Pallet::<T>::deposit_event(Event::AssetRegistered { asset_id });
		Ok(asset_id)
	}

	pub fn verify<T: Config>(asset_id: u32) -> DispatchResult {
		Self::verify_asset::<T>(asset_id)
	}

	pub fn verify_asset<T: Config>(asset_id: u32) -> DispatchResult {
		ensure!(
			AssetRepository::exists::<T>(asset_id),
			Error::<T>::InvalidAssetId
		);
		ensure!(
			AssetRepository::set_verified::<T>(asset_id, true),
			Error::<T>::InvalidAssetId
		);
		Pallet::<T>::deposit_event(Event::AssetVerified { asset_id });
		Ok(())
	}

	pub fn unverify<T: Config>(asset_id: u32) -> DispatchResult {
		Self::unverify_asset::<T>(asset_id)
	}

	pub fn unverify_asset<T: Config>(asset_id: u32) -> DispatchResult {
		ensure!(
			AssetRepository::exists::<T>(asset_id),
			Error::<T>::InvalidAssetId
		);
		ensure!(
			AssetRepository::set_verified::<T>(asset_id, false),
			Error::<T>::InvalidAssetId
		);
		Pallet::<T>::deposit_event(Event::AssetUnverified { asset_id });
		Ok(())
	}

	pub fn get_asset_metadata<T: Config>(
		asset_id: u32,
	) -> Option<AssetMetadata<T::AccountId, BlockNumberFor<T>>> {
		AssetRepository::get_asset::<T>(asset_id)
	}

	pub fn ensure_asset_verified<T: Config>(asset_id: u32) -> DispatchResult {
		let metadata =
			AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(metadata.is_verified, Error::<T>::AssetNotVerified);
		Ok(())
	}

	pub fn get_next_asset_id<T: Config>() -> u32 {
		AssetRepository::get_next_asset_id::<T>()
	}

	pub fn validate_metadata<T: Config>(
		name: &BoundedVec<u8, ConstU32<64>>,
		symbol: &BoundedVec<u8, ConstU32<16>>,
		_decimals: u8,
	) -> DispatchResult {
		ensure!(!name.is_empty(), Error::<T>::InvalidAmount);
		ensure!(name.len() <= 64, Error::<T>::InvalidAmount);
		ensure!(
			!symbol.is_empty() && symbol.len() <= 16,
			Error::<T>::InvalidAmount
		);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		pallet::Event as PalletEvent,
		storage::AssetRepository,
	};
	use frame_support::{assert_noop, assert_ok};

	// ── helpers ──────────────────────────────────────────────────────────────

	fn name(s: &str) -> BoundedVec<u8, ConstU32<64>> {
		BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
	}

	fn symbol(s: &str) -> BoundedVec<u8, ConstU32<16>> {
		BoundedVec::try_from(s.as_bytes().to_vec()).unwrap()
	}

	fn register_orb() -> Result<u32, DispatchError> {
		AssetOperation::register::<Test>(name("Orbinum"), symbol("ORB"), 18, None)
	}

	// ── register ─────────────────────────────────────────────────────────────

	#[test]
	fn register_works_returns_id() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			assert_eq!(id, 1u32); // genesis sets NextAssetId = 1
		});
	}

	#[test]
	fn register_increments_id_per_call() {
		new_test_ext().execute_with(|| {
			let id0 = register_orb().unwrap();
			let id1 =
				AssetOperation::register::<Test>(name("Token2"), symbol("TK2"), 6, None).unwrap();
			assert_eq!(id0, 1);
			assert_eq!(id1, 2);
		});
	}

	#[test]
	fn register_stores_correct_metadata() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			let meta = AssetRepository::get_asset::<Test>(id).unwrap();
			assert_eq!(meta.id, id);
			assert_eq!(meta.name.as_slice(), b"Orbinum");
			assert_eq!(meta.symbol.as_slice(), b"ORB");
			assert_eq!(meta.decimals, 18);
			assert!(!meta.is_verified);
			assert_eq!(meta.contract_address, None);
		});
	}

	#[test]
	fn register_with_contract_address() {
		new_test_ext().execute_with(|| {
			let addr = Some([0xABu8; 20]);
			let id =
				AssetOperation::register::<Test>(name("Wrapped"), symbol("WRK"), 18, addr).unwrap();
			let meta = AssetRepository::get_asset::<Test>(id).unwrap();
			assert_eq!(meta.contract_address, addr);
		});
	}

	#[test]
	fn register_empty_name_fails() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				AssetOperation::register::<Test>(BoundedVec::default(), symbol("ORB"), 18, None),
				crate::pallet::Error::<Test>::InvalidAmount
			);
		});
	}

	#[test]
	fn register_empty_symbol_fails() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				AssetOperation::register::<Test>(name("Orbinum"), BoundedVec::default(), 18, None),
				crate::pallet::Error::<Test>::InvalidAmount
			);
		});
	}

	#[test]
	fn register_emits_event() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(
						PalletEvent::AssetRegistered { asset_id }
					) if asset_id == id
				)
			});
			assert!(found, "AssetRegistered event not emitted");
		});
	}

	// ── verify ────────────────────────────────────────────────────────────────

	#[test]
	fn verify_works() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			assert_ok!(AssetOperation::verify::<Test>(id));

			let meta = AssetRepository::get_asset::<Test>(id).unwrap();
			assert!(meta.is_verified);
		});
	}

	#[test]
	fn verify_not_found_fails() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				AssetOperation::verify::<Test>(99u32),
				crate::pallet::Error::<Test>::InvalidAssetId
			);
		});
	}

	#[test]
	fn verify_emits_event() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			assert_ok!(AssetOperation::verify::<Test>(id));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(
						PalletEvent::AssetVerified { asset_id }
					) if asset_id == id
				)
			});
			assert!(found, "AssetVerified event not emitted");
		});
	}

	// ── unverify ──────────────────────────────────────────────────────────────

	#[test]
	fn unverify_works() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			AssetOperation::verify::<Test>(id).unwrap();
			assert_ok!(AssetOperation::unverify::<Test>(id));

			let meta = AssetRepository::get_asset::<Test>(id).unwrap();
			assert!(!meta.is_verified);
		});
	}

	#[test]
	fn unverify_not_found_fails() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				AssetOperation::unverify::<Test>(99u32),
				crate::pallet::Error::<Test>::InvalidAssetId
			);
		});
	}

	#[test]
	fn unverify_emits_event() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			AssetOperation::verify::<Test>(id).unwrap();
			assert_ok!(AssetOperation::unverify::<Test>(id));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(
						PalletEvent::AssetUnverified { asset_id }
					) if asset_id == id
				)
			});
			assert!(found, "AssetUnverified event not emitted");
		});
	}

	// ── ensure_asset_verified ─────────────────────────────────────────────────

	#[test]
	fn ensure_asset_verified_ok_when_verified() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			AssetOperation::verify::<Test>(id).unwrap();
			assert_ok!(AssetOperation::ensure_asset_verified::<Test>(id));
		});
	}

	#[test]
	fn ensure_asset_verified_fails_when_unverified() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			// Registered but not verified
			assert_noop!(
				AssetOperation::ensure_asset_verified::<Test>(id),
				crate::pallet::Error::<Test>::AssetNotVerified
			);
		});
	}

	#[test]
	fn ensure_asset_verified_fails_when_not_found() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				AssetOperation::ensure_asset_verified::<Test>(99u32),
				crate::pallet::Error::<Test>::InvalidAssetId
			);
		});
	}

	// ── get_next_asset_id ─────────────────────────────────────────────────────

	#[test]
	fn get_next_asset_id_starts_at_zero() {
		new_test_ext().execute_with(|| {
			assert_eq!(AssetOperation::get_next_asset_id::<Test>(), 1u32); // genesis = 1
		});
	}

	#[test]
	fn get_next_asset_id_increments_after_register() {
		new_test_ext().execute_with(|| {
			register_orb().unwrap();
			assert_eq!(AssetOperation::get_next_asset_id::<Test>(), 2u32); // after first register
		});
	}

	// ── get_asset_metadata ────────────────────────────────────────────────────

	#[test]
	fn get_asset_metadata_returns_some_when_exists() {
		new_test_ext().execute_with(|| {
			let id = register_orb().unwrap();
			assert!(AssetOperation::get_asset_metadata::<Test>(id).is_some());
		});
	}

	#[test]
	fn get_asset_metadata_returns_none_when_missing() {
		new_test_ext().execute_with(|| {
			assert!(AssetOperation::get_asset_metadata::<Test>(42u32).is_none());
		});
	}
}
