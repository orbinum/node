//! Benchmarks for pallet-shielded-pool
//!
//! These benchmarks measure the execution time of extrinsics.

use super::*;
use frame_benchmarking::v2::*;
use frame_support::{
	BoundedVec,
	pallet_prelude::ConstU32,
	traits::{Currency, Get},
};
use sp_runtime::traits::{AccountIdConversion, SaturatedConversion};
use frame_system::RawOrigin;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec;

#[benchmarks(
	where T: pallet_zk_verifier::Config
)]
mod benchmarks {
	use super::*;
	use crate::FrameEncryptedMemo;
	use crate::pallet::{Assets, HistoricPoseidonRoots, NextAssetId, PoolBalancePerAsset};
	use pallet_relayer::RelayerInterface;
	use sp_std::vec::Vec;

	fn setup_benchmark_env<T: Config>() -> (T::AccountId, u32) {
		let caller: T::AccountId = whitelisted_caller();
		let asset_id = 0u32;

		// 1. Register and verify asset 0
		if Assets::<T>::get(asset_id).is_none() {
			let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
			let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
			let metadata = crate::AssetMetadata {
				id: asset_id,
				name,
				symbol,
				decimals: 18,
				is_verified: true,
				contract_address: None,
				created_at: frame_system::Pallet::<T>::block_number(),
				creator: T::PalletId::get().into_account_truncating(),
			};
			Assets::<T>::insert(asset_id, metadata);
			NextAssetId::<T>::put(asset_id + 1);
		}

		// 2. Fund caller
		let amount: BalanceOf<T> = T::MinShieldAmount::get() * 1000u32.into();
		let _ = <T::Currency as Currency<T::AccountId>>::make_free_balance_be(&caller, amount);

		(caller, asset_id)
	}

	#[benchmark]
	fn shield() {
		let (caller, asset_id) = setup_benchmark_env::<T>();
		let amount: BalanceOf<T> = T::MinShieldAmount::get() * 10u32.into();
		let commitment = Commitment([1u8; 32]);
		// Memo must be exactly 168 bytes (MAX_ENCRYPTED_MEMO_SIZE): nonce(12) + data(108) + MAC(16) + ephPk(32)
		let memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let encrypted_memo = FrameEncryptedMemo(memo_bytes.try_into().unwrap());

		#[extrinsic_call]
		shield(
			RawOrigin::Signed(caller),
			asset_id,
			amount,
			commitment,
			encrypted_memo,
		);
	}

	#[benchmark]
	fn shield_batch(n: Linear<1, 20>) {
		let (caller, asset_id) = setup_benchmark_env::<T>();
		let amount: BalanceOf<T> = T::MinShieldAmount::get() * 10u32.into();

		let mut operations = Vec::new();
		for i in 0..n {
			let commitment = Commitment([i as u8; 32]);
			let memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
			let encrypted_memo = FrameEncryptedMemo(memo_bytes.try_into().unwrap());
			operations.push((asset_id, amount, commitment, encrypted_memo));
		}
		let operations_vec: BoundedVec<_, ConstU32<20>> = operations.try_into().unwrap();

		#[extrinsic_call]
		shield_batch(RawOrigin::Signed(caller), operations_vec);
	}

	#[benchmark]
	fn private_transfer() {
		let (_caller, _) = setup_benchmark_env::<T>();
		let merkle_root = [1u8; 32];

		// Setup valid root in storage
		HistoricPoseidonRoots::<T>::insert(merkle_root, true);

		let proof: BoundedVec<u8, ConstU32<512>> = vec![0u8; 128].try_into().unwrap();
		let nullifiers: BoundedVec<Nullifier, ConstU32<2>> =
			vec![Nullifier([2u8; 32])].try_into().unwrap();
		let commitments: BoundedVec<Commitment, ConstU32<2>> =
			vec![Commitment([3u8; 32])].try_into().unwrap();
		let memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>> =
			vec![FrameEncryptedMemo(memo_bytes.try_into().unwrap())]
				.try_into()
				.unwrap();

		let asset_id = 0u32;
		// Must be >= T::Relayer::min_relay_fee() to pass the FeeTooLow check.
		let fee: BalanceOf<T> = T::Relayer::min_relay_fee().saturated_into();

		#[extrinsic_call]
		private_transfer(
			RawOrigin::None,
			proof,
			merkle_root,
			nullifiers,
			commitments,
			encrypted_memos,
			asset_id,
			fee,
			None,
		);
	}

	#[benchmark]
	fn unshield() {
		let (_caller, asset_id) = setup_benchmark_env::<T>();
		let recipient: T::AccountId = account("recipient", 0, 0);
		let merkle_root = [1u8; 32];
		let amount: BalanceOf<T> = T::MinShieldAmount::get() * 10u32.into();

		// Setup valid state: root and pool balance
		HistoricPoseidonRoots::<T>::insert(merkle_root, true);
		PoolBalancePerAsset::<T>::insert(asset_id, amount * 2u32.into());
		// Fund pool account too for actual transfer
		let _ = <T::Currency as Currency<T::AccountId>>::make_free_balance_be(
			&Pallet::<T>::pool_account_id(),
			amount * 100u32.into(),
		);

		let proof: BoundedVec<u8, ConstU32<512>> = vec![0u8; 128].try_into().unwrap();
		let nullifier = Nullifier([4u8; 32]);

		// Must be >= T::Relayer::min_relay_fee() to pass the FeeTooLow check.
		let fee: BalanceOf<T> = T::Relayer::min_relay_fee().saturated_into();

		#[extrinsic_call]
		unshield(
			RawOrigin::None,
			proof,
			merkle_root,
			nullifier,
			asset_id,
			amount,
			recipient,
			fee,
			Hash::default(),    // change_commitment: [0u8; 32] for total unshield
			Default::default(), // change_encrypted_memo: empty for total unshield
			None,               // relayer
		);
	}

	#[benchmark]
	fn register_asset() {
		let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
		let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
		#[extrinsic_call]
		register_asset(RawOrigin::Root, name, symbol, 18, None);
	}

	#[benchmark]
	fn verify_asset() {
		let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
		let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
		let asset_id =
			crate::operations::assets::AssetOperation::register::<T>(name, symbol, 18, None)
				.unwrap();

		#[extrinsic_call]
		verify_asset(RawOrigin::Root, asset_id);
	}

	#[benchmark]
	fn unverify_asset() {
		let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
		let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
		let asset_id =
			crate::operations::assets::AssetOperation::register::<T>(name, symbol, 18, None)
				.unwrap();
		let _ = crate::operations::assets::AssetOperation::verify::<T>(asset_id);

		#[extrinsic_call]
		unverify_asset(RawOrigin::Root, asset_id);
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test,);
}
