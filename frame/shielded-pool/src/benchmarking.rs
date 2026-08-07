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
use frame_system::RawOrigin;
use sp_runtime::traits::{AccountIdConversion, SaturatedConversion};

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec;

#[benchmarks(
	where T: pallet_zk_verifier::Config + pallet_relayer::Config
)]
mod benchmarks {
	use super::*;
	use crate::FrameEncryptedMemo;
	use crate::pallet::{Assets, NextAssetId, PoolBalancePerAsset};
	use pallet_relayer::RelayerInterface;
	use sp_core::H160;
	use sp_std::vec::Vec;

	fn setup_relayer<T: Config + pallet_relayer::Config>() -> H160 {
		let addr = H160::from([0xAA; 20]);
		let relayer: T::AccountId = account("relayer", 0, 0);
		pallet_relayer::RelayerRegistry::<T>::insert(addr, relayer);
		addr
	}

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
		let amount: BalanceOf<T> = 1_000_000u32.into();
		let _ = <T::Currency as Currency<T::AccountId>>::make_free_balance_be(&caller, amount);

		(caller, asset_id)
	}

	#[benchmark]
	fn shield() {
		let (caller, asset_id) = setup_benchmark_env::<T>();
		let amount: BalanceOf<T> = 10_000u32.into();
		let commitment = Commitment([1u8; 32]);
		// Memo must be exactly 180 bytes (MAX_ENCRYPTED_MEMO_SIZE): nonce(12) + data(120) + MAC(16) + ephPk(32)
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
		let amount: BalanceOf<T> = 10_000u32.into();

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
	fn private_transfer(n: Linear<1, 2>) {
		let (_caller, _) = setup_benchmark_env::<T>();
		let merkle_root = [1u8; 32];

		// Setup valid root in storage
		crate::storage::MerkleRepository::add_historic_poseidon_root::<T>(merkle_root);

		let proof: BoundedVec<u8, ConstU32<512>> = vec![0u8; 128].try_into().unwrap();

		// n inputs/outputs: the leaf-insertion loop runs n times (worst case n=2).
		let mut nulls = Vec::new();
		let mut comms = Vec::new();
		let mut memos = Vec::new();
		for i in 0..n {
			nulls.push(Nullifier([(0x20 + i) as u8; 32]));
			comms.push(Commitment([(0x30 + i) as u8; 32]));
			let memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
			memos.push(FrameEncryptedMemo(memo_bytes.try_into().unwrap()));
		}
		let nullifiers: BoundedVec<Nullifier, ConstU32<2>> = nulls.try_into().unwrap();
		let commitments: BoundedVec<Commitment, ConstU32<2>> = comms.try_into().unwrap();
		let encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>> =
			memos.try_into().unwrap();

		let asset_id = 0u32;
		// Must be >= T::Relayer::min_relay_fee() to pass the FeeTooLow check.
		let fee: BalanceOf<T> = T::Relayer::min_relay_fee().saturated_into();
		let relayer = setup_relayer::<T>();

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
			Some(relayer),
			1u32,
		);
	}

	#[benchmark]
	fn unshield() {
		let (_caller, asset_id) = setup_benchmark_env::<T>();
		let recipient: T::AccountId = account("recipient", 0, 0);
		let merkle_root = [1u8; 32];
		let amount: BalanceOf<T> = 10_000u32.into();

		// Setup valid state: root and pool balance
		crate::storage::MerkleRepository::add_historic_poseidon_root::<T>(merkle_root);
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
		let relayer = setup_relayer::<T>();

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
			Some(relayer),      // relayer resolves the fee recipient
			1u32,               // circuit_version
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

	#[benchmark]
	fn claim_shielded_fees() {
		let (caller, asset_id) = setup_benchmark_env::<T>();
		let amount: BalanceOf<T> = 10_000u32.into();
		let amount_u128: u128 = amount.saturated_into();

		// Accumulate relay fees for the validator.
		T::Relayer::accumulate_relay_fee(&caller, asset_id, amount_u128);

		let commitment = Commitment([0x11u8; 32]);

		// public_signals layout (76 bytes): commitment(32) | value_le(8) | asset_id_le(4) | owner_hash(32)
		let mut public_signals = vec![0u8; 76];
		public_signals[..32].copy_from_slice(&commitment.0);
		public_signals[32..40].copy_from_slice(&(amount_u128 as u64).to_le_bytes());
		public_signals[40..44].copy_from_slice(&asset_id.to_le_bytes());

		let proof = vec![0x01u8; 128];
		let memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let memo = FrameEncryptedMemo(memo_bytes.try_into().unwrap());

		#[extrinsic_call]
		claim_shielded_fees(
			RawOrigin::Signed(caller),
			commitment,
			amount,
			asset_id,
			memo,
			proof.try_into().expect("proof fits bound"),
			public_signals.try_into().expect("signals fit bound"),
			1u32,
		);
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test,);
}
