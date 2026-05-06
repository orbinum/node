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
use sp_runtime::traits::AccountIdConversion;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec;

#[benchmarks(
	where T: pallet_zk_verifier::Config
)]
mod benchmarks {
	use super::*;
	use crate::pallet::{
		Assets, CommitmentMemos, DisclosureRecords, DisclosureRequests, HistoricPoseidonRoots,
		NextAssetId, PoolBalancePerAsset,
	};
	use crate::{Auditor, DisclosureCondition};
	use crate::{DisclosureRequest, FrameEncryptedMemo};
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
		let fee: BalanceOf<T> = 0u32.into();

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

		let fee: BalanceOf<T> = 0u32.into();

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
			Hash::default(), // change_commitment: [0u8; 32] for total unshield
			None,            // relayer
		);
	}

	#[benchmark]
	fn set_audit_policy() {
		let caller: T::AccountId = whitelisted_caller();
		let auditor: T::AccountId = account("auditor", 0, 0);
		let auditors = vec![Auditor::Account(auditor)].try_into().unwrap();
		let conditions = vec![DisclosureCondition::AmountThreshold {
			min_amount: 1000u32.into(),
		}]
		.try_into()
		.unwrap();

		#[extrinsic_call]
		set_audit_policy(
			RawOrigin::Signed(caller),
			auditors,
			conditions,
			Some(100u32.into()),
			None,
		);
	}

	#[benchmark]
	fn request_disclosure() {
		let target: T::AccountId = account("target", 0, 0);
		let auditor: T::AccountId = whitelisted_caller();
		let reason = vec![1u8; 100].try_into().unwrap();

		// Setup: Create audit policy for the auditor
		let auditors = vec![Auditor::Account(auditor.clone())].try_into().unwrap();
		let conditions = vec![DisclosureCondition::AmountThreshold {
			min_amount: 1000u32.into(),
		}]
		.try_into()
		.unwrap();
		let _ = Pallet::<T>::set_audit_policy(
			RawOrigin::Signed(target.clone()).into(),
			auditors,
			conditions,
			Some(100u32.into()),
			None,
		);

		#[extrinsic_call]
		request_disclosure(RawOrigin::Signed(auditor), target, reason);
	}

	#[benchmark]
	fn disclose() {
		let target: T::AccountId = whitelisted_caller();
		let auditor: T::AccountId = account("auditor", 0, 0);
		let commitment = Commitment([42u8; 32]);

		// Insert commitment memo (required by CommitmentNotFound check)
		let memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		CommitmentMemos::<T>::insert(
			commitment,
			FrameEncryptedMemo(memo_bytes.try_into().unwrap()),
		);

		// Set up audit policy with Always condition (worst case: full policy validation)
		let auditors = vec![Auditor::Account(auditor.clone())].try_into().unwrap();
		let conditions = vec![DisclosureCondition::Always].try_into().unwrap();
		let _ = Pallet::<T>::set_audit_policy(
			RawOrigin::Signed(target.clone()).into(),
			auditors,
			conditions,
			Some(100u32.into()),
			None,
		);

		// Insert a non-expired DisclosureRequest
		DisclosureRequests::<T>::insert(
			&target,
			&auditor,
			DisclosureRequest {
				target: target.clone(),
				auditor: auditor.clone(),
				reason: vec![1u8; 32].try_into().unwrap(),
				requested_at: 0u32.into(),
				expires_at: frame_system::Pallet::<T>::block_number() + T::RequestExpiration::get(),
			},
		);

		// Groth16 BN254 compressed proof = 128 bytes
		let proof_bytes: BoundedVec<u8, ConstU32<256>> = vec![1u8; 128].try_into().unwrap();
		// public_signals (76 bytes): commitment(32) + revealed_value(8) +
		//   revealed_asset_id(4) + revealed_owner_hash(32)
		let mut signals = vec![0u8; 76];
		signals[0..32].copy_from_slice(&commitment.0);
		let public_signals: BoundedVec<u8, ConstU32<76>> = signals.try_into().unwrap();

		#[extrinsic_call]
		disclose(
			RawOrigin::Signed(target),
			commitment,
			proof_bytes,
			public_signals,
			Some(auditor),
		);
	}

	#[benchmark]
	fn reject_disclosure() {
		let target: T::AccountId = whitelisted_caller();
		let auditor: T::AccountId = account("auditor", 0, 0);
		let reason = vec![1u8; 100].try_into().unwrap();

		// Setup request in storage
		crate::pallet::DisclosureRequests::<T>::insert(
			&target,
			&auditor,
			DisclosureRequest {
				target: target.clone(),
				auditor: auditor.clone(),
				reason: vec![1u8; 32].try_into().unwrap(),
				requested_at: frame_system::Pallet::<T>::block_number(),
				expires_at: frame_system::Pallet::<T>::block_number() + T::RequestExpiration::get(),
			},
		);

		#[extrinsic_call]
		reject_disclosure(RawOrigin::Signed(target), auditor, reason);
	}

	#[benchmark]
	fn batch_submit_disclosure_proofs(n: Linear<1, 10>) {
		let caller: T::AccountId = whitelisted_caller();

		// No AuditPolicy → auditor must be None (self-disclosure path)
		let mut submissions = Vec::new();
		for i in 0..n {
			// Use i+1 so commitment bytes are never all-zero
			let commitment = Commitment([i as u8 + 1; 32]);

			// Insert commitment memo (required by CommitmentNotFound check)
			CommitmentMemos::<T>::insert(
				commitment,
				FrameEncryptedMemo(
					vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize]
						.try_into()
						.unwrap(),
				),
			);

			// public_signals (76 bytes): first 32 must match commitment
			let mut signals = vec![0u8; 76];
			signals[0..32].copy_from_slice(&commitment.0);

			submissions.push(crate::BatchDisclosureSubmission {
				commitment,
				// 128-byte proof satisfies MockZkVerifier (non-empty check)
				proof: vec![1u8; 128].try_into().unwrap(),
				public_signals: signals.try_into().unwrap(),
				auditor: None,
			});
		}
		let submissions_vec: BoundedVec<_, ConstU32<10>> = submissions.try_into().unwrap();

		#[extrinsic_call]
		batch_submit_disclosure_proofs(RawOrigin::Signed(caller), submissions_vec);
	}

	#[benchmark]
	fn prune_expired_request() {
		let pruner: T::AccountId = whitelisted_caller();
		let target: T::AccountId = account("target", 0, 0);
		let auditor: T::AccountId = account("auditor", 0, 0);

		// Insert a request that is already expired (expires_at = block 1, current = 10)
		crate::pallet::DisclosureRequests::<T>::insert(
			&target,
			&auditor,
			DisclosureRequest {
				target: target.clone(),
				auditor: auditor.clone(),
				reason: vec![1u8; 32].try_into().unwrap(),
				requested_at: 0u32.into(),
				expires_at: 1u32.into(),
			},
		);
		// Advance block so current_block > expires_at
		frame_system::Pallet::<T>::set_block_number(10u32.into());

		#[extrinsic_call]
		prune_expired_request(RawOrigin::Signed(pruner), target, auditor);
	}

	#[benchmark]
	fn revoke_disclosure_record() {
		let caller: T::AccountId = whitelisted_caller();
		let commitment = Commitment([99u8; 32]);

		// Insert a self-disclosure record so the caller can revoke it
		DisclosureRecords::<T>::insert(
			commitment,
			&caller,
			crate::DisclosureRecord {
				revealed_value: None,
				revealed_asset_id: None,
				revealed_owner_hash: None,
				requester: caller.clone(),
				timestamp: frame_system::Pallet::<T>::block_number(),
			},
		);

		#[extrinsic_call]
		revoke_disclosure_record(RawOrigin::Signed(caller), commitment);
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
