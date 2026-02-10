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
		Assets, /* CommitmentMemos, DisclosureVerifyingKey, */ HistoricPoseidonRoots,
		NextAssetId, PoolBalancePerAsset,
	};
	use crate::{Auditor, /* BatchDisclosureSubmission, */ DisclosureCondition};
	use crate::{FrameEncryptedMemo, domain::entities::audit::DisclosureRequest};
	use sp_std::vec::Vec;

	// NOTE: Disclosure benchmarks están deshabilitados temporalmente mientras
	// se completa el desarrollo del circuito de disclosure.
	// Una vez que los artifacts de disclosure estén listos, se pueden reactivar estos benchmarks.

	// TODO: Reactivar cuando disclosure esté listo
	// const DISCLOSURE_VK_ARK: &[u8] = include_bytes!("../../../artifacts/disclosure_pk.ark");

	// /// Setup disclosure circuit VK in ZkVerifier (required for disclosure benchmarks)
	// fn setup_disclosure_circuit<T>()
	// where
	// 	T: Config + pallet_zk_verifier::Config,
	// {
	// 	use pallet_zk_verifier::{CircuitId, ProofSystem};
	//
	// 	// Register disclosure circuit VK in ZkVerifier
	// 	let circuit_id = CircuitId(3); // DISCLOSURE circuit ID
	// 	let version = 1u32;
	// 	let vk_bytes = DISCLOSURE_VK_ARK.to_vec();
	//
	// 	// Create VK info and insert directly into storage
	// 	let vk_info = pallet_zk_verifier::VerificationKeyInfo {
	// 		key_data: vk_bytes.try_into().unwrap_or_default(),
	// 		system: ProofSystem::Groth16,
	// 		registered_at: frame_system::Pallet::<T>::block_number(),
	// 	};
	//
	// 	pallet_zk_verifier::VerificationKeys::<T>::insert(circuit_id, version, vk_info);
	// 	pallet_zk_verifier::ActiveCircuitVersion::<T>::insert(circuit_id, version);
	// }

	fn setup_benchmark_env<T: Config>() -> (T::AccountId, u32) {
		let caller: T::AccountId = whitelisted_caller();
		let asset_id = 0u32;

		// 1. Register and verify asset 0
		if Assets::<T>::get(asset_id).is_none() {
			let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
			let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
			let metadata = crate::domain::entities::AssetMetadata {
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
		// Memo must be exactly 256 bytes (MAX_ENCRYPTED_MEMO_SIZE)
		let memo_bytes = vec![0u8; 256];
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
			let memo_bytes = vec![0u8; 256];
			let encrypted_memo = FrameEncryptedMemo(memo_bytes.try_into().unwrap());
			operations.push((asset_id, amount, commitment, encrypted_memo));
		}
		let operations_vec: BoundedVec<_, ConstU32<20>> = operations.try_into().unwrap();

		#[extrinsic_call]
		shield_batch(RawOrigin::Signed(caller), operations_vec);
	}

	#[benchmark]
	fn private_transfer() {
		let (caller, _) = setup_benchmark_env::<T>();
		let merkle_root = [1u8; 32];

		// Setup valid root in storage
		HistoricPoseidonRoots::<T>::insert(merkle_root, true);

		let proof: BoundedVec<u8, ConstU32<512>> = vec![0u8; 128].try_into().unwrap();
		let nullifiers: BoundedVec<Nullifier, ConstU32<2>> =
			vec![Nullifier([2u8; 32])].try_into().unwrap();
		let commitments: BoundedVec<Commitment, ConstU32<2>> =
			vec![Commitment([3u8; 32])].try_into().unwrap();
		let memo_bytes = vec![0u8; 256];
		let encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>> =
			vec![FrameEncryptedMemo(memo_bytes.try_into().unwrap())]
				.try_into()
				.unwrap();

		#[extrinsic_call]
		private_transfer(
			RawOrigin::Signed(caller),
			proof,
			merkle_root,
			nullifiers,
			commitments,
			encrypted_memos,
		);
	}

	#[benchmark]
	fn unshield() {
		let (caller, asset_id) = setup_benchmark_env::<T>();
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

		#[extrinsic_call]
		unshield(
			RawOrigin::Signed(caller),
			proof,
			merkle_root,
			nullifier,
			asset_id,
			amount,
			recipient,
		);
	}

	#[benchmark]
	fn set_disclosure_verifying_key() {
		let vk: BoundedVec<u8, ConstU32<4096>> = vec![1u8; 3000].try_into().unwrap();
		#[extrinsic_call]
		set_disclosure_verifying_key(RawOrigin::Root, vk);
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
		);

		#[extrinsic_call]
		request_disclosure(RawOrigin::Signed(auditor), target, reason, None);
	}

	// TODO: Reactivar cuando disclosure esté listo
	// #[benchmark(skip_meta)]
	// fn approve_disclosure() {
	// 	setup_disclosure_circuit::<T>();
	// 	let target: T::AccountId = whitelisted_caller();
	// 	let auditor: T::AccountId = account("auditor", 0, 0);
	// 	let commitment = Commitment([11u8; 32]);
	//
	// 	// Setup: Create audit policy with Always condition (always passes)
	// 	let auditors = vec![Auditor::Account(auditor.clone())].try_into().unwrap();
	// 	let conditions = vec![DisclosureCondition::Always].try_into().unwrap();
	// 	let _ = Pallet::<T>::set_audit_policy(
	// 		RawOrigin::Signed(target.clone()).into(),
	// 		auditors,
	// 		conditions,
	// 		None,
	// 	);
	//
	// 	// Setup request in storage
	// 	crate::pallet::DisclosureRequests::<T>::insert(
	// 		&target,
	// 		&auditor,
	// 		DisclosureRequest {
	// 			target: target.clone(),
	// 			auditor: auditor.clone(),
	// 			reason: vec![1u8; 32].try_into().unwrap(),
	// 			evidence: None,
	// 			requested_at: frame_system::Pallet::<T>::block_number(),
	// 		},
	// 	);
	//
	// 	// Setup: Register disclosure circuit VK in ZkVerifier
	// 	setup_disclosure_circuit::<T>();
	//
	// 	// Setup: Insert commitment in storage (required for validation)
	// 	let memo_bytes = vec![0u8; 256];
	// 	let encrypted_memo = FrameEncryptedMemo(memo_bytes.try_into().unwrap());
	// 	crate::pallet::CommitmentMemos::<T>::insert(commitment, encrypted_memo);
	//
	// 	// Public signals: commitment(32) + revealed_value(8) + revealed_asset_id(4) + revealed_owner_hash(32) = 76 bytes
	// 	let mut public_signals = Vec::new();
	// 	public_signals.extend_from_slice(&commitment.0); // 32 bytes
	// 	public_signals.extend_from_slice(&[1u8; 8]); // 8 bytes
	// 	public_signals.extend_from_slice(&[0u8; 4]); // 4 bytes
	// 	public_signals.extend_from_slice(&[0u8; 32]); // 32 bytes
	// 	let zk_proof = vec![0u8; 256].try_into().unwrap();
	// 	let disclosed_data = public_signals.try_into().unwrap();
	//
	// 	#[extrinsic_call]
	// 	approve_disclosure(
	// 		RawOrigin::Signed(target),
	// 		auditor,
	// 		commitment,
	// 		zk_proof,
	// 		disclosed_data,
	// 	);
	// }

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
				evidence: None,
				requested_at: frame_system::Pallet::<T>::block_number(),
			},
		);

		#[extrinsic_call]
		reject_disclosure(RawOrigin::Signed(target), auditor, reason);
	}

	// TODO: Reactivar cuando disclosure esté listo
	// #[benchmark(skip_meta)]
	// fn submit_disclosure() {
	// 	setup_disclosure_circuit::<T>();
	// 	let (caller, _) = setup_benchmark_env::<T>();
	// 	let commitment = Commitment([22u8; 32]);
	//
	// 	// Setup: Use real VK from artifacts (binary format for no_std compatibility)
	// 	let vk_bytes: BoundedVec<u8, ConstU32<4096>> =
	// 		DISCLOSURE_VK_ARK.to_vec().try_into().unwrap();
	// 	DisclosureVerifyingKey::<T>::put(vk_bytes);
	// 	CommitmentMemos::<T>::insert(
	// 		commitment,
	// 		FrameEncryptedMemo(vec![0u8; 104].try_into().unwrap()),
	// 	);
	//
	// 	let proof_bytes: BoundedVec<u8, ConstU32<256>> = vec![0u8; 256].try_into().unwrap();
	// 	// Public signals: commitment(32) + revealed_value(8) + revealed_asset_id(4) + revealed_owner_hash(32) = 76 bytes
	// 	let mut public_signals_vec = Vec::new();
	// 	public_signals_vec.extend_from_slice(&commitment.0); // 32 bytes
	// 	public_signals_vec.extend_from_slice(&[1u8; 8]); // 8 bytes (revealed_value)
	// 	public_signals_vec.extend_from_slice(&[0u8; 4]); // 4 bytes (revealed_asset_id)
	// 	public_signals_vec.extend_from_slice(&[0u8; 32]); // 32 bytes (revealed_owner_hash)
	// 	let public_signals: BoundedVec<u8, ConstU32<97>> = public_signals_vec.try_into().unwrap();
	// 	let partial_data: BoundedVec<u8, ConstU32<256>> = vec![4u8; 128].try_into().unwrap();
	//
	// 	#[extrinsic_call]
	// 	submit_disclosure(
	// 		RawOrigin::Signed(caller),
	// 		commitment,
	// 		proof_bytes,
	// 		public_signals,
	// 		partial_data,
	// 		None,
	// 	);
	// }

	// TODO: Reactivar cuando disclosure esté listo
	// #[benchmark(skip_meta)]
	// fn batch_submit_disclosure_proofs(n: Linear<1, 10>) {
	// 	setup_disclosure_circuit::<T>();
	// 	let (caller, _) = setup_benchmark_env::<T>();
	// 	// Setup: Use real VK from artifacts (binary format for no_std compatibility)
	// 	let vk_bytes: BoundedVec<u8, ConstU32<4096>> =
	// 		DISCLOSURE_VK_ARK.to_vec().try_into().unwrap();
	// 	DisclosureVerifyingKey::<T>::put(vk_bytes);
	//
	// 	let mut submissions = Vec::new();
	// 	for i in 0..n {
	// 		let commitment = Commitment([i as u8; 32]); // FIXED: was 33
	// 		CommitmentMemos::<T>::insert(
	// 			commitment,
	// 			FrameEncryptedMemo(vec![0u8; 104].try_into().unwrap()),
	// 		);
	//
	// 		// Public signals: commitment(32) + revealed_value(8) + revealed_asset_id(4) + revealed_owner_hash(32) = 76 bytes
	// 		let mut signals = Vec::new();
	// 		signals.extend_from_slice(&commitment.0); // 32 bytes
	// 		signals.extend_from_slice(&[1u8; 8]); // 8 bytes (revealed_value)
	// 		signals.extend_from_slice(&[0u8; 4]); // 4 bytes (revealed_asset_id)
	// 		signals.extend_from_slice(&[0u8; 32]); // 32 bytes (revealed_owner_hash)
	//
	// 		submissions.push(BatchDisclosureSubmission {
	// 			commitment,
	// 			proof: vec![0u8; 256].try_into().unwrap(),
	// 			public_signals: signals.try_into().unwrap(),
	// 			disclosed_data: vec![0u8; 256].try_into().unwrap(),
	// 		});
	// 	}
	// 	let submissions_vec: BoundedVec<_, ConstU32<10>> = submissions.try_into().unwrap();
	//
	// 	#[extrinsic_call]
	// 	batch_submit_disclosure_proofs(RawOrigin::Signed(caller), submissions_vec);
	// }

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
		let asset_id = crate::application::services::asset_service::AssetService::register::<T>(
			name, symbol, 18, None,
		)
		.unwrap();

		#[extrinsic_call]
		verify_asset(RawOrigin::Root, asset_id);
	}

	#[benchmark]
	fn unverify_asset() {
		let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
		let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
		let asset_id = crate::application::services::asset_service::AssetService::register::<T>(
			name, symbol, 18, None,
		)
		.unwrap();
		let _ = crate::application::services::asset_service::AssetService::verify::<T>(asset_id);

		#[extrinsic_call]
		unverify_asset(RawOrigin::Root, asset_id);
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test,);
}
