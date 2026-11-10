//! Benchmarks for pallet-shielded-pool
//!
//! These benchmarks measure the execution time of extrinsics.

use crate::*;
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

/// The origin the runtime's `AdminOrigin` accepts.
fn admin<T: Config>() -> T::RuntimeOrigin {
	<T::AdminOrigin as frame_support::traits::EnsureOrigin<T::RuntimeOrigin>>::try_successful_origin()
		.expect("AdminOrigin has a successful origin to benchmark with")
}

#[benchmarks(
	where
		T: pallet_zk_verifier::Config,
)]
mod benchmarks {
	use super::*;
	use crate::FrameEncryptedMemo;
	use crate::pallet::{Assets, NextAssetId, PendingFees, PoolBalancePerAsset};
	use sp_std::vec::Vec;

	/// A spend with a fee credits the block author, so the benchmarked block
	/// must have one: the runtime's `BlockAuthor` has to return `Some` under
	/// `runtime-benchmarks`.
	fn ensure_block_author<T: Config>() {
		assert!(
			T::BlockAuthor::get().is_some(),
			"spend benchmarks need `BlockAuthor` to return an account"
		);
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
		let _ = <T::Currency as Currency<T::AccountId>>::make_free_balance_be(
			&caller,
			bench_amount::<T>() * 100u32.into(),
		);

		(caller, asset_id)
	}

	/// A value large enough to survive a spend fee being deducted from it.
	///
	/// A flat literal breaks the moment a runtime's `MinSpendFee` exceeds it —
	/// the production floor is 1e15 planck, which dwarfs any hand-picked
	/// constant. Deriving it from the configured fee keeps the benchmarks
	/// working across every runtime.
	fn bench_amount<T: Config>() -> BalanceOf<T> {
		let fee: BalanceOf<T> = T::MinSpendFee::get().saturated_into();
		let scaled = fee * 1_000u32.into();
		let floor: BalanceOf<T> = 1_000_000u32.into();
		if scaled > floor { scaled } else { floor }
	}

	/// Worst case for `inserts` leaf inserts: a full prune budget of expired roots
	/// each, and an active root from an earlier block to retire. Call before
	/// seeding the spend's own roots, which must stay live. Returns the queue tail.
	fn seed_expired_roots<T: Config>(inserts: u32) -> u64 {
		let per_insert = crate::merkle::MAX_ROOTS_PRUNED_PER_INSERT as u32;
		for i in 0..inserts * per_insert {
			let mut root = [0xBEu8; 32];
			root[..4].copy_from_slice(&i.to_le_bytes());
			crate::merkle::MerkleTreeService::add_poseidon_historic_root::<T>(root);
		}
		let past =
			frame_system::Pallet::<T>::block_number() + T::RootRetentionBlocks::get() + 1u32.into();
		frame_system::Pallet::<T>::set_block_number(past);
		crate::storage::MerkleRepository::get_historic_roots_tail::<T>()
	}

	/// Every insert pruned its whole budget.
	fn assert_budget_spent<T: Config>(tail: u64, inserts: u32) {
		let per_insert = crate::merkle::MAX_ROOTS_PRUNED_PER_INSERT as u64;
		let pruned = crate::storage::MerkleRepository::get_historic_roots_tail::<T>() - tail;
		assert_eq!(pruned, inserts as u64 * per_insert, "inserts {inserts}");
	}

	/// A distinct, canonical 32-byte field value for `seed`.
	///
	/// Commitments and nullifiers are checked against the BN254 modulus, and a
	/// repeated byte at or above 0x30 exceeds it — `p` starts at 0x30. Real
	/// values come out of Poseidon and are always canonical, so a filler that is
	/// not would benchmark a call the chain would reject.
	fn canonical_bytes(seed: u8) -> [u8; 32] {
		let mut b = [0u8; 32];
		b[0] = seed;
		b[1] = 0xA5;
		b
	}

	#[benchmark]
	fn shield() {
		let (caller, asset_id) = setup_benchmark_env::<T>();
		let tail = seed_expired_roots::<T>(1);
		let amount: BalanceOf<T> = bench_amount::<T>();
		let commitment = Commitment(canonical_bytes(1));
		// Memo must be exactly 180 bytes (MAX_ENCRYPTED_MEMO_SIZE): nonce(12) + data(120) + MAC(16) + ephPk(32)
		let memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let encrypted_memo = FrameEncryptedMemo(memo_bytes.try_into().unwrap());
		// Verification is weighed separately (`verification_weight`), so a stub proof.
		let proof: Proof = vec![0u8; 128].try_into().unwrap();

		#[extrinsic_call]
		shield(
			RawOrigin::Signed(caller),
			asset_id,
			amount,
			commitment,
			encrypted_memo,
			proof,
			1u32,
		);

		assert_budget_spent::<T>(tail, 1);
	}

	#[benchmark]
	fn shield_batch(n: Linear<1, 20>) {
		let (caller, asset_id) = setup_benchmark_env::<T>();
		let tail = seed_expired_roots::<T>(n);
		let amount: BalanceOf<T> = bench_amount::<T>();

		let mut operations = Vec::new();
		for i in 0..n {
			let commitment = Commitment(canonical_bytes(i as u8));
			let memo_bytes = vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
			let encrypted_memo = FrameEncryptedMemo(memo_bytes.try_into().unwrap());
			let proof: Proof = vec![0u8; 128].try_into().unwrap();
			operations.push((asset_id, amount, commitment, encrypted_memo, proof, 1u32));
		}
		let operations_vec: BoundedVec<_, ConstU32<20>> = operations.try_into().unwrap();

		#[extrinsic_call]
		shield_batch(RawOrigin::Signed(caller), operations_vec);

		assert_budget_spent::<T>(tail, n);
	}

	#[benchmark]
	fn private_transfer() {
		let (_caller, _) = setup_benchmark_env::<T>();
		let tail = seed_expired_roots::<T>(2);
		// Two notes from two sealed trees: each root misses the active and
		// historic lookups and is found last, in `SealedRootIndex`.
		let merkle_roots = [[1u8; 32], [2u8; 32]];
		for (tree_id, root) in (0u32..).zip(merkle_roots) {
			crate::storage::MerkleRepository::insert_sealed_root::<T>(tree_id, root);
		}

		let proof: Proof = vec![0u8; 128].try_into().unwrap();

		// Two real inputs and two outputs: the most reads and leaf insertions.
		let memo = || {
			FrameEncryptedMemo(
				vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize]
					.try_into()
					.unwrap(),
			)
		};
		let nullifiers: BoundedVec<Nullifier, ConstU32<2>> = vec![
			Nullifier(canonical_bytes(0x20)),
			Nullifier(canonical_bytes(0x21)),
		]
		.try_into()
		.unwrap();
		let commitments: BoundedVec<Commitment, ConstU32<2>> = vec![
			Commitment(canonical_bytes(0x30)),
			Commitment(canonical_bytes(0x31)),
		]
		.try_into()
		.unwrap();
		let encrypted_memos: BoundedVec<FrameEncryptedMemo, ConstU32<2>> =
			vec![memo(), memo()].try_into().unwrap();

		let asset_id = 0u32;
		// Non-zero, so the fee is credited, and >= MinSpendFee to pass FeeTooLow.
		let fee: BalanceOf<T> = T::MinSpendFee::get().max(1).saturated_into();
		ensure_block_author::<T>();

		#[extrinsic_call]
		private_transfer(
			RawOrigin::None,
			proof,
			merkle_roots,
			nullifiers,
			commitments,
			encrypted_memos,
			asset_id,
			fee,
			1u32,
		);

		assert_budget_spent::<T>(tail, 2);
	}

	#[benchmark]
	fn unshield() {
		let (_caller, asset_id) = setup_benchmark_env::<T>();
		let tail = seed_expired_roots::<T>(1);
		let recipient: T::AccountId = account("recipient", 0, 0);
		let merkle_root = [1u8; 32];
		let amount: BalanceOf<T> = bench_amount::<T>();

		// Setup valid state: root and pool balance
		crate::storage::MerkleRepository::add_historic_poseidon_root::<T>(merkle_root);
		PoolBalancePerAsset::<T>::insert(asset_id, amount * 2u32.into());
		// Fund pool account too for actual transfer
		let _ = <T::Currency as Currency<T::AccountId>>::make_free_balance_be(
			&Pallet::<T>::pool_account_id(),
			amount * 100u32.into(),
		);

		let proof: Proof = vec![0u8; 128].try_into().unwrap();
		let nullifier = Nullifier(canonical_bytes(4));
		// Partial: the change note's leaf and memo make it the costlier branch.
		let change_commitment = canonical_bytes(9);
		let change_memo = FrameEncryptedMemo(
			vec![0u8; MAX_ENCRYPTED_MEMO_SIZE as usize]
				.try_into()
				.unwrap(),
		);

		// Non-zero, so the fee is credited, and >= MinSpendFee to pass FeeTooLow.
		let fee: BalanceOf<T> = T::MinSpendFee::get().max(1).saturated_into();
		ensure_block_author::<T>();

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
			change_commitment,
			change_memo,
			1u32, // circuit_version
		);

		assert_budget_spent::<T>(tail, 1);
		assert!(crate::storage::CommitmentRepository::exists::<T>(
			&Commitment(change_commitment)
		));
	}

	#[benchmark]
	fn register_asset() {
		let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
		let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
		let origin = admin::<T>();
		#[extrinsic_call]
		register_asset(origin as T::RuntimeOrigin, name, symbol, 18, None);
	}

	#[benchmark]
	fn verify_asset() {
		let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
		let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
		let asset_id =
			crate::operations::assets::AssetOperation::register::<T>(name, symbol, 18, None)
				.unwrap();

		let origin = admin::<T>();
		#[extrinsic_call]
		verify_asset(origin as T::RuntimeOrigin, asset_id);
	}

	#[benchmark]
	fn unverify_asset() {
		let name: BoundedVec<u8, ConstU32<64>> = vec![1u8; 32].try_into().unwrap();
		let symbol: BoundedVec<u8, ConstU32<16>> = vec![1u8; 4].try_into().unwrap();
		let asset_id =
			crate::operations::assets::AssetOperation::register::<T>(name, symbol, 18, None)
				.unwrap();
		let _ = crate::operations::assets::AssetOperation::verify::<T>(asset_id);

		let origin = admin::<T>();
		#[extrinsic_call]
		unverify_asset(origin as T::RuntimeOrigin, asset_id);
	}

	/// Worst case: the validator's account does not exist yet, so the payout
	/// creates it.
	#[benchmark]
	fn claim_fees() {
		let (_caller, asset_id) = setup_benchmark_env::<T>();
		let amount: BalanceOf<T> = bench_amount::<T>();
		let validator: T::AccountId = account("validator", 0, 0);
		PendingFees::<T>::insert(&validator, asset_id, amount.saturated_into::<u128>());
		PoolBalancePerAsset::<T>::insert(asset_id, amount * 2u32.into());
		let _ = <T::Currency as Currency<T::AccountId>>::make_free_balance_be(
			&Pallet::<T>::pool_account_id(),
			amount * 100u32.into(),
		);

		#[extrinsic_call]
		claim_fees(RawOrigin::Signed(validator), asset_id, amount);
	}

	/// Cost of one sweep that probes `n` sealed-tree nodes.
	///
	/// Not an extrinsic: the sweep runs in `on_initialize` over a fixed batch. It
	/// still needs measuring, because the hook must return the weight it actually
	/// consumed — declaring less would let a block overrun.
	///
	/// The setup seals a tree and populates its prunable levels directly rather
	/// than inserting 2^20 leaves, which no benchmark could run. What matters for
	/// the measurement is the trie shape: `MerkleNodes` is a three-key `StorageNMap`,
	/// so the per-node cost is a keyed lookup plus a removal, exactly as in
	/// production.
	#[benchmark]
	fn prune_sealed_nodes(n: Linear<0, 512>) {
		let cap = T::MaxLeavesPerTree::get();
		let cut = T::SealedTreePrunedBelowLevel::get();

		// Seal tree 0 by parking the size past its capacity, then give it a
		// permanent anchor as `seal_tree` would.
		crate::storage::MerkleRepository::set_tree_size::<T>(cap);
		crate::storage::MerkleRepository::insert_sealed_root::<T>(0, [0xABu8; 32]);

		// Fill the prunable levels with `n` nodes for the sweep to find.
		let mut placed = 0u32;
		'outer: for level in 1..cut {
			for index in 0..(cap >> level) {
				if placed >= n {
					break 'outer;
				}
				let mut node = [0u8; 32];
				node[..4].copy_from_slice(&placed.to_le_bytes());
				crate::storage::MerkleRepository::set_node::<T>(0, level, index, node);
				placed = placed.saturating_add(1);
			}
		}

		#[block]
		{
			crate::merkle::MerkleTreeService::prune_sealed_nodes::<T>(n);
		}
	}

	impl_benchmark_test_suite!(
		Pallet,
		crate::tests::mock::new_test_ext(),
		crate::tests::mock::Test,
	);
}
