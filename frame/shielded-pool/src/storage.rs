//! Storage access — typed wrappers over every `StorageValue` / `StorageMap`.
//!
//! One struct per logical domain (Assets, Commitments, Merkle, Nullifiers,
//! PoolBalance, Audit). All functions are static; no instance state.

use crate::{
	pallet::{
		Assets, AuditPolicies, AuditTrailStorage, BalanceOf, CommitmentMemos, Config,
		DisclosureCounters, DisclosureRecords, DisclosureRequests, Error, HistoricPoseidonRoots,
		HistoricRootsOrder, LastDisclosureTimestamp, MerkleLeaves, MerkleTreeFrontier,
		MerkleTreeSize, NextAssetId, NextAuditTrailId, NullifierSet, PoolBalancePerAsset,
		PoseidonRoot,
	},
	types::{
		AssetMetadata, AuditPolicy, AuditTrail, Commitment, DisclosureRecord, DisclosureRequest,
		EncryptedMemo, Hash,
	},
};
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::BlockNumberFor;
use parity_scale_codec::Encode;
use sp_runtime::traits::Saturating;

// ════════════════════════════════════════════════════════════════════════════
// AssetRepository
// ════════════════════════════════════════════════════════════════════════════

pub struct AssetRepository;

impl AssetRepository {
	pub fn get_asset<T: Config>(
		asset_id: u32,
	) -> Option<AssetMetadata<T::AccountId, BlockNumberFor<T>>> {
		Assets::<T>::get(asset_id)
	}
	pub fn store_asset<T: Config>(
		asset_id: u32,
		metadata: AssetMetadata<T::AccountId, BlockNumberFor<T>>,
	) {
		Assets::<T>::insert(asset_id, metadata);
	}
	pub fn exists<T: Config>(asset_id: u32) -> bool {
		Assets::<T>::contains_key(asset_id)
	}
	pub fn get_next_asset_id<T: Config>() -> u32 {
		NextAssetId::<T>::get()
	}
	pub fn increment_asset_id<T: Config>() -> u32 {
		let current = Self::get_next_asset_id::<T>();
		NextAssetId::<T>::put(current.saturating_add(1));
		current
	}
	pub fn set_verified<T: Config>(asset_id: u32, is_verified: bool) -> bool {
		Assets::<T>::mutate(asset_id, |maybe_asset| {
			if let Some(asset) = maybe_asset {
				asset.is_verified = is_verified;
				true
			} else {
				false
			}
		})
	}
}

// ════════════════════════════════════════════════════════════════════════════
// CommitmentRepository
// ════════════════════════════════════════════════════════════════════════════

pub struct CommitmentRepository;

impl CommitmentRepository {
	pub fn get_memo<T: Config>(commitment: &Commitment) -> Option<EncryptedMemo> {
		CommitmentMemos::<T>::get(commitment)
	}
	pub fn store_memo<T: Config>(commitment: Commitment, memo: EncryptedMemo) {
		CommitmentMemos::<T>::insert(commitment, memo);
	}
	pub fn exists<T: Config>(commitment: &Commitment) -> bool {
		CommitmentMemos::<T>::contains_key(commitment)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// MerkleRepository
// ════════════════════════════════════════════════════════════════════════════

pub struct MerkleRepository;

impl MerkleRepository {
	pub fn get_poseidon_root<T: Config>() -> Hash {
		PoseidonRoot::<T>::get()
	}
	pub fn set_poseidon_root<T: Config>(root: Hash) {
		PoseidonRoot::<T>::put(root);
	}
	pub fn get_tree_size<T: Config>() -> u32 {
		MerkleTreeSize::<T>::get()
	}
	pub fn set_tree_size<T: Config>(size: u32) {
		MerkleTreeSize::<T>::put(size);
	}
	pub fn get_leaf<T: Config>(index: u32) -> Option<Commitment> {
		MerkleLeaves::<T>::get(index)
	}
	pub fn insert_leaf<T: Config>(index: u32, commitment: Commitment) {
		MerkleLeaves::<T>::insert(index, commitment);
	}
	pub fn is_known_poseidon_root<T: Config>(root: &Hash) -> bool {
		HistoricPoseidonRoots::<T>::get(root)
	}
	pub fn is_known_root<T: Config>(root: &Hash) -> bool {
		Self::is_known_poseidon_root::<T>(root)
	}
	pub fn add_historic_poseidon_root<T: Config>(root: Hash) {
		HistoricPoseidonRoots::<T>::insert(root, true);
	}
	pub fn remove_poseidon_historic_root<T: Config>(root: &Hash) {
		HistoricPoseidonRoots::<T>::remove(root);
	}
	pub fn get_historic_roots_order<T: Config>() -> BoundedVec<Hash, T::MaxHistoricRoots> {
		HistoricRootsOrder::<T>::get()
	}
	pub fn set_historic_roots_order<T: Config>(order: BoundedVec<Hash, T::MaxHistoricRoots>) {
		HistoricRootsOrder::<T>::put(order);
	}
	pub fn get_frontier<T: Config>() -> [[u8; 32]; 20] {
		MerkleTreeFrontier::<T>::get()
	}
	pub fn set_frontier<T: Config>(frontier: [[u8; 32]; 20]) {
		MerkleTreeFrontier::<T>::put(frontier);
	}
	pub fn find_leaf_index<T: Config>(commitment: &Commitment) -> Option<u32> {
		let size = Self::get_tree_size::<T>();
		for i in 0..size {
			#[allow(clippy::collapsible_if)]
			if let Some(c) = Self::get_leaf::<T>(i) {
				if c == *commitment {
					return Some(i);
				}
			}
		}
		None
	}
	pub fn get_all_leaves<T: Config>() -> sp_std::vec::Vec<Hash> {
		let size = Self::get_tree_size::<T>();
		(0..size)
			.filter_map(|i| Self::get_leaf::<T>(i).map(|c| c.0))
			.collect()
	}
}

// ════════════════════════════════════════════════════════════════════════════
// NullifierRepository
// ════════════════════════════════════════════════════════════════════════════

pub struct NullifierRepository;

impl NullifierRepository {
	pub fn is_used<T: Config>(nullifier: &crate::types::Nullifier) -> bool {
		NullifierSet::<T>::contains_key(nullifier)
	}
	pub fn mark_as_used<T: Config>(nullifier: crate::types::Nullifier, block: BlockNumberFor<T>) {
		NullifierSet::<T>::insert(nullifier, block);
	}
	pub fn get_usage_block<T: Config>(
		nullifier: &crate::types::Nullifier,
	) -> Option<BlockNumberFor<T>> {
		NullifierSet::<T>::get(nullifier)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// PoolBalanceRepository
// ════════════════════════════════════════════════════════════════════════════

pub struct PoolBalanceRepository;

impl PoolBalanceRepository {
	pub fn get_asset_balance<T: Config>(asset_id: u32) -> BalanceOf<T> {
		PoolBalancePerAsset::<T>::get(asset_id)
	}
	pub fn set_asset_balance<T: Config>(asset_id: u32, balance: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::insert(asset_id, balance);
	}
	pub fn increase_balance<T: Config>(asset_id: u32, amount: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::mutate(asset_id, |balance| {
			*balance = balance.saturating_add(amount);
		});
	}
	pub fn decrease_balance<T: Config>(asset_id: u32, amount: BalanceOf<T>) {
		PoolBalancePerAsset::<T>::mutate(asset_id, |balance| {
			*balance = balance.saturating_sub(amount);
		});
	}
}

// ════════════════════════════════════════════════════════════════════════════
// AuditRepository
// ════════════════════════════════════════════════════════════════════════════

pub struct AuditRepository;

impl AuditRepository {
	// ── Policies ────────────────────────────────────────────────────────
	pub fn get_policy<T: Config>(
		account: &T::AccountId,
	) -> Option<AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>> {
		AuditPolicies::<T>::get(account)
	}
	pub fn store_policy<T: Config>(
		account: &T::AccountId,
		policy: AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
	) {
		AuditPolicies::<T>::insert(account, policy);
	}
	pub fn get_audit_policy<T: Config>(
		account: &T::AccountId,
	) -> Option<AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>> {
		AuditPolicies::<T>::get(account)
	}
	pub fn set_audit_policy<T: Config>(
		account: T::AccountId,
		policy: AuditPolicy<T::AccountId, BalanceOf<T>, BlockNumberFor<T>>,
	) {
		AuditPolicies::<T>::insert(account, policy);
	}
	pub fn remove_audit_policy<T: Config>(account: &T::AccountId) {
		AuditPolicies::<T>::remove(account);
	}

	// ── Disclosure Requests ─────────────────────────────────────────────
	pub fn get_disclosure_request<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
	) -> Option<DisclosureRequest<T::AccountId, BlockNumberFor<T>>> {
		DisclosureRequests::<T>::get(target, auditor)
	}
	pub fn store_disclosure_request<T: Config>(
		target: T::AccountId,
		auditor: T::AccountId,
		request: DisclosureRequest<T::AccountId, BlockNumberFor<T>>,
	) {
		DisclosureRequests::<T>::insert(target, auditor, request);
	}
	pub fn remove_disclosure_request<T: Config>(target: &T::AccountId, auditor: &T::AccountId) {
		DisclosureRequests::<T>::remove(target, auditor);
	}
	pub fn has_disclosure_request<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
	) -> bool {
		DisclosureRequests::<T>::contains_key(target, auditor)
	}

	// ── Disclosure Records ──────────────────────────────────────────────
	pub fn get_disclosure_record<T: Config>(
		commitment: Commitment,
		key: &T::AccountId,
	) -> Option<DisclosureRecord<T::AccountId, BlockNumberFor<T>>> {
		DisclosureRecords::<T>::get(commitment, key)
	}
	pub fn store_disclosure_record<T: Config>(
		commitment: Commitment,
		key: &T::AccountId,
		record: DisclosureRecord<T::AccountId, BlockNumberFor<T>>,
	) -> sp_runtime::DispatchResult {
		frame_support::ensure!(
			!DisclosureRecords::<T>::contains_key(commitment, key),
			Error::<T>::DisclosureRecordAlreadyExists
		);
		DisclosureRecords::<T>::insert(commitment, key, record);
		Ok(())
	}
	pub fn has_disclosure_record<T: Config>(commitment: Commitment, key: &T::AccountId) -> bool {
		DisclosureRecords::<T>::contains_key(commitment, key)
	}

	// ── Audit Trail ─────────────────────────────────────────────────────
	pub fn get_audit_trail<T: Config>(
		trail_hash: &Hash,
	) -> Option<AuditTrail<T::AccountId, BlockNumberFor<T>>> {
		AuditTrailStorage::<T>::get(trail_hash)
	}
	pub fn store_audit_trail<T: Config>(
		trail_hash: Hash,
		trail: AuditTrail<T::AccountId, BlockNumberFor<T>>,
	) {
		AuditTrailStorage::<T>::insert(trail_hash, trail);
	}
	pub fn get_next_audit_trail_id<T: Config>() -> u64 {
		NextAuditTrailId::<T>::get()
	}
	pub fn increment_audit_trail_id<T: Config>() -> u64 {
		let current = Self::get_next_audit_trail_id::<T>();
		NextAuditTrailId::<T>::put(current.saturating_add(1));
		current
	}

	// ── Rate Limiting ───────────────────────────────────────────────────
	pub fn get_last_disclosure_timestamp<T: Config>(
		account: &T::AccountId,
		commitment: Commitment,
	) -> Option<BlockNumberFor<T>> {
		LastDisclosureTimestamp::<T>::get(account, commitment)
	}
	pub fn update_disclosure_timestamp<T: Config>(
		account: &T::AccountId,
		commitment: Commitment,
		block: BlockNumberFor<T>,
	) {
		LastDisclosureTimestamp::<T>::insert(account, commitment, block);
	}
	pub fn set_last_disclosure_timestamp<T: Config>(
		account: T::AccountId,
		commitment: Commitment,
		block: BlockNumberFor<T>,
	) {
		LastDisclosureTimestamp::<T>::insert(account, commitment, block);
	}

	// ── Commitment Memos ────────────────────────────────────────────────
	pub fn has_commitment_memo<T: Config>(commitment: Commitment) -> bool {
		CommitmentMemos::<T>::contains_key(commitment)
	}

	// ── Audit Trail Creation ────────────────────────────────────────────
	pub fn create_audit_trail<T: Config>(
		account: &T::AccountId,
		auditor: &T::AccountId,
		commitment: Commitment,
		disclosure_type: &[u8],
	) -> Result<[u8; 32], sp_runtime::DispatchError> {
		let trail_id = Self::increment_audit_trail_id::<T>();
		let trail_hash = {
			let mut data = trail_id.to_le_bytes().to_vec();
			data.extend_from_slice(&account.encode());
			data.extend_from_slice(&auditor.encode());
			data.extend_from_slice(&commitment.0);
			sp_io::hashing::blake2_256(&data)
		};
		let current_block = frame_system::Pallet::<T>::block_number();
		let trail = AuditTrail {
			account: account.clone(),
			auditor: auditor.clone(),
			timestamp: current_block,
			disclosure_type: disclosure_type.to_vec().try_into().unwrap_or_default(),
			trail_hash,
		};
		Self::store_audit_trail::<T>(trail_hash, trail);
		Ok(trail_hash)
	}

	// ── Disclosure Counters ─────────────────────────────────────────────
	pub fn get_disclosure_counter<T: Config>(target: &T::AccountId, auditor: &T::AccountId) -> u32 {
		DisclosureCounters::<T>::get(target, auditor)
	}
	pub fn increment_disclosure_counter<T: Config>(target: &T::AccountId, auditor: &T::AccountId) {
		DisclosureCounters::<T>::mutate(target, auditor, |c| *c = c.saturating_add(1));
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		types::{
			AssetMetadata, AuditPolicy, Commitment, DisclosureCondition, DisclosureRecord,
			DisclosureRequest, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE, Nullifier,
		},
	};
	use frame_support::{BoundedVec, assert_ok, pallet_prelude::ConstU32};

	// ── helpers ───────────────────────────────────────────────────────────────

	fn test_commitment(seed: u8) -> Commitment {
		Commitment::new([seed; 32])
	}

	fn test_nullifier(seed: u8) -> Nullifier {
		Nullifier::new([seed; 32])
	}

	fn test_memo() -> EncryptedMemo {
		EncryptedMemo::from_bytes(&[0x01u8; MAX_ENCRYPTED_MEMO_SIZE as usize]).unwrap()
	}

	fn make_asset_metadata(id: u32) -> AssetMetadata<u64, u64> {
		AssetMetadata::new(
			id,
			BoundedVec::try_from(b"Test".to_vec()).unwrap(),
			BoundedVec::try_from(b"TST".to_vec()).unwrap(),
			18,
			0u64,
			1u64,
		)
	}

	// ── AssetRepository ──────────────────────────────────────────────────────

	#[test]
	fn asset_repo_store_and_get() {
		new_test_ext().execute_with(|| {
			let meta = make_asset_metadata(10);
			AssetRepository::store_asset::<Test>(10, meta);
			let got = AssetRepository::get_asset::<Test>(10).unwrap();
			assert_eq!(got.id, 10);
		});
	}

	#[test]
	fn asset_repo_exists_returns_correct() {
		new_test_ext().execute_with(|| {
			assert!(!AssetRepository::exists::<Test>(99));
			AssetRepository::store_asset::<Test>(99, make_asset_metadata(99));
			assert!(AssetRepository::exists::<Test>(99));
		});
	}

	#[test]
	fn asset_repo_get_none_for_unknown() {
		new_test_ext().execute_with(|| {
			assert!(AssetRepository::get_asset::<Test>(999).is_none());
		});
	}

	#[test]
	fn asset_repo_get_next_id_starts_at_1() {
		new_test_ext().execute_with(|| {
			// genesis sets NextAssetId = 1
			assert_eq!(AssetRepository::get_next_asset_id::<Test>(), 1);
		});
	}

	#[test]
	fn asset_repo_increment_returns_current_then_advances() {
		new_test_ext().execute_with(|| {
			let id0 = AssetRepository::increment_asset_id::<Test>(); // returns 1, stores 2
			assert_eq!(id0, 1);
			let id1 = AssetRepository::increment_asset_id::<Test>(); // returns 2, stores 3
			assert_eq!(id1, 2);
			assert_eq!(AssetRepository::get_next_asset_id::<Test>(), 3);
		});
	}

	#[test]
	fn asset_repo_set_verified_true_and_false() {
		new_test_ext().execute_with(|| {
			AssetRepository::store_asset::<Test>(5, make_asset_metadata(5));
			assert!(AssetRepository::set_verified::<Test>(5, true));
			assert!(AssetRepository::get_asset::<Test>(5).unwrap().is_verified);
			assert!(AssetRepository::set_verified::<Test>(5, false));
			assert!(!AssetRepository::get_asset::<Test>(5).unwrap().is_verified);
		});
	}

	#[test]
	fn asset_repo_set_verified_not_found_returns_false() {
		new_test_ext().execute_with(|| {
			assert!(!AssetRepository::set_verified::<Test>(999, true));
		});
	}

	// ── CommitmentRepository ─────────────────────────────────────────────────

	#[test]
	fn commitment_repo_store_and_get_memo() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x01);
			let memo = test_memo();
			CommitmentRepository::store_memo::<Test>(c, memo.clone());
			assert_eq!(CommitmentRepository::get_memo::<Test>(&c), Some(memo));
		});
	}

	#[test]
	fn commitment_repo_exists_returns_correct() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x02);
			assert!(!CommitmentRepository::exists::<Test>(&c));
			CommitmentRepository::store_memo::<Test>(c, test_memo());
			assert!(CommitmentRepository::exists::<Test>(&c));
		});
	}

	#[test]
	fn commitment_repo_get_memo_none_when_missing() {
		new_test_ext().execute_with(|| {
			assert!(CommitmentRepository::get_memo::<Test>(&test_commitment(0xAA)).is_none());
		});
	}

	// ── MerkleRepository ─────────────────────────────────────────────────────

	#[test]
	fn merkle_repo_poseidon_root_get_and_set() {
		new_test_ext().execute_with(|| {
			let root = [0xBBu8; 32];
			MerkleRepository::set_poseidon_root::<Test>(root);
			assert_eq!(MerkleRepository::get_poseidon_root::<Test>(), root);
		});
	}

	#[test]
	fn merkle_repo_tree_size_zero_on_start() {
		new_test_ext().execute_with(|| {
			assert_eq!(MerkleRepository::get_tree_size::<Test>(), 0);
		});
	}

	#[test]
	fn merkle_repo_tree_size_set() {
		new_test_ext().execute_with(|| {
			MerkleRepository::set_tree_size::<Test>(7);
			assert_eq!(MerkleRepository::get_tree_size::<Test>(), 7);
		});
	}

	#[test]
	fn merkle_repo_insert_and_get_leaf() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x05);
			MerkleRepository::insert_leaf::<Test>(0, c);
			assert_eq!(MerkleRepository::get_leaf::<Test>(0), Some(c));
			assert_eq!(MerkleRepository::get_leaf::<Test>(1), None);
		});
	}

	#[test]
	fn merkle_repo_is_known_root_after_add() {
		new_test_ext().execute_with(|| {
			let root = [0xCCu8; 32];
			assert!(!MerkleRepository::is_known_root::<Test>(&root));
			MerkleRepository::add_historic_poseidon_root::<Test>(root);
			assert!(MerkleRepository::is_known_root::<Test>(&root));
		});
	}

	#[test]
	fn merkle_repo_remove_historic_root() {
		new_test_ext().execute_with(|| {
			let root = [0xDDu8; 32];
			MerkleRepository::add_historic_poseidon_root::<Test>(root);
			assert!(MerkleRepository::is_known_root::<Test>(&root));
			MerkleRepository::remove_poseidon_historic_root::<Test>(&root);
			assert!(!MerkleRepository::is_known_root::<Test>(&root));
		});
	}

	#[test]
	fn merkle_repo_find_leaf_index_returns_correct_positions() {
		new_test_ext().execute_with(|| {
			let c0 = test_commitment(0xA1);
			let c1 = test_commitment(0xA2);
			MerkleRepository::insert_leaf::<Test>(0, c0);
			MerkleRepository::insert_leaf::<Test>(1, c1);
			MerkleRepository::set_tree_size::<Test>(2);
			assert_eq!(MerkleRepository::find_leaf_index::<Test>(&c0), Some(0));
			assert_eq!(MerkleRepository::find_leaf_index::<Test>(&c1), Some(1));
			assert_eq!(
				MerkleRepository::find_leaf_index::<Test>(&test_commitment(0xFF)),
				None
			);
		});
	}

	#[test]
	fn merkle_repo_get_all_leaves_returns_all() {
		new_test_ext().execute_with(|| {
			let c0 = test_commitment(0xB1);
			let c1 = test_commitment(0xB2);
			MerkleRepository::insert_leaf::<Test>(0, c0);
			MerkleRepository::insert_leaf::<Test>(1, c1);
			MerkleRepository::set_tree_size::<Test>(2);
			let leaves = MerkleRepository::get_all_leaves::<Test>();
			assert_eq!(leaves.len(), 2);
			assert!(leaves.contains(&c0.0));
			assert!(leaves.contains(&c1.0));
		});
	}

	// ── NullifierRepository ──────────────────────────────────────────────────

	#[test]
	fn nullifier_repo_not_used_by_default() {
		new_test_ext().execute_with(|| {
			assert!(!NullifierRepository::is_used::<Test>(&test_nullifier(0x01)));
		});
	}

	#[test]
	fn nullifier_repo_mark_and_check_used() {
		new_test_ext().execute_with(|| {
			let n = test_nullifier(0x02);
			NullifierRepository::mark_as_used::<Test>(n, 42u64);
			assert!(NullifierRepository::is_used::<Test>(&n));
		});
	}

	#[test]
	fn nullifier_repo_get_usage_block() {
		new_test_ext().execute_with(|| {
			let n = test_nullifier(0x03);
			assert!(NullifierRepository::get_usage_block::<Test>(&n).is_none());
			NullifierRepository::mark_as_used::<Test>(n, 100u64);
			assert_eq!(
				NullifierRepository::get_usage_block::<Test>(&n),
				Some(100u64)
			);
		});
	}

	// ── PoolBalanceRepository ─────────────────────────────────────────────────

	#[test]
	fn pool_balance_repo_zero_by_default() {
		new_test_ext().execute_with(|| {
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(0), 0u128);
		});
	}

	#[test]
	fn pool_balance_repo_set_and_get() {
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(1, 500u128);
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(1), 500u128);
		});
	}

	#[test]
	fn pool_balance_repo_increase_adds_amount() {
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(2, 100u128);
			PoolBalanceRepository::increase_balance::<Test>(2, 50u128);
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(2), 150u128);
		});
	}

	#[test]
	fn pool_balance_repo_decrease_subtracts_amount() {
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(3, 200u128);
			PoolBalanceRepository::decrease_balance::<Test>(3, 80u128);
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(3), 120u128);
		});
	}

	#[test]
	fn pool_balance_repo_decrease_saturates_at_zero() {
		new_test_ext().execute_with(|| {
			PoolBalanceRepository::set_asset_balance::<Test>(4, 10u128);
			PoolBalanceRepository::decrease_balance::<Test>(4, 100u128);
			assert_eq!(PoolBalanceRepository::get_asset_balance::<Test>(4), 0u128);
		});
	}

	// ── AuditRepository ──────────────────────────────────────────────────────

	#[test]
	fn audit_repo_policy_store_and_get() {
		new_test_ext().execute_with(|| {
			let policy: AuditPolicy<u64, u128, u64> = AuditPolicy {
				auditors: BoundedVec::new(),
				conditions: BoundedVec::new(),
				max_frequency: None,
				valid_until: None,
				version: 1,
			};
			AuditRepository::store_policy::<Test>(&1u64, policy);
			let got = AuditRepository::get_policy::<Test>(&1u64).unwrap();
			assert_eq!(got.version, 1);
		});
	}

	#[test]
	fn audit_repo_policy_remove() {
		new_test_ext().execute_with(|| {
			let policy: AuditPolicy<u64, u128, u64> = AuditPolicy {
				auditors: BoundedVec::new(),
				conditions: BoundedVec::new(),
				max_frequency: None,
				valid_until: None,
				version: 2,
			};
			AuditRepository::store_policy::<Test>(&2u64, policy);
			AuditRepository::remove_audit_policy::<Test>(&2u64);
			assert!(AuditRepository::get_policy::<Test>(&2u64).is_none());
		});
	}

	#[test]
	fn audit_repo_disclosure_request_store_and_get() {
		new_test_ext().execute_with(|| {
			let req = DisclosureRequest {
				auditor: 10u64,
				target: 20u64,
				requested_at: 1u64,
				expires_at: 1000u64,
				reason: BoundedVec::try_from(b"audit".to_vec()).unwrap(),
			};
			AuditRepository::store_disclosure_request::<Test>(20u64, 10u64, req);
			assert!(AuditRepository::has_disclosure_request::<Test>(
				&20u64, &10u64
			));
			assert!(AuditRepository::get_disclosure_request::<Test>(&20u64, &10u64).is_some());
		});
	}

	#[test]
	fn audit_repo_disclosure_request_remove() {
		new_test_ext().execute_with(|| {
			let req = DisclosureRequest {
				auditor: 11u64,
				target: 21u64,
				requested_at: 2u64,
				expires_at: 2000u64,
				reason: BoundedVec::try_from(b"test".to_vec()).unwrap(),
			};
			AuditRepository::store_disclosure_request::<Test>(21u64, 11u64, req);
			AuditRepository::remove_disclosure_request::<Test>(&21u64, &11u64);
			assert!(!AuditRepository::has_disclosure_request::<Test>(
				&21u64, &11u64
			));
		});
	}

	#[test]
	fn audit_repo_disclosure_record_store_and_has() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x30);
			let record = DisclosureRecord {
				revealed_value: Some(100u64),
				revealed_asset_id: Some(0),
				revealed_owner_hash: None,
				requester: 5u64,
				timestamp: 1u64,
			};
			assert_ok!(AuditRepository::store_disclosure_record::<Test>(
				c, &5u64, record
			));
			assert!(AuditRepository::has_disclosure_record::<Test>(c, &5u64));
		});
	}

	#[test]
	fn audit_repo_disclosure_record_duplicate_fails() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x31);
			let record = DisclosureRecord {
				revealed_value: None,
				revealed_asset_id: None,
				revealed_owner_hash: None,
				requester: 6u64,
				timestamp: 1u64,
			};
			AuditRepository::store_disclosure_record::<Test>(c, &6u64, record.clone()).unwrap();
			assert!(AuditRepository::store_disclosure_record::<Test>(c, &6u64, record).is_err());
		});
	}

	#[test]
	fn audit_repo_audit_trail_id_increments() {
		new_test_ext().execute_with(|| {
			let id0 = AuditRepository::get_next_audit_trail_id::<Test>();
			let returned = AuditRepository::increment_audit_trail_id::<Test>();
			let id1 = AuditRepository::get_next_audit_trail_id::<Test>();
			assert_eq!(returned, id0);
			assert_eq!(id1, id0 + 1);
		});
	}

	#[test]
	fn audit_repo_create_audit_trail_stores_entry() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x40);
			let hash =
				AuditRepository::create_audit_trail::<Test>(&1u64, &2u64, c, b"full_disclosure")
					.unwrap();
			let trail = AuditRepository::get_audit_trail::<Test>(&hash).unwrap();
			assert_eq!(trail.account, 1u64);
			assert_eq!(trail.auditor, 2u64);
		});
	}

	#[test]
	fn audit_repo_disclosure_counter_starts_at_zero_and_increments() {
		new_test_ext().execute_with(|| {
			assert_eq!(
				AuditRepository::get_disclosure_counter::<Test>(&1u64, &2u64),
				0
			);
			AuditRepository::increment_disclosure_counter::<Test>(&1u64, &2u64);
			assert_eq!(
				AuditRepository::get_disclosure_counter::<Test>(&1u64, &2u64),
				1
			);
			AuditRepository::increment_disclosure_counter::<Test>(&1u64, &2u64);
			assert_eq!(
				AuditRepository::get_disclosure_counter::<Test>(&1u64, &2u64),
				2
			);
		});
	}

	#[test]
	fn audit_repo_rate_limit_timestamp_store_and_retrieve() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x50);
			assert!(AuditRepository::get_last_disclosure_timestamp::<Test>(&1u64, c).is_none());
			AuditRepository::update_disclosure_timestamp::<Test>(&1u64, c, 999u64);
			assert_eq!(
				AuditRepository::get_last_disclosure_timestamp::<Test>(&1u64, c),
				Some(999u64)
			);
		});
	}

	#[test]
	fn audit_repo_has_commitment_memo_returns_correct() {
		new_test_ext().execute_with(|| {
			let c = test_commitment(0x60);
			assert!(!AuditRepository::has_commitment_memo::<Test>(c));
			CommitmentRepository::store_memo::<Test>(c, test_memo());
			assert!(AuditRepository::has_commitment_memo::<Test>(c));
		});
	}

	fn _suppress_unused(_: DisclosureCondition<u128, u64>, _: ConstU32<10>) {}
}
