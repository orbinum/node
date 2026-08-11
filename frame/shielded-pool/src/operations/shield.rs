//! `shield` — moving public tokens into the shielded pool.
//!
//! The one operation with NO proof: the depositor names the commitment their
//! note will have, and nothing constrains those bytes. Everything the other
//! calls get from the circuit has to be checked explicitly here, which makes
//! this the least guarded way into the Merkle tree.
//!
//! ## Order of steps
//!
//! Numbered below. The split matters: every validation (steps 1–3) runs BEFORE
//! the fund transfer (step 4), so a rejected shield never moves money. After
//! step 4 the operation must not fail — `?` on any later step would leave the
//! tokens in the pool account with no note to claim them. Storage is rolled
//! back on error, so the danger is not a partial write; it is that the
//! post-transfer steps are all infallible by construction.
//!
//! | # | Step                          | Fallible |
//! |---|-------------------------------|----------|
//! | 1 | asset is registered, verified | yes      |
//! | 2 | amount and memo well-formed   | yes      |
//! | 3 | commitment usable and unused  | yes      |
//! | 4 | transfer funds into the pool  | yes      |
//! | 5 | insert leaf, store memo       | tree-full only |
//! | 6 | emit `Shielded`               | no       |

use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use sp_runtime::traits::Zero;

use crate::{
	merkle::MerkleTreeService,
	pallet::{Config, Error, Event, Pallet},
	storage::{AssetRepository, CommitmentRepository, PoolBalanceRepository},
	types::{Commitment, EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
};

pub struct ShieldOperation;

impl ShieldOperation {
	/// Executes a shield. Steps are numbered to match the table in the module
	/// header; the ordering around step 4 is a safety property, not style.
	pub fn execute<T: Config>(
		depositor: <T as frame_system::Config>::AccountId,
		asset_id: u32,
		amount: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		commitment: Commitment,
		encrypted_memo: EncryptedMemo,
	) -> DispatchResult {
		// ── 1. Asset ─────────────────────────────────────────────────────────
		// Unverified assets are refused: governance vets what may enter the pool.
		let asset = AssetRepository::get_asset::<T>(asset_id).ok_or(Error::<T>::InvalidAssetId)?;
		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);

		// ── 2. Amount and memo ───────────────────────────────────────────────
		// A zero-amount shield would insert a leaf and grow the tree for free.
		// The memo is exact-sized, never merely bounded — the wallet slices it at
		// fixed offsets, so a short one is a note nobody can open.
		ensure!(!amount.is_zero(), Error::<T>::InvalidAmount);
		ensure!(
			encrypted_memo.0.len() == MAX_ENCRYPTED_MEMO_SIZE as usize,
			Error::<T>::InvalidMemoSize
		);

		// ── 3. Commitment ────────────────────────────────────────────────────
		// No proof constrains these bytes, so all three checks live here:
		//   - canonical: `n` and `n + p` reduce to the same field element but are
		//     DIFFERENT storage keys, so a non-canonical spelling would give one
		//     note two identities;
		//   - non-zero: zero is the tree's empty-leaf sentinel;
		//   - unused: one commitment may occupy at most one leaf.
		ensure!(commitment.is_canonical(), Error::<T>::InvalidPublicSignals);
		ensure!(commitment.is_valid(), Error::<T>::InvalidPublicSignals);
		ensure!(
			!CommitmentRepository::exists::<T>(&commitment),
			Error::<T>::CommitmentAlreadyExists
		);

		// ── 4. Move the funds ────────────────────────────────────────────────
		// The point of no return: everything above rejects without touching
		// money. `KeepAlive` refuses to reap the depositor's account.
		T::Currency::transfer(
			&depositor,
			&Pallet::<T>::pool_account_id(),
			amount,
			ExistenceRequirement::KeepAlive,
		)?;

		// ── 5. Record the note ───────────────────────────────────────────────
		// The only way this fails is a full forest, which the `?` propagates and
		// the runtime rolls back along with the transfer above.
		let leaf_index = MerkleTreeService::insert_leaf::<T>(commitment)?;
		CommitmentRepository::store_memo::<T>(commitment, encrypted_memo.clone());
		PoolBalanceRepository::increase_balance::<T>(asset_id, amount);

		// ── 6. Announce it ───────────────────────────────────────────────────
		// `leaf_index` is what lets a scanner locate the note without walking the
		// whole tree.
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

	/// A distinct, canonical 32-byte commitment for `seed`.
	///
	/// The seed goes in the low byte rather than filling all 32: a repeated high
	/// byte puts the value above the BN254 modulus (`p` starts at 0x30), which
	/// the canonicity guard refuses. Real commitments come out of Poseidon and
	/// are always canonical.
	fn commitment(seed: u8) -> Commitment {
		let mut b = [0u8; 32];
		b[0] = seed;
		b[1] = 0xA5;
		Commitment::new(b)
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

	/// A zero commitment is refused even though zero is a canonical field value.
	///
	/// The tree represents an absent leaf with `[0u8; 32]`, so a stored zero is
	/// indistinguishable from an empty slot when `subtree_root` rebuilds a pruned
	/// level — and nobody can prove a preimage for it, so it would sit in the
	/// tree forever as dead weight. The canonicity check alone lets it through;
	/// this needs its own guard, which a dev-node probe caught missing.
	#[test]
	fn execute_zero_commitment_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			let zero = Commitment::new([0u8; 32]);
			assert!(zero.is_canonical(), "zero is canonical — that is the trap");

			assert_noop!(
				ShieldOperation::execute::<Test>(acc(1), asset_id, 500u128, zero, memo_valid()),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	/// The modular twin of a value must not be storable alongside it: both reduce
	/// to the same field element, so accepting each would give one note two
	/// identities in the tree and in the reverse index.
	#[test]
	fn execute_non_canonical_commitment_fails() {
		new_test_ext().execute_with(|| {
			use ark_bn254::Fr;
			use ark_ff::{BigInteger, PrimeField};

			let asset_id = setup_asset();

			let mut canonical = [0u8; 32];
			canonical[0] = 7;

			// n + p: same field element, different bytes.
			let p_minus_1 = (-Fr::from(1u64)).into_bigint().to_bytes_le();
			let mut twin = [0u8; 32];
			twin[..p_minus_1.len()].copy_from_slice(&p_minus_1);
			let mut carry = 1u16 + 7;
			for b in twin.iter_mut() {
				let v = *b as u16 + carry;
				*b = (v & 0xff) as u8;
				carry = v >> 8;
			}

			assert_eq!(
				Fr::from_le_bytes_mod_order(&canonical),
				Fr::from_le_bytes_mod_order(&twin),
				"the pair must reduce to one element, or this proves nothing"
			);

			assert_ok!(ShieldOperation::execute::<Test>(
				acc(1),
				asset_id,
				500u128,
				Commitment::new(canonical),
				memo_valid(),
			));
			assert_noop!(
				ShieldOperation::execute::<Test>(
					acc(1),
					asset_id,
					500u128,
					Commitment::new(twin),
					memo_valid()
				),
				crate::pallet::Error::<Test>::InvalidPublicSignals
			);
		});
	}

	#[test]
	fn execute_zero_amount_fails() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			assert_noop!(
				ShieldOperation::execute::<Test>(
					acc(1),
					asset_id,
					0u128,
					commitment(1),
					memo_valid()
				),
				crate::pallet::Error::<Test>::InvalidAmount
			);
		});
	}

	/// There is no minimum: a 1-unit shield is accepted.
	#[test]
	fn execute_accepts_smallest_non_zero_amount() {
		new_test_ext().execute_with(|| {
			let asset_id = setup_asset();
			assert_ok!(ShieldOperation::execute::<Test>(
				acc(1),
				asset_id,
				1u128,
				commitment(1),
				memo_valid(),
			));
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

	// ── batch guard ──────────────────────────────────────────────────────────

	/// An empty `shield_batch` is rejected instead of dispatching at zero weight.
	#[test]
	fn shield_batch_empty_fails() {
		use crate::mock::{RuntimeOrigin, ShieldedPool};
		new_test_ext().execute_with(|| {
			let empty = frame_support::BoundedVec::default();
			assert_noop!(
				ShieldedPool::shield_batch(RuntimeOrigin::signed(acc(1)), empty),
				crate::pallet::Error::<Test>::EmptyBatch
			);
		});
	}

	/// The benchmarked `shield_batch(n)` weight has a non-zero base and scales
	/// with n (guards against the old ad-hoc `shield()*n*0.8` that hit zero at n=0).
	#[test]
	fn shield_batch_weight_has_base_and_scales() {
		use crate::weights::WeightInfo;
		let zero = <() as WeightInfo>::shield_batch(0);
		let one = <() as WeightInfo>::shield_batch(1);
		assert!(
			zero.ref_time() > 0,
			"empty batch must still carry a base weight"
		);
		assert!(one.ref_time() > zero.ref_time(), "weight must scale with n");
	}

	/// A one-element batch must still be charged for the proof verification.
	///
	/// The check above passes for ANY positive intercept, which is too weak.
	/// `shield_batch(n)` is a line fitted over n ∈ [1,20], and where that line
	/// puts its intercept is a fitting artifact rather than a measurement: the
	/// fixed cost is dominated by ONE proof verification (~1s, the same for
	/// every n), so a fit is free to park it in the slope instead. When it does,
	/// short batches — the ones worth spamming — get under-priced, and the
	/// intercept alone (41.8 ms here) is nowhere near a verification.
	///
	/// So the assertion is on the total charged at n=1, not on the intercept,
	/// anchored against `shield()` — which covers the same single verification
	/// and single insert, so it holds wherever the fit moves the split.
	///
	/// Execution time only, deliberately: `shield()` writes 34 storage entries
	/// against `shield_batch(1)`'s 33, so their DB weights differ BY DESIGN and a
	/// raw `ref_time()` comparison would fail on that gap instead of on the thing
	/// under test.
	#[test]
	fn shield_batch_of_one_is_charged_for_a_proof_verification() {
		use crate::weights::WeightInfo;
		use frame_support::weights::constants::RocksDbWeight;

		// The DB term has to come off both sides first. It is ~3.7 Gwt against an
		// execution time of ~1 Gwt, so a comparison on raw `ref_time()` is
		// dominated by storage access and stays green even when the execution
		// component collapses to nothing — which is precisely the regression
		// this test exists to catch.
		let db = |r: u64, w: u64| RocksDbWeight::get().read * r + RocksDbWeight::get().write * w;
		// Read/write counts come from the benchmark header above each weight fn.
		let batch_exec = <() as WeightInfo>::shield_batch(1).ref_time() - db(15 + 2, 27 + 6);
		let single_exec = <() as WeightInfo>::shield().ref_time() - db(17, 34);

		// One verification either way, so they must land in the same ballpark.
		// Half is a deliberately loose floor: it tolerates the spread between two
		// separate benchmark runs while still failing hard if the fit has moved
		// the fixed cost into the slope (which drops this by ~25×).
		assert!(
			batch_exec * 2 > single_exec,
			"shield_batch(1) execution time ({batch_exec} ps) is under half of \
			 shield() ({single_exec} ps) — both verify exactly one proof, so the \
			 linear fit has pushed that fixed cost out of the intercept and into \
			 the per-element slope, under-pricing short batches"
		);
	}
}
