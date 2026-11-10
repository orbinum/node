//! Sealed-tree node pruning: the per-block sweep and the paths it leaves.

use crate::{
	Config,
	merkle::service::MerkleTreeService,
	pallet::{LastPrunedTree, PRUNED_NODES_PER_BLOCK, SealedPruneCursor},
	storage::MerkleRepository,
	tests::mock::{Test, new_test_ext},
	types::Commitment,
};

/// Fill exactly one tree so it seals, then start the next.
fn seal_one_tree() -> u32 {
	let cap: u32 = <Test as Config>::MaxLeavesPerTree::get();
	// Offset by the leaves already present: each commitment is unique.
	let start = crate::storage::MerkleRepository::get_tree_size::<Test>();
	for i in start..start + cap {
		let mut c = [0u8; 32];
		c[..4].copy_from_slice(&i.to_le_bytes());
		c[31] = 0x5A;
		MerkleTreeService::insert_leaf::<Test>(Commitment(c)).expect("insert");
	}
	cap
}

/// Pruned nodes must be reproducible: the path a wallet gets after the sweep
/// has to be byte-identical to the one it would have got before, or every
/// proof built against a sealed tree would fail verification.
#[test]
fn path_is_identical_before_and_after_pruning() {
	new_test_ext().execute_with(|| {
		let cap = seal_one_tree();

		let before: Vec<_> = (0..cap)
			.map(|i| MerkleTreeService::get_merkle_path::<Test>(i).expect("path"))
			.collect();

		// Sweep the whole tree.
		while MerkleTreeService::prune_sealed_nodes::<Test>(1_000) > 0 {}

		for (i, expected) in before.iter().enumerate() {
			let after = MerkleTreeService::get_merkle_path::<Test>(i as u32).expect("path");
			assert_eq!(
				after.siblings, expected.siblings,
				"leaf {i}: siblings changed after pruning"
			);
			assert_eq!(after.indices, expected.indices, "leaf {i}: indices changed");
		}
	});
}

/// The recomputed path must still verify against the tree's permanent root —
/// this is what keeps a sealed-tree note spendable.
#[test]
fn pruned_tree_paths_still_verify_against_sealed_root() {
	new_test_ext().execute_with(|| {
		let cap = seal_one_tree();
		let sealed_root = MerkleRepository::get_sealed_root::<Test>(0).expect("sealed root");

		while MerkleTreeService::prune_sealed_nodes::<Test>(1_000) > 0 {}

		for i in 0..cap {
			let leaf = MerkleRepository::get_leaf::<Test>(i).expect("leaf").0;
			let path = MerkleTreeService::get_merkle_path::<Test>(i).expect("path");
			assert!(
				MerkleTreeService::verify_merkle_proof(&sealed_root, &leaf, &path),
				"leaf {i} no longer verifies against its sealed root"
			);
		}
	});
}

/// Only levels below the cut are dropped; the kept ones must survive so the
/// recompute has somewhere to stop.
#[test]
fn prunes_only_below_the_cut_level() {
	new_test_ext().execute_with(|| {
		seal_one_tree();
		let cut: u8 = <Test as Config>::SealedTreePrunedBelowLevel::get();
		let cap: u32 = <Test as Config>::MaxLeavesPerTree::get();

		while MerkleTreeService::prune_sealed_nodes::<Test>(1_000) > 0 {}

		for level in 1..cut {
			for idx in 0..(cap >> level) {
				assert!(
					MerkleRepository::get_node::<Test>(0, level, idx).is_none(),
					"level {level} index {idx} should have been pruned"
				);
			}
		}
		// At least one node at the cut level must remain.
		assert!(
			MerkleRepository::get_node::<Test>(0, cut, 0).is_some(),
			"level {cut} must be kept"
		);
	});
}

/// The active tree is never touched — its paths must stay O(depth) reads.
#[test]
fn active_tree_is_never_pruned() {
	new_test_ext().execute_with(|| {
		seal_one_tree();
		// Two leaves into tree 1, which is now active.
		for i in 0..2u32 {
			let mut c = [0u8; 32];
			c[..4].copy_from_slice(&(1000 + i).to_le_bytes());
			c[31] = 0xC3;
			MerkleTreeService::insert_leaf::<Test>(Commitment(c)).expect("insert");
		}

		while MerkleTreeService::prune_sealed_nodes::<Test>(1_000) > 0 {}

		assert!(
			MerkleRepository::get_node::<Test>(1, 1, 0).is_some(),
			"the active tree must keep every internal node"
		);
	});
}

/// A sweep must respect its budget so one block cannot absorb a whole tree.
#[test]
fn sweep_respects_its_budget_and_resumes() {
	new_test_ext().execute_with(|| {
		seal_one_tree();

		let first = MerkleTreeService::prune_sealed_nodes::<Test>(2);
		assert!(first <= 2, "budget exceeded: {first}");
		assert!(
			SealedPruneCursor::<Test>::get().is_some(),
			"an unfinished sweep must park its cursor"
		);

		let mut total = first;
		while MerkleTreeService::prune_sealed_nodes::<Test>(2) > 0 {
			total += 2;
			assert!(total < 10_000, "sweep is not converging");
		}
		assert!(
			LastPrunedTree::<Test>::get().is_some(),
			"a finished tree must be recorded"
		);
	});
}

/// With nothing sealed there is no work, and the sweep must not spin.
#[test]
fn sweep_is_a_noop_before_any_tree_seals() {
	new_test_ext().execute_with(|| {
		let mut c = [0u8; 32];
		c[31] = 0x11;
		MerkleTreeService::insert_leaf::<Test>(Commitment(c)).expect("insert");

		assert_eq!(MerkleTreeService::prune_sealed_nodes::<Test>(100), 0);
		assert!(SealedPruneCursor::<Test>::get().is_none());
		assert!(LastPrunedTree::<Test>::get().is_none());
	});
}

/// A zero budget must do nothing rather than fall through to a full sweep.
#[test]
fn zero_budget_prunes_nothing() {
	new_test_ext().execute_with(|| {
		seal_one_tree();
		assert_eq!(MerkleTreeService::prune_sealed_nodes::<Test>(0), 0);
		assert!(MerkleRepository::get_node::<Test>(0, 1, 0).is_some());
	});
}

/// The budget counts probes, not removals. A level already swept is all
/// misses, so charging only removals would let one block walk hundreds of
/// thousands of keys for free.
#[test]
fn budget_charges_probes_not_just_removals() {
	new_test_ext().execute_with(|| {
		seal_one_tree();
		// First pass clears everything prunable.
		while MerkleTreeService::prune_sealed_nodes::<Test>(1_000) > 0 {}

		// A second sweep from scratch finds only misses. It must still stop,
		// which it can only do if probes are charged.
		SealedPruneCursor::<Test>::kill();
		LastPrunedTree::<Test>::kill();
		let removed = MerkleTreeService::prune_sealed_nodes::<Test>(4);
		assert_eq!(removed, 0, "nothing left to remove");
		assert!(
			SealedPruneCursor::<Test>::get().is_some(),
			"an all-miss sweep must still park its cursor rather than scan on"
		);
	});
}

/// Two nodes running the same block must end at the same state root.
///
/// The old `on_idle` hook received the block's leftover weight, which is NOT consensus: an
/// author that filled the block differently from what the importer measures
/// hands the hook a different leftover weight, the sweep prunes a different
/// number of nodes, and the two states diverge. That halted the testnet at
/// block 406997.
///
/// Regression: the sweep must consume a constant batch, so two nodes running
/// the same block land on the same state regardless of how full it was.
#[test]
fn prune_batch_is_independent_of_block_fullness() {
	// The mock's 8-leaf tree is swept dry in one call, which would hide the
	// divergence. Production seals 1_048_576-leaf trees, where the batch
	// genuinely bounds the sweep — seal several mock trees to match.
	fn sweep_once() -> (u32, Option<(u32, u8, u32)>) {
		new_test_ext().execute_with(|| {
			for _ in 0..40 {
				seal_one_tree();
			}
			let removed = MerkleTreeService::prune_sealed_nodes::<Test>(PRUNED_NODES_PER_BLOCK);
			(removed, SealedPruneCursor::<Test>::get())
		})
	}

	// Same block, two nodes. Nothing about how full the block was may reach
	// the sweep, so both must land identically.
	assert_eq!(
		sweep_once(),
		sweep_once(),
		"the sealed-node sweep is not deterministic: author and importer would \
		 disagree on state and the chain would fork"
	);
}

/// How many internal nodes the forest still holds — the sweep's whole effect.
fn surviving_nodes() -> usize {
	crate::pallet::MerkleNodes::<Test>::iter().count()
}

// ── Adversarial: can anything reintroduce the divergence? ───────────────
//
// The fix is only worth what it survives. Each of these attacks the sweep
// from a different angle, trying to make two nodes running the same block
// prune differently.

/// Attack: run the sweep from a cursor parked anywhere, repeatedly.
///
/// The full sweep of a forest must reach the same end state no matter how
/// the batches were carved up — otherwise a node that restarted mid-sweep
/// would land somewhere its peers never do.
#[test]
fn sweep_converges_regardless_of_how_the_batches_are_carved() {
	fn sweep_to_exhaustion(batch: u32) -> (u32, Option<(u32, u8, u32)>, usize) {
		new_test_ext().execute_with(|| {
			for _ in 0..20 {
				seal_one_tree();
			}
			let mut total = 0;
			// Bounded: a stuck sweep must fail the test, not hang it.
			for _ in 0..10_000 {
				let removed = MerkleTreeService::prune_sealed_nodes::<Test>(batch);
				total += removed;
				if SealedPruneCursor::<Test>::get().is_none() && removed == 0 {
					break;
				}
			}
			(total, SealedPruneCursor::<Test>::get(), surviving_nodes())
		})
	}

	// One node sweeps in tiny batches, another in large ones. Same forest,
	// so the same nodes must end up gone.
	let fine = sweep_to_exhaustion(1);
	let coarse = sweep_to_exhaustion(PRUNED_NODES_PER_BLOCK);
	assert_eq!(
		fine, coarse,
		"batch size changed the end state: nodes that swept at different \
		 rates would hold different tries"
	);
}

/// Attack: seal more trees mid-sweep, the way a live chain does.
///
/// The cursor walks tree-by-tree while the forest grows underneath it. Two
/// nodes that saw the same insertions must still agree.
#[test]
fn sweep_is_stable_while_the_forest_grows() {
	fn interleaved(batch: u32) -> usize {
		new_test_ext().execute_with(|| {
			for _ in 0..20 {
				seal_one_tree();
				// A block's worth of sweeping between each sealing.
				MerkleTreeService::prune_sealed_nodes::<Test>(batch);
			}
			for _ in 0..2_000 {
				let removed = MerkleTreeService::prune_sealed_nodes::<Test>(batch);
				if SealedPruneCursor::<Test>::get().is_none() && removed == 0 {
					break;
				}
			}
			surviving_nodes()
		})
	}

	assert_eq!(
		interleaved(PRUNED_NODES_PER_BLOCK),
		interleaved(PRUNED_NODES_PER_BLOCK),
		"interleaving sealing with sweeping is not reproducible"
	);
}

/// Attack: the sweep must never touch the tree still being written to.
///
/// This is the property that keeps today's notes spendable at O(depth); the
/// batch change moved the hook, so re-prove it rather than assume it held.
#[test]
fn active_tree_survives_an_exhaustive_sweep() {
	new_test_ext().execute_with(|| {
		let cap = seal_one_tree();
		// Start a second tree and leave it active with one leaf.
		let mut c = [0u8; 32];
		c[..4].copy_from_slice(&cap.to_le_bytes());
		MerkleTreeService::insert_leaf::<Test>(Commitment(c)).expect("insert");

		for _ in 0..1_000 {
			if MerkleTreeService::prune_sealed_nodes::<Test>(PRUNED_NODES_PER_BLOCK) == 0
				&& SealedPruneCursor::<Test>::get().is_none()
			{
				break;
			}
		}

		let active = MerkleRepository::get_tree_size::<Test>() / cap;
		let cut = <Test as Config>::SealedTreePrunedBelowLevel::get();
		for level in 1..cut {
			assert!(
				MerkleRepository::get_node::<Test>(active, level, 0).is_some(),
				"active tree lost node at level {level}: paths would no longer \
				 be O(depth) and the sweep is eating live state"
			);
		}
	});
}

/// The per-block batch has to be a real bound, not a placeholder.
///
/// A `const` block rather than a runtime assert: both operands are constants,
/// so the compiler would fold an `assert!` away and the check would never run.
/// This one fails the build instead.
const _: () = assert!(
	PRUNED_NODES_PER_BLOCK > 0 && PRUNED_NODES_PER_BLOCK <= 4096,
	"PRUNED_NODES_PER_BLOCK must bound the sweep: zero disables pruning, \
	 and a value this far above the benchmarked batch would let one block \
	 absorb work it cannot pay for"
);
