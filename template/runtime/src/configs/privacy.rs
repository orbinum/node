//! Orbinum privacy stack: ZK verifier and the shielded pool.
//!
//! One `///` line per associated type: what it is wired to, or what the value
//! means. The reasoning behind each bound lives on the pallet's `Config`.

use crate::*;
use frame_support::parameter_types;

// ─── ZK verifier ──────────────────────────────────────────────────────────────

impl pallet_zk_verifier::Config for Runtime {
	/// A compressed Groth16 proof over BN254: exactly 128 bytes.
	type MaxProofSize = ConstU32<128>;
	/// Public inputs `verify_proof` takes at most; the widest circuit has 9.
	type MaxPublicInputs = ConstU32<32>;
	/// Benchmarked weights.
	type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Runtime>;
}

// ─── Shielded pool ────────────────────────────────────────────────────────────

parameter_types! {
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shld/pol");
}

/// The validator account that authored the current block, as `pallet_authorship`
/// reports it through `ValidatorAuthor`.
pub struct ValidatorAccountAuthor;

impl frame_support::traits::Get<Option<AccountId>> for ValidatorAccountAuthor {
	fn get() -> Option<AccountId> {
		let author = pallet_authorship::Pallet::<Runtime>::author();
		// A benchmark block carries no Aura pre-digest, so it has no author.
		#[cfg(feature = "runtime-benchmarks")]
		let author = author.or(Some(AccountId::from([0xbe; 32])));
		author
	}
}

impl pallet_shielded_pool::Config for Runtime {
	/// The native token: the pool holds only asset 0.
	type Currency = Balances;
	/// Verifies every shield, transfer and unshield proof.
	type ZkVerifier = ZkVerifier;
	/// Earns each spend's fee: the validator that authored the block.
	type BlockAuthor = ValidatorAccountAuthor;
	/// Spend fee floor: 0.001 ORB, against spam.
	type MinSpendFee = ConstU128<1_000_000_000_000_000>;
	/// Derives the pool's account, which holds every shielded deposit.
	type PalletId = ShieldedPoolPalletId;
	/// Tree depth, fixed by the circuits (`integrity_test` pins it).
	type MaxTreeDepth = ConstU32<20>;
	/// Leaves per tree, pinned to 2^20: clients derive `tree_id = leaf_index >> 20`.
	type MaxLeavesPerTree = ConstU32<1_048_576>;
	/// Sealed trees keep nodes from level 6 up: a path reads 62 leaves, not 1_022.
	type SealedTreePrunedBelowLevel = ConstU8<6>;
	/// A root stays spendable for 300 blocks (~30 min), past the mempool's 64.
	type RootRetentionBlocks = ConstU32<300>;
	/// Safety cap on the historic-root queue: ~27 inserts per block over a window.
	type MaxHistoricRoots = ConstU32<16384>;
	/// Benchmarked weights.
	type WeightInfo = pallet_shielded_pool::weights::SubstrateWeight<Runtime>;
}
