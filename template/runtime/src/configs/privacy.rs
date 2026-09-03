//! Orbinum privacy stack: ZK verifier, relayer, and the shielded pool.

use crate::*;
use frame_support::parameter_types;

impl pallet_zk_verifier::Config for Runtime {
	type MaxProofSize = ConstU32<128>;
	type MaxPublicInputs = ConstU32<32>;
	type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Runtime>;
}

pub struct RelayerBlockAuthor;
impl frame_support::traits::Get<Option<AccountId>> for RelayerBlockAuthor {
	fn get() -> Option<AccountId> {
		pallet_authorship::Pallet::<Runtime>::author()
	}
}

impl pallet_relayer::Config for Runtime {
	type BlockAuthor = RelayerBlockAuthor;
	/// 0.001 ORB, anti-spam floor. Overridable via `set_min_relay_fee`.
	type DefaultMinRelayFee = ConstU128<1_000_000_000_000_000>;
	/// Ceiling for `set_min_relay_fee`: 1 ORB. Room to react to price swings, far below
	/// where a typo would brick relaying until the next runtime upgrade.
	type MaxMinRelayFee = ConstU128<1_000_000_000_000_000_000>;
	type ManageOrigin = frame_system::EnsureRoot<AccountId>;
	type MaxAllowedSelectors = ConstU32<16>;
	type ValidatorSet = ValidatorSet;
	type WeightInfo = ();
}

parameter_types! {
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shld/pol");
}

impl pallet_shielded_pool::Config for Runtime {
	type Currency = Balances;
	type ZkVerifier = ZkVerifier;
	type Relayer = pallet_relayer::Pallet<Runtime>;
	type PalletId = ShieldedPoolPalletId;
	type MaxTreeDepth = ConstU32<20>;
	/// Safety cap on the historic-root queue, not the retention window: a root expires by
	/// elapsed blocks, so `RootRetentionBlocks` is what frees one. Sized for ~27
	/// transfers/block sustained across a full window, well past the ~127 proof
	/// verifications a block can fit.
	type MaxHistoricRoots = ConstU32<16384>;
	/// Roots stay spendable for 300 blocks (~30 min at 6s), comfortably above
	/// the 64-block mempool longevity of an unsigned transaction.
	type RootRetentionBlocks = ConstU32<300>;
	/// Prune sealed trees below level 10: drops 99.8% of their internal nodes
	/// (1_048_574 -> 2_046 each) while a Merkle path costs 2^10 leaf reads and
	/// 1_023 Poseidon hashes — ~60ms native, ~180ms in Wasm. Level 12 would free
	/// only 0.15% more for four times the work. Active trees are never pruned.
	type SealedTreePrunedBelowLevel = ConstU8<10>;
	// Pinned to 2^20: clients derive tree_id = leaf_index >> 20 from this.
	type MaxLeavesPerTree = ConstU32<1_048_576>;
	type WeightInfo = pallet_shielded_pool::weights::SubstrateWeight<Runtime>;
}
