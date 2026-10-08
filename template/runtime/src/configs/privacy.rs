//! Orbinum privacy stack: ZK verifier, relayer, and the shielded pool.

use crate::*;
use frame_support::parameter_types;

impl pallet_zk_verifier::Config for Runtime {
	type MaxProofSize = ConstU32<128>;
	type MaxPublicInputs = ConstU32<32>;
	type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Runtime>;
}

/// The current block's author, as `pallet_authorship` reports it.
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
	/// A relay commit credits spends in the next 19 blocks (~2 min at 6 s), then
	/// expires. Short, since a relayer that commits and never submits holds that
	/// spend's fee until then.
	type CommitTtl = ConstU32<20>;
	/// Covers a busy relayer's block; keeps the expiry index at ≤ 32 × 64 entries.
	type MaxCommitsPerRelayerPerBlock = ConstU32<64>;
	type WeightInfo = ();
}

parameter_types! {
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shld/pol");
}

/// The account an EVM address controls, per the runtime's address mapping.
pub struct EvmAccount;

impl sp_runtime::traits::Convert<sp_core::H160, AccountId> for EvmAccount {
	fn convert(address: sp_core::H160) -> AccountId {
		crate::evm_account::evm_h160_to_account_id(address)
	}
}

impl pallet_shielded_pool::Config for Runtime {
	type Currency = Balances;
	type ZkVerifier = ZkVerifier;
	type Relayer = pallet_relayer::Pallet<Runtime>;
	type EvmAccount = EvmAccount;
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
	/// Prune sealed trees below level 6: keeps 32_766 of their 1_048_574 internal
	/// nodes (2^(21−c) − 2) while a Merkle path rebuilds its pruned siblings from
	/// 62 leaves (2^c − 2) — ~11ms in Wasm. Level 10 kept 2_046 nodes but cost
	/// 1_022 leaf reads per path (~180ms), cheap enough to flood the public RPC
	/// with. Lowering this on a live chain is safe: a node pruned under a higher
	/// cut is rebuilt on demand. Active trees are never pruned.
	type SealedTreePrunedBelowLevel = ConstU8<6>;
	/// Pinned to 2^20: clients derive tree_id = leaf_index >> 20 from this.
	type MaxLeavesPerTree = ConstU32<1_048_576>;
	type WeightInfo = pallet_shielded_pool::weights::SubstrateWeight<Runtime>;
}
