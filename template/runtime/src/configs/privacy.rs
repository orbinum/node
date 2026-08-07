//! Orbinum privacy stack: ZK verifier, relayer, and the shielded pool.
//!
//! The shielded-pool constants carry real operational weight — the retention
//! window must outlive mempool longevity, and the prune level trades storage
//! against how long a Merkle path takes to rebuild. Both are documented at the
//! point of use below.

use crate::*;
use frame_support::parameter_types;

impl pallet_zk_verifier::Config for Runtime {
	type MaxProofSize = ConstU32<128>;
	type MaxPublicInputs = ConstU32<32>;
	type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Runtime>;
}

// ────────────────────────────────────────────────────────────────────────────
// pallet-relayer
// ────────────────────────────────────────────────────────────────────────────

/// Provides the current block's author (Aura validator) for relay fee attribution.
pub struct RelayerBlockAuthor;
impl frame_support::traits::Get<Option<AccountId>> for RelayerBlockAuthor {
	fn get() -> Option<AccountId> {
		pallet_authorship::Pallet::<Runtime>::author()
	}
}

impl pallet_relayer::Config for Runtime {
	/// Block author for relay fee attribution.
	type BlockAuthor = RelayerBlockAuthor;
	/// Default minimum relay fee: 0.001 ORB = 1e15 planck (anti-spam).
	/// Overridable at runtime via `set_min_relay_fee` (governance/sudo).
	type DefaultMinRelayFee = ConstU128<1_000_000_000_000_000>;
	/// Only sudo/governance can update relay configuration.
	type ManageOrigin = frame_system::EnsureRoot<AccountId>;
	/// Allow up to 16 ABI selectors in the whitelist.
	type MaxAllowedSelectors = ConstU32<16>;
	type WeightInfo = ();
}

parameter_types! {
	/// Pool account that holds all shielded tokens
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shld/pol");
}

impl pallet_shielded_pool::Config for Runtime {
	/// Native currency (ORB) for shield/unshield operations
	type Currency = Balances;
	/// Groth16 proof verifier for unshield/transfer operations
	type ZkVerifier = ZkVerifier;
	/// Relay config, fee accumulation and block-author — delegated to pallet-relayer.
	type Relayer = pallet_relayer::Pallet<Runtime>;
	/// PalletId for the pool account
	type PalletId = ShieldedPoolPalletId;
	/// Merkle tree depth: 2^20 = 1M notes max (see MERKLE_TREE_SCALABILITY.md)
	type MaxTreeDepth = ConstU32<20>;
	/// Historic roots: allows proofs against past states (30s window)
	/// Safety cap on the historic-root queue, not the retention window. A root
	/// expires by elapsed blocks; this only bounds worst-case storage.
	///
	/// Steady state is `RootRetentionBlocks × commitments-per-block`: 1200 at a
	/// sustained 2 transfers/block, 6000 at 10. Sized for ~27 transfers/block
	/// sustained across a full window, well past the ~127 proof verifications a
	/// block can fit, so the window — never this bound — is what expires a root.
	type MaxHistoricRoots = ConstU32<16384>;
	/// Roots stay spendable for 300 blocks (~30 min at 6s), comfortably above
	/// the 64-block mempool longevity of an unsigned transaction.
	type RootRetentionBlocks = ConstU32<300>;
	// Pinned to 2^20: clients derive tree_id = leaf_index >> 20 from this.
	type MaxLeavesPerTree = ConstU32<1_048_576>;
	type WeightInfo = pallet_shielded_pool::weights::SubstrateWeight<Runtime>;
}

// Create the runtime by composing the FRAME pallets that were previously configured.
