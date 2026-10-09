//! Orbinum privacy stack: ZK verifier, relayer, and the shielded pool.
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

// ─── Relayer ──────────────────────────────────────────────────────────────────

/// The current block's author, as `pallet_authorship` reports it.
pub struct RelayerBlockAuthor;

impl frame_support::traits::Get<Option<AccountId>> for RelayerBlockAuthor {
	fn get() -> Option<AccountId> {
		pallet_authorship::Pallet::<Runtime>::author()
	}
}

impl pallet_relayer::Config for Runtime {
	/// Who earns a spend's fee when no relayer committed to it.
	type BlockAuthor = RelayerBlockAuthor;
	/// The validator set relayers are registered against.
	type ValidatorSet = ValidatorSet;
	/// Root sets the fee floor and the allowed selectors.
	type ManageOrigin = frame_system::EnsureRoot<AccountId>;
	/// Fee floor until Root sets one: 0.001 ORB, against spam.
	type DefaultMinRelayFee = ConstU128<1_000_000_000_000_000>;
	/// Highest floor Root may set: 1 ORB, room for price swings but not for typos.
	type MaxMinRelayFee = ConstU128<1_000_000_000_000_000_000>;
	/// Precompile selectors the relay may be allowed to call.
	type MaxAllowedSelectors = ConstU32<16>;
	/// A commit credits spends for the next 19 blocks (~2 min), then expires.
	type CommitTtl = ConstU32<20>;
	/// Commits one relayer may record per block.
	type MaxCommitsPerRelayerPerBlock = ConstU32<64>;
	/// No benchmarked weights yet: the pallet's defaults.
	type WeightInfo = ();
}

// ─── Shielded pool ────────────────────────────────────────────────────────────

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
	/// The native token: the pool holds only asset 0.
	type Currency = Balances;
	/// Verifies every shield, transfer and unshield proof.
	type ZkVerifier = ZkVerifier;
	/// Fee floor, relay commits and fee crediting.
	type Relayer = pallet_relayer::Pallet<Runtime>;
	/// Maps an EVM caller to the account it pays from or is paid to.
	type EvmAccount = EvmAccount;
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
