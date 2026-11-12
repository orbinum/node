// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Orbinum privacy stack: the ZK verifier and the shielded pool.
//!
//! The reasoning behind each bound lives on the pallet's `Config`.

use crate::{
	configs::{
		consensus::ValidatorAccountAuthor,
		governance::{CircuitAdmin, ShieldedAssetAdmin},
	},
	Balances, Runtime, ZkVerifier,
};
use frame_support::{
	parameter_types,
	traits::{ConstU128, ConstU32, ConstU8},
	PalletId,
};

// ZK verifier

impl pallet_zk_verifier::Config for Runtime {
	/// A compressed Groth16 proof over BN254: exactly 128 bytes.
	type MaxProofSize = ConstU32<128>;
	/// Public inputs `verify_proof` takes at most; the widest circuit has 9.
	type MaxPublicInputs = ConstU32<32>;
	type AdminOrigin = CircuitAdmin;
	type WeightInfo = pallet_zk_verifier::weights::SubstrateWeight<Runtime>;
}

// Shielded pool

parameter_types! {
	pub const ShieldedPoolPalletId: PalletId = PalletId(*b"shld/pol");
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
	type AdminOrigin = ShieldedAssetAdmin;
	type WeightInfo = pallet_shielded_pool::weights::SubstrateWeight<Runtime>;
}
