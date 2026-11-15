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
	/// What a `bound_spend` can do: see [`BoundAction`].
	type BoundActions = BoundRouter;
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

// Bound actions

/// What a shielded note can be spent for, through `ShieldedPool.bound_spend`. The
/// proof binds the encoded action, so each variant keeps its index for good.
#[derive(
	Clone,
	PartialEq,
	Eq,
	scale_codec::Encode,
	scale_codec::Decode,
	scale_codec::DecodeWithMemTracking,
	scale_codec::MaxEncodedLen,
	scale_info::TypeInfo,
	Debug
)]
pub enum BoundAction {
	/// Enter or leave a nomination pool privately (`staking::private`).
	#[codec(index = 0)]
	PrivateStaking(crate::staking::private::Action),
}

/// Sends each bound action to the pallet that runs it.
pub struct BoundRouter;

type PrivateStaking = crate::staking::private::Pallet<Runtime>;

/// Whether `asset_id` is issued by private staking: the router hands a pallet-backed
/// asset only to the pallet that issues it.
fn issued_by_private_staking(asset_id: u32) -> bool {
	pallet_shielded_pool::Assets::<Runtime>::get(asset_id).is_some_and(|asset| {
		asset.backend
			== pallet_shielded_pool::types::AssetBackend::Pallet(
				<Runtime as crate::staking::private::Config>::PrivateStakingId::get().0,
			)
	})
}

impl pallet_shielded_pool::BoundActions<crate::AccountId> for BoundRouter {
	type Action = BoundAction;

	fn executor(action: &BoundAction) -> Option<crate::AccountId> {
		let BoundAction::PrivateStaking(action) = action;
		<PrivateStaking as pallet_shielded_pool::BoundActions<_>>::executor(action)
	}

	fn is_executor(who: &crate::AccountId) -> bool {
		<PrivateStaking as pallet_shielded_pool::BoundActions<_>>::is_executor(who)
	}

	fn min_fee(asset_id: u32) -> Option<u128> {
		if !issued_by_private_staking(asset_id) {
			return None;
		}
		<PrivateStaking as pallet_shielded_pool::BoundActions<crate::AccountId>>::min_fee(asset_id)
	}

	fn validate(
		action: &BoundAction,
		asset_id: u32,
		amount: u128,
		fee: u128,
	) -> frame_support::dispatch::DispatchResult {
		let BoundAction::PrivateStaking(action) = action;
		<PrivateStaking as pallet_shielded_pool::BoundActions<_>>::validate(
			action, asset_id, amount, fee,
		)
	}

	fn execute(
		action: BoundAction,
		asset_id: u32,
		amount: u128,
		fee: u128,
	) -> frame_support::dispatch::DispatchResult {
		let BoundAction::PrivateStaking(action) = action;
		<PrivateStaking as pallet_shielded_pool::BoundActions<_>>::execute(
			action, asset_id, amount, fee,
		)
	}

	fn weight(action: &BoundAction) -> frame_support::weights::Weight {
		let BoundAction::PrivateStaking(action) = action;
		<PrivateStaking as pallet_shielded_pool::BoundActions<_>>::weight(action)
	}

	fn redeem_fees(
		validator: &crate::AccountId,
		asset_id: u32,
		amount: u128,
	) -> frame_support::dispatch::DispatchResult {
		frame_support::ensure!(
			issued_by_private_staking(asset_id),
			sp_runtime::DispatchError::Other("no pallet issues this asset")
		);
		<PrivateStaking as pallet_shielded_pool::BoundActions<_>>::redeem_fees(
			validator, asset_id, amount,
		)
	}
	fn redeem_fees_weight() -> frame_support::weights::Weight {
		<PrivateStaking as pallet_shielded_pool::BoundActions<crate::AccountId>>::redeem_fees_weight(
		)
	}
}
