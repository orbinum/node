//! Staking on a chain that ran without it (testnet, spec 20 → 21).
//!
//! Nobody is bonded yet, so there is nothing to elect. The migration opens era 0
//! at the current session with the current validators kept in place and eras
//! forced off (`ForceNone`): staking plans no election until governance forces
//! one after the operators bond (`staking.forceNewEra`). Otherwise an election
//! would run near the era's end whether or not anyone bonded, and one that elects
//! too few is dropped and planned again every session.
//!
//! The session side starts reporting at once (ah-client `Active`), and the
//! current set counts as applied at the current session, so an offence in era 0
//! disables its offender. Era 0 has no exposures: it pays no rewards and slashes
//! nothing.
//!
//! Nomination pools start with the bonds a new chain's genesis sets. Nominators,
//! pools, members and commission are left uncapped, as at genesis; governance
//! may cap them on-chain later.
//!
//! It touches no balance: bonding is each operator's own call.

use super::db_weight;
use crate::{
	staking::params::{
		MAX_VALIDATOR_CANDIDATES, POOL_MIN_JOIN_BOND, SLASH_REWARD_FRACTION,
		TEST_MIN_NOMINATOR_BOND, TEST_MIN_VALIDATOR_BOND, TEST_POOL_MIN_CREATE_BOND,
	},
	Runtime, Session, ValidatorSet,
};
use frame_support::{
	traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion},
	weights::Weight,
	BoundedVec,
};
use pallet_nomination_pools as pools;
use pallet_staking_async::{self as staking, ActiveEraInfo, Forcing};
use pallet_staking_async_ah_client::{self as ah_client, OperatingMode};

#[cfg(feature = "try-runtime")]
use alloc::vec::Vec;

/// See the module docs. Applies only to the network upgraded from spec 20 (testnet):
/// its validator set is still at storage version 0, and staking has no era. A new
/// chain starts at version 1 (genesis writes the in-code version) and opens era 0 at
/// genesis; this run, or one before it, leaves version 1 too. Remove it from
/// `Migrations` once spec 21 has run on testnet.
pub struct InitStaking;

impl InitStaking {
	/// Whether the chain is the spec 20 shape this migration applies to.
	fn applies() -> bool {
		ValidatorSet::on_chain_storage_version() == 0
			&& staking::CurrentEra::<Runtime>::get().is_none()
	}
}

impl OnRuntimeUpgrade for InitStaking {
	fn on_runtime_upgrade() -> Weight {
		if !Self::applies() {
			return db_weight(2, 0);
		}
		let session = Session::current_index();
		let validators = Session::validators().len() as u32;

		// As many seats as the current session has validators. A set under two thirds of them is
		// dropped and the current one stays (`MinimumValidatorSetSize`).
		staking::ValidatorCount::<Runtime>::put(validators);
		staking::MinNominatorBond::<Runtime>::put(TEST_MIN_NOMINATOR_BOND);
		staking::MinValidatorBond::<Runtime>::put(TEST_MIN_VALIDATOR_BOND);
		staking::MaxValidatorsCount::<Runtime>::put(MAX_VALIDATOR_CANDIDATES);
		staking::SlashRewardFraction::<Runtime>::put(SLASH_REWARD_FRACTION);
		// `forceNewEra` replaces it, and staking returns to `NotForcing` once that
		// era is planned.
		staking::ForceEra::<Runtime>::put(Forcing::ForceNone);

		pools::MinJoinBond::<Runtime>::put(POOL_MIN_JOIN_BOND);
		pools::MinCreateBond::<Runtime>::put(TEST_POOL_MIN_CREATE_BOND);

		// Era 0, active from now and from the current session.
		staking::CurrentEra::<Runtime>::put(0);
		staking::ActiveEra::<Runtime>::put(ActiveEraInfo {
			index: 0,
			start: Some(pallet_timestamp::Now::<Runtime>::get()),
		});
		staking::BondedEras::<Runtime>::put(BoundedVec::truncate_from(alloc::vec![(0, session)]));

		ah_client::Mode::<Runtime>::put(OperatingMode::Active);
		ah_client::ValidatorSetAppliedAt::<Runtime>::put(session);

		StorageVersion::new(1).put::<ValidatorSet>();

		log::info!(
			target: "runtime::migrations",
			"staking opened at era 0, session {session}, keeping {validators} validator(s)",
		);
		db_weight(5, 14)
	}

	#[cfg(feature = "try-runtime")]
	fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
		use scale_codec::Encode;
		Ok((
			Self::applies(),
			Session::validators(),
			Session::current_index(),
			crate::Balances::total_issuance(),
		)
			.encode())
	}

	#[cfg(feature = "try-runtime")]
	fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
		use frame_support::ensure;
		use scale_codec::Decode;
		let (applied, validators, session, issuance): (
			bool,
			Vec<crate::AccountId>,
			u32,
			crate::Balance,
		) = Decode::decode(&mut &state[..]).map_err(|_| "pre_upgrade state")?;
		// Not the spec 20 shape: the migration only read.
		if !applied {
			return Ok(());
		}
		ensure!(
			Session::validators() == validators,
			"the validator set changed"
		);
		ensure!(
			crate::Balances::total_issuance() == issuance,
			"issuance changed"
		);
		ensure!(
			staking::CurrentEra::<Runtime>::get() == Some(0)
				&& staking::ActiveEra::<Runtime>::get().map(|era| era.index) == Some(0),
			"no era 0"
		);
		ensure!(
			staking::BondedEras::<Runtime>::get().into_inner() == alloc::vec![(0, session)],
			"era 0 not bonded at the current session"
		);
		ensure!(
			staking::ForceEra::<Runtime>::get() == Forcing::ForceNone,
			"eras not held for governance"
		);
		ensure!(
			staking::ValidatorCount::<Runtime>::get() == validators.len() as u32,
			"validator count"
		);
		ensure!(
			ah_client::Mode::<Runtime>::get() == OperatingMode::Active,
			"session side not reporting"
		);
		ensure!(
			staking::MaxNominatorsCount::<Runtime>::get().is_none(),
			"nominators capped"
		);
		ensure!(
			staking::MaxCommission::<Runtime>::get() == sp_runtime::Perbill::one(),
			"commission ceiling"
		);
		ensure!(
			pools::MinJoinBond::<Runtime>::get() == POOL_MIN_JOIN_BOND
				&& pools::MinCreateBond::<Runtime>::get() == TEST_POOL_MIN_CREATE_BOND
				&& pools::MaxPools::<Runtime>::get().is_none()
				&& pools::MaxPoolMembers::<Runtime>::get().is_none()
				&& pools::MaxPoolMembersPerPool::<Runtime>::get().is_none()
				&& pools::GlobalMaxCommission::<Runtime>::get().is_none(),
			"pool limits"
		);
		ensure!(
			ValidatorSet::on_chain_storage_version() == 1,
			"validator-set version"
		);
		Ok(())
	}
}
