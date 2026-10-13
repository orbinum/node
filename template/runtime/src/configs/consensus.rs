//! Block production and finality: Aura, GRANDPA, sessions, and the validator set.
//!
//! The validator set is a sudo-controlled allowlist: operators are selected
//! off-chain and added with `add_validator`, which requires the account to have
//! session keys registered so an approved account can always author.

use crate::*;
use frame_support::parameter_types;

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type MaxAuthorities = ConstU32<32>;
	type DisabledValidators = Session;
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

parameter_types! {
	/// Session length: 600 blocks ≈ 1 hour at 6 s/block.
	/// Validator set changes take effect at the next session boundary.
	pub const Period: u32 = HOURS;
	pub const Offset: u32 = 0;
}

/// `pallet_session::Config::ValidatorIdOf` for `ValidatorId = AccountId`.
pub struct IdentityValidatorId;
impl Convert<AccountId, Option<AccountId>> for IdentityValidatorId {
	fn convert(a: AccountId) -> Option<AccountId> {
		Some(a)
	}
}

impl pallet_session::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type ValidatorId = AccountId;
	type ValidatorIdOf = IdentityValidatorId;
	type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
	type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
	type SessionManager = ValidatorSet;
	type SessionHandler = <opaque::SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = opaque::SessionKeys;
	/// Validators are never disabled automatically.
	type DisablingStrategy = ();
	type Currency = Balances;
	/// No deposit to set session keys, on testnet.
	type KeyDeposit = ConstU128<0>;
	type WeightInfo = ();
}

/// Verifies that an account can actually author before it joins the active set.
///
/// Checks `pallet_session::NextKeys` for `who`, i.e. that the operator called
/// `session.setKeys` with their Aura + GRANDPA keys. Without them the account would hold
/// a slot without producing blocks.
pub struct ValidatorPrerequisiteChecker;

impl pallet_validator_set::ValidatorPrerequisites<AccountId> for ValidatorPrerequisiteChecker {
	fn has_session_keys(who: &AccountId) -> bool {
		pallet_session::NextKeys::<Runtime>::contains_key(who)
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_session_keys(who: &AccountId) {
		// Benchmarks add throwaway accounts that never called `session.setKeys`.
		// Only the presence of an entry matters to the gate, so derive both keys
		// from the account bytes rather than generating real ones.
		let raw: [u8; 32] = who.clone().into();
		pallet_session::NextKeys::<Runtime>::insert(
			who,
			opaque::SessionKeys {
				aura: sp_core::sr25519::Public::from_raw(raw).into(),
				grandpa: sp_core::ed25519::Public::from_raw(raw).into(),
			},
		);
	}
}

impl pallet_validator_set::Config for Runtime {
	type AddRemoveOrigin = frame_system::EnsureRoot<AccountId>;
	type MaxValidators = ConstU32<32>;
	type Prerequisites = ValidatorPrerequisiteChecker;
	type OnValidatorRemoved = ();
	type FindAuthor = ValidatorAuthor;
	type QuorumWindow = Period;
	type WeightInfo = pallet_validator_set::weights::SubstrateWeight<Runtime>;
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = ValidatorAuthor;
	type EventHandler = ();
}

/// The block author's validator account: the session validator at the Aura
/// authority index the block's pre-digest names. Aura's authorities are set from
/// the session's validators, in the same order.
///
/// Not the Aura key read as an account: that is the validator's account only when
/// the operator registered the key as its own account, so every validator that
/// called `session.setKeys` from another account went unrecognised.
pub type ValidatorAuthor = pallet_session::FindAccountFromAuthorIndex<Runtime, Aura>;

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxAuthorities = ConstU32<32>;
	type MaxNominators = ConstU32<0>;
	type MaxSetIdSessionEntries = ConstU64<0>;
	type KeyOwnerProof = sp_core::Void;
	type EquivocationReportSystem = ();
}
