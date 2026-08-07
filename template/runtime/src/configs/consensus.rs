//! Block production and finality: Aura, GRANDPA, sessions, and the validator set.
//!
//! The validator set is governance-gated and enforces prerequisites before
//! bonding — a candidate must have registered both its session keys and its
//! relayer EVM address, or it cannot author.

use crate::*;
use frame_support::parameter_types;

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type MaxAuthorities = ConstU32<32>;
	// Session manages disabled validators when pallet-session is active.
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

/// Identity converter: `AccountId` → `Option<AccountId>` (always `Some`).
///
/// Used as `pallet_session::Config::ValidatorIdOf` when `ValidatorId = AccountId`.
pub struct IdentityValidatorId;
impl Convert<AccountId, Option<AccountId>> for IdentityValidatorId {
	fn convert(a: AccountId) -> Option<AccountId> {
		Some(a)
	}
}

impl pallet_session::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	/// Validators are identified by their `AccountId`.
	type ValidatorId = AccountId;
	/// Identity mapping: stash AccountId → ValidatorId (same type).
	type ValidatorIdOf = IdentityValidatorId;
	/// Sessions rotate every `Period` blocks.
	type ShouldEndSession = pallet_session::PeriodicSessions<Period, Offset>;
	type NextSessionRotation = pallet_session::PeriodicSessions<Period, Offset>;
	/// Validator set is managed by our custom `ValidatorSet` pallet (sudo-gated).
	type SessionManager = ValidatorSet;
	/// Session handlers: Aura + GRANDPA are notified on each session change.
	type SessionHandler = <opaque::SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = opaque::SessionKeys;
	/// No disabling strategy — validators are never automatically disabled.
	type DisablingStrategy = ();
	/// Balances pallet handles key-deposit holds.
	type Currency = Balances;
	/// No deposit required to set session keys (testnet).
	type KeyDeposit = ConstU128<0>;
	type WeightInfo = ();
}

/// Checks that a validator candidate has completed all prerequisites before bonding.
///
/// - [`has_session_keys`]: verifies `pallet_session::NextKeys` contains an entry for `who`
///   (i.e. the node called `session.setKeys` with its Aura + GRANDPA keys).
/// - [`has_relayer`]: verifies `pallet_relayer::RelayerByAccount` contains an entry for `who`
///   (i.e. the node called `relayer.register_relayer` with its EVM address).
pub struct ValidatorPrerequisiteChecker;

impl pallet_validator_set::ValidatorPrerequisites<AccountId> for ValidatorPrerequisiteChecker {
	fn has_session_keys(who: &AccountId) -> bool {
		pallet_session::NextKeys::<Runtime>::contains_key(who)
	}
	fn has_relayer(who: &AccountId) -> bool {
		pallet_relayer::RelayerByAccount::<Runtime>::contains_key(who)
	}
}

impl pallet_validator_set::Config for Runtime {
	/// Only sudo (EnsureRoot) can add/remove/approve/reject validators.
	type AddRemoveOrigin = frame_system::EnsureRoot<AccountId>;
	/// Native currency (ORB) used to lock the validator bond.
	type Currency = Balances;
	/// Maximum 32 validators in the approved (active) set.
	type MaxValidators = ConstU32<32>;
	/// Maximum 32 registrations awaiting governance approval.
	type MaxPendingValidators = ConstU32<32>;
	/// Validator bond: 1 000 ORB (18 decimals) locked on self-registration.
	/// Returned in full on deregistration, rejection, or force-removal.
	type ValidatorBond = ConstU128<1_000_000_000_000_000_000_000>;
	/// Prerequisite gate: verifies session keys and EVM relayer before accepting registration.
	type Prerequisites = ValidatorPrerequisiteChecker;
	type WeightInfo = pallet_validator_set::weights::SubstrateWeight<Runtime>;
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = FindAuthorAccountId;
	type EventHandler = ();
}

/// Maps an Aura authority index to its `AccountId32`.
///
/// `pallet_aura::AuraAuthorId` implements `FindAuthor<u32>` (authority index).
/// This wrapper looks up the AuraId at that index and converts its 32-byte
/// sr25519 public key into an `AccountId32`.
pub struct FindAuthorAccountId;
impl FindAuthor<AccountId> for FindAuthorAccountId {
	fn find_author<'a, I>(digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (ConsensusEngineId, &'a [u8])>,
	{
		if let Some(aura_id) = pallet_aura::AuraAuthorId::<Runtime>::find_author(digests) {
			let raw: [u8; 32] = aura_id.to_raw_vec().try_into().unwrap_or([0u8; 32]);
			return Some(AccountId::from(raw));
		}
		None
	}
}

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = ();
	type MaxAuthorities = ConstU32<32>;
	type MaxNominators = ConstU32<0>;
	type MaxSetIdSessionEntries = ConstU64<0>;
	type KeyOwnerProof = sp_core::Void;
	type EquivocationReportSystem = ();
}

impl cumulus_pallet_weight_reclaim::Config for Runtime {
	type WeightInfo = ();
}
