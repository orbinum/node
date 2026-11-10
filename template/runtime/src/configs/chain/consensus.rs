//! Block production and finality: Aura, GRANDPA, sessions, the validator set, block
//! authorship and dev-only manual seal.
//!
//! Staking elects each era's validators (`configs::staking`); ah-client queues
//! the elected set and sessions hand it to Aura and GRANDPA. The validator set
//! decides who may be elected: a governance allowlist while permissioned, plus
//! bans in either mode.

use crate::{
	configs::{governance::AdmissionAdmin, staking::MaxActiveValidators},
	opaque,
	pallets::manual_seal::{self, EnableManualSeal},
	staking::{
		admission::{ChillOnRemoval, SelfBondFloor, StakingCandidacy},
		params::{
			BONDING_DURATION, MAX_EXPOSURE_PAGE_SIZE, MAX_VALIDATOR_CANDIDATES, SESSIONS_PER_ERA,
			SESSION_PERIOD,
		},
	},
	AccountId, AhClient, Aura, Balances, Historical, Offences, Runtime, RuntimeEvent, Session,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use frame_support::{
	parameter_types,
	traits::{ConstBool, ConstU128, ConstU32, Get, OnTimestampSet},
};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_runtime::traits::{Convert, OpaqueKeys};

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type MaxAuthorities = MaxActiveValidators;
	type DisabledValidators = Session;
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

parameter_types! {
	/// Session length: 600 blocks ≈ 1 hour at 6 s/block (2 minutes with
	/// `fast-runtime`). An elected set takes over at a session boundary.
	pub const Period: u32 = SESSION_PERIOD;
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
	/// ah-client hands over the set staking elected and reports each session's
	/// end to staking; the historical root of each session's set is kept so
	/// offences in it can be proven.
	type SessionManager = pallet_session::historical::NoteHistoricalRoot<Runtime, AhClient>;
	type SessionHandler = <opaque::SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
	type Keys = opaque::SessionKeys;
	/// An offender stops authoring and voting for the rest of the session, up to
	/// a third of the set; the most severe offenders win the slots.
	type DisablingStrategy = pallet_session::disabling::UpToLimitWithReEnablingDisablingStrategy;
	type Currency = Balances;
	/// No deposit to set session keys.
	type KeyDeposit = ConstU128<0>;
	type WeightInfo = pallet_session::weights::SubstrateWeight<Runtime>;
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

/// The current session's validators.
pub struct SessionValidators;
impl Get<Vec<AccountId>> for SessionValidators {
	fn get() -> Vec<AccountId> {
		pallet_session::Validators::<Runtime>::get()
	}
}

/// The validators queued for the next session.
pub struct QueuedSessionValidators;
impl Get<Vec<AccountId>> for QueuedSessionValidators {
	fn get() -> Vec<AccountId> {
		pallet_session::QueuedKeys::<Runtime>::get()
			.into_iter()
			.map(|(validator, _)| validator)
			.collect()
	}
}

#[cfg(feature = "runtime-benchmarks")]
impl pallet_validator_set::traits::BenchmarkHelper<AccountId> for SessionValidators {
	fn set_active_validators(validators: Vec<AccountId>) {
		let keys = |v: &AccountId| {
			let raw: [u8; 32] = v.clone().into();
			crate::opaque::SessionKeys {
				aura: sp_core::sr25519::Public::from_raw(raw).into(),
				grandpa: sp_core::ed25519::Public::from_raw(raw).into(),
			}
		};
		pallet_session::QueuedKeys::<Runtime>::put(
			validators
				.iter()
				.map(|v| (v.clone(), keys(v)))
				.collect::<Vec<_>>(),
		);
		pallet_session::Validators::<Runtime>::put(validators);
	}
}

impl pallet_validator_set::Config for Runtime {
	type AddRemoveOrigin = AdmissionAdmin;
	type MaxValidators = ConstU32<{ MAX_VALIDATOR_CANDIDATES }>;
	type Prerequisites = ValidatorPrerequisiteChecker;
	/// Removing or banning an account ends its staking candidacy at once.
	type OnValidatorRemoved = ChillOnRemoval;
	type OpenModeGuard = SelfBondFloor;
	type Candidacy = StakingCandidacy;
	type ActiveValidators = SessionValidators;
	type QueuedValidators = QueuedSessionValidators;
	type DisabledValidators = Session;
	type FindAuthor = ValidatorAuthor;
	type QuorumWindow = Period;
	type WeightInfo = pallet_validator_set::weights::SubstrateWeight<Runtime>;
	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkHelper = SessionValidators;
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = ValidatorAuthor;
	/// Authoring a block earns era points, which split the era's reward:
	/// ah-client counts them and reports them to staking each session.
	type EventHandler = AhClient;
}

/// The block author's validator account: the session validator at the Aura
/// authority index the block's pre-digest names. Aura's authorities are set from
/// the session's validators, in the same order.
///
/// Not the Aura key read as an account: an operator may call `session.setKeys` from an
/// account other than the key's.
pub type ValidatorAuthor = pallet_session::FindAccountFromAuthorIndex<Runtime, Aura>;

/// The validator account that authored the current block, as `pallet_authorship`
/// reports it through `ValidatorAuthor`.
pub struct ValidatorAccountAuthor;

impl Get<Option<AccountId>> for ValidatorAccountAuthor {
	fn get() -> Option<AccountId> {
		let author = pallet_authorship::Pallet::<Runtime>::author();
		// A benchmark block carries no Aura pre-digest, so it has no author.
		#[cfg(feature = "runtime-benchmarks")]
		let author = author.or(Some(AccountId::from([0xbe; 32])));
		author
	}
}

parameter_types! {
	/// Set-id-to-session entries kept: one per session for as long as stake
	/// stays slashable (GRANDPA's set changes at most once a session), so an
	/// equivocation can be proven until then.
	pub const MaxSetIdSessionEntries: u64 =
		BONDING_DURATION as u64 * SESSIONS_PER_ERA as u64;
	/// Blocks an equivocation report stays valid in the pool.
	pub const ReportLongevity: u64 = MaxSetIdSessionEntries::get() * Period::get() as u64;
}

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	/// The pallet's default weights (its `SubstrateWeight` prices only the proof
	/// check): an estimate scaled by the set size and nominators per validator
	/// (what a slash touches).
	type WeightInfo = ();
	type MaxAuthorities = MaxActiveValidators;
	type MaxNominators = ConstU32<{ MAX_EXPOSURE_PAGE_SIZE }>;
	type MaxSetIdSessionEntries = MaxSetIdSessionEntries;
	/// Proof that a GRANDPA key belonged to a validator in a past session.
	type KeyOwnerProof = sp_session::MembershipProof;
	/// Equivocations are reported as offences, which staking slashes; a report
	/// that can change no slash or ban is refused (`staking::offences::OncePerEra`).
	type EquivocationReportSystem = pallet_grandpa::EquivocationReportSystem<
		Self,
		crate::staking::offences::OncePerEra<Offences>,
		Historical,
		ReportLongevity,
	>;
}

/// `pallet_timestamp`'s hook: Aura checks each block's slot, unless the dev chain
/// seals manually.
pub struct ConsensusOnTimestampSet<T>(PhantomData<T>);
impl<T: pallet_aura::Config> OnTimestampSet<T::Moment> for ConsensusOnTimestampSet<T> {
	fn on_timestamp_set(moment: T::Moment) {
		if EnableManualSeal::get() {
			return;
		}
		<pallet_aura::Pallet<T> as OnTimestampSet<T::Moment>>::on_timestamp_set(moment)
	}
}

impl manual_seal::Config for Runtime {}
