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

/// Clears the EVM relay binding of an account that leaves the validator set.
///
/// Registering a relay address requires an active validator, so the binding must
/// not outlive the membership that authorised it.
pub struct RelayerCleanup;

impl pallet_validator_set::OnValidatorRemoved<AccountId> for RelayerCleanup {
	fn on_validator_removed(who: &AccountId) {
		pallet_relayer::Pallet::<Runtime>::clear_relayer(who);
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn setup_removal_state(who: &AccountId) {
		// Give `remove_validator` a binding to tear down, so its benchmark
		// measures the two cleanup writes instead of the empty branch.
		let evm_address = sp_core::H160::repeat_byte(0x99);
		pallet_relayer::RelayerRegistry::<Runtime>::insert(evm_address, who.clone());
		pallet_relayer::RelayerByAccount::<Runtime>::insert(who.clone(), evm_address);
	}
}

impl pallet_validator_set::Config for Runtime {
	type AddRemoveOrigin = frame_system::EnsureRoot<AccountId>;
	type MaxValidators = ConstU32<32>;
	type Prerequisites = ValidatorPrerequisiteChecker;
	type OnValidatorRemoved = RelayerCleanup;
	type WeightInfo = pallet_validator_set::weights::SubstrateWeight<Runtime>;
}

impl pallet_authorship::Config for Runtime {
	type FindAuthor = FindAuthorAccountId;
	type EventHandler = ();
}

/// Maps an Aura authority index to its `AccountId32`: upstream's `AuraAuthorId` yields
/// the index, and the sr25519 public key at that index is the account's 32 bytes.
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
