//! ISMP / Hyperbridge configuration.
//!
//! Solochain path: [`ismp_grandpa::consensus::GrandpaConsensusClient`], not
//! `ismp-parachain`. Proofs are checked against GRANDPA finality on both sides, so Orbinum
//! keeps its own validator set.
//!
//! `handle_unsigned` is unsigned and fee-less, so a relayer needs no funded account;
//! `validate_unsigned` rejects forged proofs at the pool. Known gap: a batch of
//! almost-valid messages costs a node full verification and the submitter nothing;
//! bounding it would need a chain-wide `BaseCallFilter`.
//!
//! - `router`: where an incoming request is delivered.
//! - `messaging`: `pallet-ismp-messaging`, this chain's own ISMP application.
//! - `network`: which Hyperbridge deployment this build talks to.
//! - `slot_duration`: bounds on a whitelisted chain's slot duration.

mod messaging;
pub mod network;
mod router;
pub mod slot_duration;
#[cfg(test)]
mod tests;

pub use router::Router;

use crate::{
	configs::governance::CrossChainAdmin, weights, AccountId, Balance, Balances, Runtime, Timestamp,
};
use frame_support::{parameter_types, PalletId};
use ismp::host::StateMachine;
use sp_runtime::traits::AccountIdConversion;

parameter_types! {
	/// Verifies consensus and state proofs on Orbinum's behalf; which deployment depends
	/// on the build feature. See [`network::coprocessor`].
	pub const Coprocessor: Option<StateMachine> = network::coprocessor();

	/// See [`network::HOST_STATE_MACHINE_ID`] for why it must never change.
	pub const HostStateMachine: StateMachine = network::host_state_machine();

	/// The ISMP treasury: receives message charges. Also handed to `WeightFeeHandler`,
	/// which collects nothing while its `POLICY` is off.
	pub const IsmpTreasuryPalletId: PalletId = PalletId(*b"orb/ismp");
	/// The same pallet id as an account, for `Config::FeeDestination`.
	pub IsmpTreasuryAccount: AccountId = IsmpTreasuryPalletId::get().into_account_truncating();

	/// 0.01 ORB per signed dispatch, plus a per-byte term, paid to the ISMP treasury and
	/// never refunded. Starting values; Root changes both with `set_message_fee`.
	///
	/// Ten times the shielded pool's spend fee floor (`MinSpendFee`), since a cross-chain
	/// dispatch costs real gas on the far side, and a hundredth of the ceiling below.
	///
	/// Not escrowed in `FeeMetadata`: a refundable anti-spam charge could be recycled on
	/// every timeout. See the pallet's `outbound::fee_for`.
	pub const IsmpDefaultMessageFee: Balance = 10_000_000_000_000_000;
	/// 0.000001 ORB per byte: a full 8 KiB body adds ~0.008 ORB, roughly doubling the price
	/// of the largest message this chain will carry. Hyperbridge prices its own outbound
	/// traffic per byte for the same reason (`pallet-bandwidth`).
	pub const IsmpDefaultMessageByteFee: Balance = 1_000_000_000_000;
	/// 1 ORB: far enough above the default to absorb a token repricing, far below where a
	/// typo would price dispatch out of reach until the next runtime upgrade.
	pub const IsmpMaxMessageFee: Balance = 1_000_000_000_000_000_000;
	/// Ten minutes: two finality rounds — Orbinum→Hyperbridge, Hyperbridge→destination —
	/// each with its challenge period. Shorter can only expire.
	pub const IsmpMinSignedTimeout: u64 = 10 * 60;
	/// A week. The fee comes back only by expiring, so a signer may not set "never".
	pub const IsmpMaxSignedTimeout: u64 = 7 * 24 * 60 * 60;
}

impl pallet_ismp::Config for Runtime {
	/// Decides whose cross-chain proofs this chain trusts.
	type AdminOrigin = CrossChainAdmin;
	type HostStateMachine = HostStateMachine;
	type TimestampProvider = Timestamp;
	type Balance = Balance;
	type Currency = Balances;
	type Router = Router;
	type Coprocessor = Coprocessor;

	/// GRANDPA only. `tests` asserts its envelope check (`envelope_matches_state_machine`),
	/// so a fork that drops it fails.
	type ConsensusClients = (ismp_grandpa::consensus::GrandpaConsensusClient<Runtime>,);

	type OffchainDB = ();

	/// `POLICY = false`: inbound delivery is free for the submitter (`on_executed` returns
	/// `Pays::No` before charging anyone). Turning it on would bill the submitter for the
	/// execution weight.
	///
	/// Separate from the outbound message charge, which `pallet-ismp-messaging` takes
	/// directly (its `outbound::fee_for`).
	type FeeHandler = pallet_ismp::fee_handler::WeightFeeHandler<
		AccountId,
		Balances,
		<Runtime as pallet_transaction_payment::Config>::WeightToFee,
		IsmpTreasuryPalletId,
		false,
	>;
}

// Commitment retention stays at the pallet default: 10,240 heights, ~17 h against a 6 s
// counterparty. `update_commitment_caps` (root) overrides it per chain, e.g. for a
// sub-second one.

impl ismp_grandpa::Config for Runtime {
	type IsmpHost = pallet_ismp::Pallet<Runtime>;

	/// The pallet drops datagrams from any chain absent from the whitelist.
	type RootOrigin = CrossChainAdmin;

	/// Benchmarked; the unit impl charges a flat 10 ms whatever the batch size.
	type WeightInfo = weights::ismp_grandpa::SubstrateWeight<Runtime>;
}
