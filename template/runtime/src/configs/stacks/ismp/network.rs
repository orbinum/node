// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Which Hyperbridge deployment this runtime talks to, and how Orbinum names itself.
//!
//! Hyperbridge is the transport, not the destination: these constants say where the
//! bridge lives, not which chains we exchange messages with. Destinations are
//! per-message (`dispatch_post`) and per-counterparty (`AcceptedSources`).

use ismp::host::StateMachine;

/// Hyperbridge's parachain id on Polkadot: the mainnet deployment.
///
/// `allow`: each build reads only one of the pair; the tests assert both stay distinct.
#[allow(dead_code)]
pub const HYPERBRIDGE_MAINNET_PARA_ID: u32 = 3367;

/// Hyperbridge's parachain id on its testnet deployment (Paseo relay). See the mainnet
/// id for `allow`.
#[allow(dead_code)]
pub const HYPERBRIDGE_TESTNET_PARA_ID: u32 = 4009;

/// Hyperbridge's slot duration in milliseconds: the value to whitelist it with.
///
/// Hyperbridge's Aura slot, not Orbinum's block time. `ismp-grandpa` dates each
/// Hyperbridge header as `aura_slot * slot_duration`, so a wrong value misdates every
/// commitment, challenge period and timeout. Set on-chain through
/// `ismp_grandpa::add_state_machines`; exposed by `OrbinumIsmpApi::hyperbridge_slot_duration`.
#[cfg(not(feature = "hyperbridge-testnet"))]
pub const HYPERBRIDGE_SLOT_DURATION_MS: u64 = 12_000;

/// See the mainnet variant above.
#[cfg(feature = "hyperbridge-testnet")]
pub const HYPERBRIDGE_SLOT_DURATION_MS: u64 = 6_000;

/// Orbinum's own four-byte identifier on the ISMP network.
///
/// Remote chains use this both to address requests to Orbinum and to accept requests
/// originating here. It must be unique across every solochain connected to
/// Hyperbridge, and it must not change once messages have been exchanged — the id is
/// baked into every commitment already in flight.
pub const HOST_STATE_MACHINE_ID: [u8; 4] = *b"orbi";

/// The coprocessor that verifies consensus and state proofs on Orbinum's behalf.
///
/// The relay is part of the identifier: `is_allowed_proxy` compares it with `==`, so the
/// wrong one fails every proxied request with `RequestProxyProhibited`. The testnet
/// deployment is `KUSAMA-4009`.
#[cfg(not(feature = "hyperbridge-testnet"))]
pub const fn coprocessor() -> Option<StateMachine> {
	Some(StateMachine::Polkadot(HYPERBRIDGE_MAINNET_PARA_ID))
}

/// See the mainnet variant above for why the testnet is `Kusama`, not `Polkadot`.
#[cfg(feature = "hyperbridge-testnet")]
pub const fn coprocessor() -> Option<StateMachine> {
	Some(StateMachine::Kusama(HYPERBRIDGE_TESTNET_PARA_ID))
}

/// Orbinum's own state machine identifier.
pub const fn host_state_machine() -> StateMachine {
	StateMachine::Substrate(HOST_STATE_MACHINE_ID)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn para_id_follows_the_build_feature() {
		assert_ne!(HYPERBRIDGE_MAINNET_PARA_ID, HYPERBRIDGE_TESTNET_PARA_ID);

		// Read through `coprocessor()`: that is the value the runtime consults.
		let expected = if cfg!(feature = "hyperbridge-testnet") {
			HYPERBRIDGE_TESTNET_PARA_ID
		} else {
			HYPERBRIDGE_MAINNET_PARA_ID
		};
		let actual = match coprocessor().expect("coprocessor is configured") {
			StateMachine::Polkadot(id) | StateMachine::Kusama(id) => id,
			other => panic!("coprocessor must be a parachain, got {other:?}"),
		};
		assert_eq!(actual, expected);
	}

	#[test]
	fn coprocessor_names_the_right_relay_chain() {
		// The para id alone is not the identifier: `is_allowed_proxy` compares the
		// whole variant with `==`, so assert the whole variant.
		#[cfg(feature = "hyperbridge-testnet")]
		assert_eq!(
			coprocessor(),
			Some(StateMachine::Kusama(HYPERBRIDGE_TESTNET_PARA_ID))
		);
		#[cfg(not(feature = "hyperbridge-testnet"))]
		assert_eq!(
			coprocessor(),
			Some(StateMachine::Polkadot(HYPERBRIDGE_MAINNET_PARA_ID))
		);
	}

	/// The slot duration matches the documented value for the coprocessor this build
	/// targets, so the two constants cannot be switched independently.
	#[test]
	fn slot_duration_follows_the_coprocessor() {
		// `developers/polkadot/solochains`, `consensus.toml`: Paseo 6000, Polkadot 12000.
		let documented = match coprocessor() {
			Some(StateMachine::Kusama(HYPERBRIDGE_TESTNET_PARA_ID)) => 6_000,
			Some(StateMachine::Polkadot(HYPERBRIDGE_MAINNET_PARA_ID)) => 12_000,
			other => panic!("no documented slot duration for coprocessor {other:?}"),
		};
		assert_eq!(HYPERBRIDGE_SLOT_DURATION_MS, documented);
	}

	#[test]
	fn polkadot_and_kusama_variants_are_not_interchangeable() {
		assert_ne!(
			StateMachine::Polkadot(HYPERBRIDGE_TESTNET_PARA_ID),
			StateMachine::Kusama(HYPERBRIDGE_TESTNET_PARA_ID)
		);
	}

	/// The runtime API reports the coprocessor the pallet uses.
	#[test]
	fn runtime_api_reports_the_configured_coprocessor() {
		use crate::runtime_api::runtime_decl_for_orbinum_ismp_api::OrbinumIsmpApiV1;
		assert_eq!(
			<crate::Runtime as OrbinumIsmpApiV1<crate::Block>>::coprocessor(),
			coprocessor()
		);
		assert_eq!(
			<crate::Runtime as pallet_ismp::Config>::Coprocessor::get(),
			coprocessor(),
			"the pallet and the API must agree on which chain proxies for us"
		);
	}

	#[test]
	fn host_state_machine_is_the_declared_id() {
		assert_eq!(host_state_machine(), StateMachine::Substrate(*b"orbi"));
	}
}
