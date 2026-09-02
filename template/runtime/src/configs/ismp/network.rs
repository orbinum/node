//! Which Hyperbridge deployment this runtime talks to, and how Orbinum names itself.
//!
//! Hyperbridge is the transport, not the destination: these constants say where the
//! bridge lives, not which chains we exchange messages with. Destinations are
//! per-message (`dispatch_post`) and per-counterparty (`AcceptedSources`).

use ismp::host::StateMachine;

/// Hyperbridge's parachain id on Polkadot — the mainnet deployment.
///
/// `allow`: only one of the pair is read by any given build, but the tests assert both
/// so they can never collapse into one.
#[allow(dead_code)]
pub const HYPERBRIDGE_MAINNET_PARA_ID: u32 = 3367;

/// Hyperbridge's parachain id on its testnet deployment, currently hosted on the Paseo
/// relay. See the mainnet id for `allow`.
#[allow(dead_code)]
pub const HYPERBRIDGE_TESTNET_PARA_ID: u32 = 4009;

/// Hyperbridge's slot duration, in milliseconds — the value to whitelist it with.
///
/// This is the *counterparty's* block time, not Orbinum's; they coincide at 6s today.
/// It reaches the chain through `ismp_grandpa::add_state_machines`, so the setup scripts
/// read it from here rather than restating it.
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
/// The relay chain is part of the identifier, not decoration: `Polkadot` and `Kusama`
/// are different SCALE variants, and `is_allowed_proxy` compares the coprocessor to a
/// request's source with `==`. Naming the wrong relay fails every proxied request with
/// `RequestProxyProhibited`.
///
/// The testnet deployment identifies itself as **`KUSAMA-4009`**, not `POLKADOT-4009` —
/// verified live against its RPC. Relay and para id switch together with the build
/// feature so they cannot drift apart.
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

	#[test]
	fn polkadot_and_kusama_variants_are_not_interchangeable() {
		assert_ne!(
			StateMachine::Polkadot(HYPERBRIDGE_TESTNET_PARA_ID),
			StateMachine::Kusama(HYPERBRIDGE_TESTNET_PARA_ID)
		);
	}

	/// The API and the pallet must agree, or a suite reading the API derives a
	/// confident wrong answer.
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
