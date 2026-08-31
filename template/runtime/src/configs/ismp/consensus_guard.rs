//! Envelope/state-machine binding for the GRANDPA consensus client.
//!
//! `GrandpaConsensusClient::verify_consensus` decodes an attacker-supplied
//! `ConsensusMessage`, matches on its variant, then labels the header it verified with
//! the **trusted** state machine from the stored consensus state. On 2512 nothing
//! checks that the two agree.
//!
//! That is a type confusion, not a decoding quirk. A parachain tracker's authority set
//! *is* the relay chain's GRANDPA set, so a genuine relay finality proof submitted
//! under the `StandaloneChain` envelope passes signature verification — and the relay's
//! **global** state root is recorded under the parachain's identity, at a relay height.
//! Every subsequent state proof against that commitment verifies against the wrong trie.
//!
//! **Live for Orbinum, not theoretical:** we track Hyperbridge as `Kusama(4009)`,
//! precisely the parachain-tracker case the upstream advisory names.
//!
//! Upstream fixed it on the 2606 line (`envelope_matches_state_machine`), which needs
//! `frame-support` 48 against our 45.1.3. [`GuardedGrandpaConsensusClient`] applies the
//! same check in front of the unpatched client until we can take it.

use alloc::{boxed::Box, format, vec::Vec};
use grandpa_verifier_primitives::ConsensusState;
use ismp::{
	consensus::{
		ConsensusClient, ConsensusClientId, ConsensusStateId, StateMachineClient,
		VerifiedCommitments,
	},
	error::Error as IsmpError,
	host::{IsmpHost, StateMachine},
};
use ismp_grandpa::{consensus::GrandpaConsensusClient, messages::ConsensusMessage};
use scale_codec::Decode;

use crate::Runtime;

/// Whether the proof envelope a submitter chose is valid for the class of state
/// machine the trusted consensus state tracks.
///
/// The envelope is attacker-selected; the state machine is trusted. See the module
/// docs for why an unchecked pairing is exploitable.
pub fn envelope_matches_state_machine(
	state_machine: &StateMachine,
	message: &ConsensusMessage,
) -> bool {
	matches!(
		(state_machine, message),
		(
			StateMachine::Polkadot(_) | StateMachine::Kusama(_),
			ConsensusMessage::Polkadot(_)
		) | (StateMachine::Relay { .. }, ConsensusMessage::Relaychain(_))
			| (
				StateMachine::Substrate(_),
				ConsensusMessage::StandaloneChain(_)
			)
	)
}

/// [`GrandpaConsensusClient`] with the envelope binding upstream added in 2606.
///
/// Delegates everything except `verify_consensus`, which is gated on
/// [`envelope_matches_state_machine`] first. Drop this wrapper once the runtime moves
/// to the 2606 line, where the check lives in the client itself.
#[derive(Default)]
pub struct GuardedGrandpaConsensusClient(GrandpaConsensusClient<Runtime>);

impl ConsensusClient for GuardedGrandpaConsensusClient {
	fn verify_consensus(
		&self,
		host: &dyn IsmpHost,
		consensus_state_id: ConsensusStateId,
		trusted_consensus_state: Vec<u8>,
		proof: Vec<u8>,
	) -> Result<(Vec<u8>, VerifiedCommitments), IsmpError> {
		// Decode both sides ourselves to compare them. The inner client decodes them
		// again; that duplication is the price of not forking the crate, and it is
		// cheap next to signature verification.
		let message = ConsensusMessage::decode(&mut &proof[..])
			.map_err(|e| IsmpError::Custom(format!("Failed to decode consensus message: {e:?}")))?;
		let state = ConsensusState::decode(&mut &trusted_consensus_state[..])
			.map_err(|e| IsmpError::Custom(format!("Failed to decode consensus state: {e:?}")))?;

		if !envelope_matches_state_machine(&state.state_machine, &message) {
			return Err(IsmpError::Custom(format!(
				"Consensus message envelope does not match tracked state machine {:?}",
				state.state_machine
			)));
		}

		self.0
			.verify_consensus(host, consensus_state_id, trusted_consensus_state, proof)
	}

	fn verify_fraud_proof(
		&self,
		host: &dyn IsmpHost,
		trusted_consensus_state: Vec<u8>,
		proof_1: Vec<u8>,
		proof_2: Vec<u8>,
	) -> Result<(), IsmpError> {
		self.0
			.verify_fraud_proof(host, trusted_consensus_state, proof_1, proof_2)
	}

	fn consensus_client_id(&self) -> ConsensusClientId {
		self.0.consensus_client_id()
	}

	fn state_machine(&self, id: StateMachine) -> Result<Box<dyn StateMachineClient>, IsmpError> {
		self.0.state_machine(id)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use grandpa_verifier_primitives::FinalityProof;

	/// Envelopes that upstream accepts. Kept in the same order as the doc table.
	#[test]
	fn accepts_the_documented_pairings() {
		// A parachain tracker verifies through its relay chain.
		assert!(envelope_matches_state_machine(
			&StateMachine::Polkadot(3367),
			&sample_polkadot()
		));
		assert!(envelope_matches_state_machine(
			&StateMachine::Kusama(4009),
			&sample_polkadot()
		));
		// A solochain proves its own finality.
		assert!(envelope_matches_state_machine(
			&StateMachine::Substrate(*b"orbi"),
			&sample_standalone()
		));
	}

	/// The exact confusion the upstream advisory describes: a relay finality proof
	/// smuggled in under `StandaloneChain` while the tracker is a parachain.
	#[test]
	fn rejects_relay_proof_smuggled_as_standalone_for_a_parachain_tracker() {
		assert!(!envelope_matches_state_machine(
			&StateMachine::Kusama(4009),
			&sample_standalone()
		));
		assert!(!envelope_matches_state_machine(
			&StateMachine::Polkadot(3367),
			&sample_standalone()
		));
	}

	/// The mirror case — a solochain tracker fed a parachain envelope.
	#[test]
	fn rejects_parachain_envelope_for_a_solochain_tracker() {
		assert!(!envelope_matches_state_machine(
			&StateMachine::Substrate(*b"orbi"),
			&sample_polkadot()
		));
		assert!(!envelope_matches_state_machine(
			&StateMachine::Substrate(*b"orbi"),
			&sample_relaychain()
		));
	}

	/// Hyperbridge on Paseo is `Kusama(4009)`; this is the pairing Orbinum relies on
	/// in production, asserted so a refactor cannot silently break it.
	#[test]
	fn orbinum_paseo_topology_is_accepted() {
		assert!(envelope_matches_state_machine(
			&StateMachine::Kusama(super::super::network::HYPERBRIDGE_TESTNET_PARA_ID),
			&sample_polkadot()
		));
	}

	// ── fixtures ────────────────────────────────────────────────────────────────
	// Only the enum variant is under test, so the payloads are empty. Building real
	// finality proofs would test `verify_consensus`, which is upstream's job.

	/// Minimal proof value — only the enum variant is under test, never the payload.
	fn empty_finality_proof() -> FinalityProof<ismp_grandpa::messages::SubstrateHeader> {
		FinalityProof {
			block: Default::default(),
			justification: Default::default(),
			unknown_headers: Default::default(),
		}
	}

	fn sample_standalone() -> ConsensusMessage {
		ConsensusMessage::StandaloneChain(ismp_grandpa::messages::StandaloneChainMessage {
			finality_proof: empty_finality_proof(),
		})
	}

	fn sample_polkadot() -> ConsensusMessage {
		ConsensusMessage::Polkadot(ismp_grandpa::messages::RelayChainMessage {
			finality_proof: empty_finality_proof(),
			parachain_headers: Default::default(),
		})
	}

	fn sample_relaychain() -> ConsensusMessage {
		ConsensusMessage::Relaychain(ismp_grandpa::messages::RelayChainMessage {
			finality_proof: empty_finality_proof(),
			parachain_headers: Default::default(),
		})
	}
}

#[cfg(test)]
mod wiring_tests {
	use super::*;
	use scale_codec::Encode;

	/// The guard is only useful if it is the client the runtime actually consults.
	///
	/// The unit tests above cover [`envelope_matches_state_machine`] as a free
	/// function — and would all still pass if `type ConsensusClients` were reverted to
	/// the bare `GrandpaConsensusClient`, silently reopening the type confusion the
	/// module docs describe. Nothing else in the suite distinguishes the two.
	///
	/// So this drives the tuple the pallet resolves at runtime and asserts on the
	/// rejection message, which only the wrapper can emit: the bare client has no
	/// envelope check and would fail later, inside signature verification, with a
	/// different error. No valid finality proof is needed precisely because the guard
	/// rejects before verification runs.
	#[test]
	fn configured_consensus_client_is_the_guarded_one() {
		// Go through the `IsmpHost` impl rather than the provider trait: the trait
		// lives in a private module, and the host is the path the pallet itself uses.
		let clients =
			<pallet_ismp::Pallet<Runtime> as IsmpHost>::consensus_clients(&Default::default());

		let grandpa = clients
			.iter()
			.find(|c| c.consensus_client_id() == ismp_grandpa::consensus::GRANDPA_CONSENSUS_ID)
			.expect("the GRANDPA client must be wired into `ConsensusClients`");

		// Hyperbridge on Paseo is a parachain tracker; `StandaloneChain` is the
		// envelope the upstream advisory names. This is the smuggling attempt.
		let trusted = ConsensusState {
			current_authorities: Default::default(),
			current_set_id: 0,
			latest_height: 0,
			latest_hash: Default::default(),
			slot_duration: 6_000,
			state_machine: StateMachine::Kusama(super::super::network::HYPERBRIDGE_TESTNET_PARA_ID),
		};

		let err = grandpa
			.verify_consensus(
				&pallet_ismp::Pallet::<Runtime>::default(),
				*b"PAS0",
				trusted.encode(),
				mismatched_envelope().encode(),
			)
			.expect_err("a relay envelope under a parachain tracker must be rejected");

		assert!(
			format!("{err:?}").contains("envelope does not match"),
			"expected the guard's own rejection, got: {err:?}"
		);
	}

	/// A `StandaloneChain` envelope — invalid for the `Kusama(_)` tracker above.
	fn mismatched_envelope() -> ConsensusMessage {
		ConsensusMessage::StandaloneChain(ismp_grandpa::messages::StandaloneChainMessage {
			finality_proof: grandpa_verifier_primitives::FinalityProof {
				block: Default::default(),
				justification: Default::default(),
				unknown_headers: Default::default(),
			},
		})
	}
}
