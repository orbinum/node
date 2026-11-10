//! The GRANDPA consensus client the runtime wires rejects a proof whose envelope does
//! not match the tracked chain.

use super::network;
use crate::Runtime;
use grandpa_verifier_primitives::{ConsensusState, FinalityProof};
use ismp::host::{IsmpHost, StateMachine};
use ismp_grandpa::messages::{ConsensusMessage, StandaloneChainMessage};
use scale_codec::Encode;

/// Drives the client the runtime actually wires and asserts upstream's own envelope
/// rejection, so a fork or downgrade that drops the check fails here.
#[test]
fn configured_consensus_client_rejects_mismatched_envelope() {
	sp_io::TestExternalities::default().execute_with(|| {
		let err = verify_with_envelope(standalone_envelope())
			.expect_err("a relay envelope under a parachain tracker must be rejected");
		assert!(
			format!("{err:?}").contains("envelope does not match"),
			"expected the envelope-binding rejection, got: {err:?}"
		);
	});
}

/// A matching envelope passes the binding check: the empty proof still fails, but with
/// a different error.
#[test]
fn correct_envelope_passes_the_binding_check() {
	sp_io::TestExternalities::default().execute_with(|| {
		let err = verify_with_envelope(ConsensusMessage::Polkadot(
			ismp_grandpa::messages::RelayChainMessage {
				finality_proof: empty_proof(),
				parachain_headers: Default::default(),
			},
		))
		.expect_err("garbage proof cannot verify");
		assert!(
			!format!("{err:?}").contains("envelope does not match"),
			"the correct pairing must not trip the binding check: {err:?}"
		);
	});
}

fn verify_with_envelope(
	message: ConsensusMessage,
) -> Result<(alloc::vec::Vec<u8>, ismp::consensus::VerifiedCommitments), ismp::error::Error> {
	let clients = pallet_ismp::Pallet::<Runtime>::default().consensus_clients();
	let grandpa = clients
		.iter()
		.find(|c| c.consensus_client_id() == ismp_grandpa::consensus::GRANDPA_CONSENSUS_ID)
		.expect("the GRANDPA client must be wired into `ConsensusClients`");

	// A parachain tracker (Hyperbridge's testnet), so a `StandaloneChain` envelope
	// does not match it.
	let trusted = ConsensusState {
		current_authorities: Default::default(),
		current_set_id: 0,
		latest_height: 0,
		latest_hash: Default::default(),
		slot_duration: 6_000,
		state_machine: StateMachine::Kusama(network::HYPERBRIDGE_TESTNET_PARA_ID),
	};

	grandpa.verify_consensus(
		&pallet_ismp::Pallet::<Runtime>::default(),
		*b"PAS0",
		trusted.encode(),
		message.encode(),
	)
}

fn empty_proof() -> FinalityProof<ismp_grandpa::messages::SubstrateHeader> {
	FinalityProof {
		block: Default::default(),
		justification: Default::default(),
		unknown_headers: Default::default(),
	}
}

fn standalone_envelope() -> ConsensusMessage {
	ConsensusMessage::StandaloneChain(StandaloneChainMessage {
		finality_proof: empty_proof(),
	})
}

/// A batch's callback weight, plus a read and write per request and timeout, lands
/// in the block weight.
#[test]
fn inbound_callback_weight_is_charged_to_the_block() {
	use frame_support::{traits::Get, weights::Weight};
	use ismp::{
		consensus::{StateMachineHeight, StateMachineId},
		messaging::{Message, MessageWithWeight, Proof, RequestMessage, TimeoutMessage},
		router::PostRequest,
	};
	use pallet_ismp::fee_handler::FeeHandler;

	sp_io::TestExternalities::default().execute_with(|| {
		let request = PostRequest {
			source: StateMachine::Evm(1),
			dest: StateMachine::Evm(2),
			nonce: 0,
			from: vec![],
			to: vec![],
			timeout_timestamp: 0,
			body: vec![],
		};
		let proof = Proof {
			height: StateMachineHeight {
				id: StateMachineId {
					state_id: StateMachine::Evm(1),
					consensus_state_id: *b"PARA",
				},
				height: 1,
			},
			proof: vec![],
		};
		let callbacks = Weight::from_parts(465_000_000, 0);
		let batch = MessageWithWeight {
			message: Message::Request(RequestMessage {
				requests: vec![request.clone(); 3],
				proof: proof.clone(),
				signer: vec![],
			}),
			weight: callbacks,
		};
		let timeouts = MessageWithWeight {
			message: Message::Timeout(TimeoutMessage::Post {
				requests: vec![request; 2],
				timeout_proof: proof,
			}),
			weight: Weight::zero(),
		};

		let before = frame_system::Pallet::<Runtime>::block_weight().total();
		// Through the configured handler, to cover the wiring.
		assert!(<Runtime as pallet_ismp::Config>::FeeHandler::on_executed(
			vec![batch, timeouts],
			vec![]
		)
		.is_ok());
		// 3 requests + 2 timeouts.
		let receipts = <<Runtime as frame_system::Config>::DbWeight as Get<
			frame_support::weights::RuntimeDbWeight,
		>>::get()
		.reads_writes(5, 5);
		assert_eq!(
			frame_system::Pallet::<Runtime>::block_weight().total(),
			before + callbacks + receipts
		);
	});
}
