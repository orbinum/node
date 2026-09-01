//! ISMP / Hyperbridge configuration.
//!
//! # Why the solochain path
//!
//! Orbinum is a sovereign L1: it runs its own NPoS validator set and finalises with
//! GRANDPA. Becoming a parachain would hand finalisation to a relay chain's validators
//! — the sovereignty the chain exists to keep. Hyperbridge's *solochain* path verifies
//! our consensus instead of taking it: `ismp-grandpa` checks Orbinum's own finality
//! proofs, so the chain reaches Polkadot trustlessly while keeping its validator set.
//!
//! Hence [`ismp_grandpa::consensus::GrandpaConsensusClient`] and **not**
//! `ismp-parachain`, which is for chains that borrow relay-chain consensus.
//!
//! # The unsigned entry point
//!
//! `pallet_ismp::handle_unsigned` takes no signature and charges no fee, so relayers
//! can deliver consensus updates without a funded account on every chain they serve.
//! `#[pallet::validate_unsigned]` runs the full message pipeline and rejects forged
//! proofs, unknown consensus state ids and empty batches at the transaction pool. We
//! deliberately do not filter the call itself: that would break the relayer path this
//! integration exists to enable.
//!
//! What that does not cover: validation runs before any fee logic, so a batch of
//! almost-valid messages costs a node full verification and the submitter nothing.
//! Nothing lands on chain, but the CPU is spent. Bounding it would need a
//! `BaseCallFilter` entry — transaction-pool limits only cap how many candidates
//! queue, not what each one costs to validate.
//!
//! `MAXIMUM_BLOCK_LENGTH` is 8 MiB at an 85% normal ratio because of this pallet:
//! GRANDPA proofs do not fit the previous 5 MiB budget.

pub mod network;
pub mod slot_duration;

use crate::*;
use alloc::{boxed::Box, vec::Vec};
use frame_support::{parameter_types, PalletId};
use frame_system::EnsureRoot;
use ismp::{host::StateMachine, router::IsmpRouter};

parameter_types! {
	/// The coprocessor performs the costly consensus and state-proof verification on
	/// Orbinum's behalf. Which deployment that is depends on the build — see
	/// [`network::HYPERBRIDGE_PARA_ID`].
	pub const Coprocessor: Option<StateMachine> = network::coprocessor();

	/// Orbinum's identifier on the ISMP network. See
	/// [`network::HOST_STATE_MACHINE_ID`] for why it must never change.
	pub const HostStateMachine: StateMachine = network::host_state_machine();

	/// Destination for ISMP relayer fees.
	///
	/// Unused while fees are disabled (see the `FeeHandler` associated type below),
	/// but `WeightFeeHandler` requires the type regardless.
	pub const IsmpTreasuryPalletId: PalletId = PalletId(*b"orb/ismp");
}

/// Fallback for ISMP callbacks addressed to a module we do not host.
///
/// `on_accept`/`on_response` reject; `on_timeout` must not, and the asymmetry is
/// load-bearing. `ismp/src/handlers/timeout.rs` resolves the module *before* it checks
/// the commitment and calls `delete_request_commitment`, propagating with `?`. Erring
/// here would make requests Orbinum itself dispatched impossible to time out — the
/// commitment is never deleted and any fee escrowed via `fund_message` is stranded.
/// Hyperbridge's own runtime does the same: *"instead of returning an error, do
/// nothing. The timeout is for a connected chain."*
#[derive(Default)]
pub struct UnroutedModule;

impl ismp::module::IsmpModule for UnroutedModule {
	fn on_accept(&self, request: ismp::router::PostRequest) -> Result<Weight, anyhow::Error> {
		Err(ismp::Error::ModuleNotFound(request.to).into())
	}

	fn on_response(&self, response: ismp::router::GetResponse) -> Result<Weight, anyhow::Error> {
		Err(ismp::Error::ModuleNotFound(response.get.from).into())
	}

	/// Deliberately `Ok` — see the type docs.
	fn on_timeout(&self, _request: ismp::router::Request) -> Result<Weight, anyhow::Error> {
		Ok(Weight::zero())
	}
}

/// Routes an incoming ISMP request to the module that should handle it.
///
/// `orb/msgs` reaches [`pallet_ismp_messaging`]; everything else gets
/// [`UnroutedModule`]. Always resolves — see [`UnroutedModule`].
///
/// Deleting the match arm below leaves every id resolving to `UnroutedModule` and
/// still passes `router_resolves_every_id`, which is why a separate test asserts our
/// own id reaches our own module.
#[derive(Default)]
pub struct Router;

impl IsmpRouter for Router {
	fn module_for_id(
		&self,
		id: Vec<u8>,
	) -> Result<Box<dyn ismp::module::IsmpModule>, anyhow::Error> {
		if id.as_slice() == pallet_ismp_messaging::PALLET_ID_BYTES {
			return Ok(Box::new(
				pallet_ismp_messaging::inbound::IsmpModuleCallback::<Runtime>::default(),
			));
		}

		Ok(Box::new(UnroutedModule))
	}
}

impl pallet_ismp::Config for Runtime {
	/// Root-only: adding or reconfiguring a consensus client changes whose
	/// cross-chain proofs this chain will trust.
	type AdminOrigin = EnsureRoot<AccountId>;
	type HostStateMachine = HostStateMachine;
	type TimestampProvider = Timestamp;
	type Balance = Balance;
	type Currency = Balances;
	type Router = Router;
	type Coprocessor = Coprocessor;

	/// Only the GRANDPA client. That single choice is what lets a sovereign chain
	/// participate without surrendering consensus.
	///
	/// The 2606 client carries the envelope/state-machine binding built in
	/// (`envelope_matches_state_machine`), so the local `consensus_guard` backport that
	/// existed on 2512 is gone. The wiring test below still asserts the rejection, so a
	/// downgrade or a fork without the check cannot pass silently.
	type ConsensusClients = (ismp_grandpa::consensus::GrandpaConsensusClient<Runtime>,);

	/// No offchain MMR: Orbinum's message flow does not need proof generation.
	type OffchainDB = ();

	/// `POLICY = false` disables relayer fee charging: `on_executed` returns `Pays::No`
	/// before touching balances. Switching it on is a mainnet-economics decision.
	type FeeHandler = pallet_ismp::fee_handler::WeightFeeHandler<
		AccountId,
		Balances,
		<Runtime as pallet_transaction_payment::Config>::WeightToFee,
		IsmpTreasuryPalletId,
		false,
	>;
}

impl ismp_grandpa::Config for Runtime {
	type IsmpHost = pallet_ismp::Pallet<Runtime>;

	/// Root-only: the whitelist decides whose consensus proofs this chain will look at
	/// — the pallet drops datagrams from anything absent from it.
	type RootOrigin = EnsureRoot<AccountId>;

	/// Benchmarked: the unit impl charges a flat 10 ms regardless of `n`, so a
	/// 100-entry batch cost the same as one.
	type WeightInfo = crate::weights::ismp_grandpa::SubstrateWeight<Runtime>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use ismp::module::IsmpModule;

	/// The asymmetry in [`UnroutedModule`] is deliberate, and nothing else asserts it.
	///
	/// `on_accept`/`on_response` reject because Orbinum hosts no application module;
	/// `on_timeout` must **not**, because the timeout handler resolves the module
	/// before it deletes the commitment and propagates the error with `?`. "Tidying"
	/// the three to match would leave every request Orbinum dispatches impossible to
	/// time out, with escrowed fees stranded — and would not fail a single other test
	/// in the suite. Stating both halves in one test makes the asymmetry legible as
	/// intent rather than oversight.
	#[test]
	fn unrouted_module_rejects_delivery_but_never_timeouts() {
		let module = UnroutedModule;

		assert!(
			module.on_accept(sample_post()).is_err(),
			"nothing here answers incoming requests"
		);
		assert!(
			module.on_response(sample_get_response()).is_err(),
			"nothing here answers responses"
		);
		assert!(
			module
				.on_timeout(ismp::router::Request::Post(sample_post()))
				.is_ok(),
			"erring here strands our own outbound requests — see the type docs"
		);
	}

	/// The router must resolve for *any* id, including ones no module claims.
	///
	/// The timeout path calls `module_for_id` with the `from` of a request Orbinum
	/// itself dispatched, so a future real router that matches known ids and errs on
	/// the fallback arm would reintroduce the same stranding through a different door.
	/// Our own id must reach our own module.
	///
	/// `router_resolves_every_id` cannot catch a deleted match arm: with the arm gone
	/// every id still resolves to `UnroutedModule`, so it stays green while inbound
	/// messaging is silently dead. This is the test that notices.
	#[test]
	fn router_resolves_our_id_to_our_module() {
		sp_io::TestExternalities::default().execute_with(|| {
			let router = Router;
			let ours = router
				.module_for_id(pallet_ismp_messaging::PALLET_ID_BYTES.to_vec())
				.expect("our id resolves");

			// `UnroutedModule::on_accept` always errs; ours errs only for an unaccepted
			// source. Both err here — the whitelist is empty in this context — so the two
			// are told apart by the message, which only our module produces.
			let err = ours
				.on_accept(sample_post())
				.expect_err("empty whitelist rejects");
			assert!(
				alloc::format!("{err:?}").contains("unaccepted source"),
				"expected our module's rejection, got: {err:?}"
			);
		});
	}

	/// A near-miss id must NOT reach our module.
	///
	/// Catches a comparison loosened to `starts_with` or a truncating match.
	#[test]
	fn near_miss_ids_do_not_reach_our_module() {
		sp_io::TestExternalities::default().execute_with(|| {
			let router = Router;
			let mut truncated = pallet_ismp_messaging::PALLET_ID_BYTES.to_vec();
			truncated.pop();

			let mut extended = pallet_ismp_messaging::PALLET_ID_BYTES.to_vec();
			extended.push(0);

			let mut flipped = pallet_ismp_messaging::PALLET_ID_BYTES.to_vec();
			flipped[0] ^= 0xff;

			for id in [truncated, extended, flipped] {
				let module = router.module_for_id(id.clone()).expect("still resolves");
				let err = module.on_accept(sample_post()).expect_err("not ours");
				// `UnroutedModule` reports "An Ismp Module was not found"; ours reports
				// "unaccepted source". Matching on the latter's absence is what proves the
				// near-miss did not reach us.
				assert!(
					!alloc::format!("{err:?}").contains("unaccepted source"),
					"id {id:?} must fall through to UnroutedModule, got: {err:?}"
				);
			}
		});
	}

	#[test]
	fn router_resolves_every_id() {
		let router = Router;
		for id in [alloc::vec![], alloc::vec![0u8; 32], alloc::vec![0xab; 1024]] {
			assert!(
				router.module_for_id(id).is_ok(),
				"every id must resolve; the fallback is what keeps timeouts recoverable"
			);
		}
	}

	fn sample_post() -> ismp::router::PostRequest {
		ismp::router::PostRequest {
			source: network::host_state_machine(),
			dest: StateMachine::Kusama(network::HYPERBRIDGE_TESTNET_PARA_ID),
			nonce: 0,
			from: alloc::vec![1, 2, 3, 4],
			to: alloc::vec![5, 6, 7, 8],
			timeout_timestamp: 0,
			body: alloc::vec![],
		}
	}

	fn sample_get_response() -> ismp::router::GetResponse {
		ismp::router::GetResponse {
			get: ismp::router::GetRequest {
				source: network::host_state_machine(),
				dest: StateMachine::Kusama(network::HYPERBRIDGE_TESTNET_PARA_ID),
				nonce: 0,
				from: alloc::vec![1, 2, 3, 4],
				keys: alloc::vec![],
				height: 0,
				context: alloc::vec![],
				timeout_timestamp: 0,
			},
			values: alloc::vec![],
		}
	}
}

impl pallet_ismp_messaging::Config for Runtime {
	/// Root-only. Opening this to signed accounts is an economics decision: the cost of
	/// delivering a message falls on the relayer on the far side of the bridge, so a
	/// local deposit is the wrong currency on the wrong chain. ISMP's own answer is a
	/// non-zero `FeeMetadata.fee`, escrowed on dispatch and paid on delivery.
	type DispatchOrigin = EnsureRoot<AccountId>;

	/// Bounds the cost of decoding a remote party's bytes, and is the range the weights
	/// are measured over. Keep this and the benchmark's upper bound equal.
	type MaxBodyLen = ConstU32<8192>;

	/// Regenerate with:
	/// `benchmark pallet --pallet=pallet_ismp_messaging --extrinsic='*'`
	/// and swap this for `pallet_ismp_messaging::weights::SubstrateWeight<Runtime>`.
	/// The unit impl is conservative by hand, not measured.
	type WeightInfo = ();
}

#[cfg(test)]
mod consensus_binding_tests {
	use super::*;
	use grandpa_verifier_primitives::{ConsensusState, FinalityProof};
	use ismp::host::IsmpHost;
	use ismp_grandpa::messages::{ConsensusMessage, StandaloneChainMessage};
	use scale_codec::Encode;

	/// On 2512 this binding lived in a local wrapper (`consensus_guard.rs`); 2606 builds
	/// it into the client. The wrapper is gone, so this drives the client **the runtime
	/// actually wires** and asserts upstream's own rejection — a fork or downgrade that
	/// drops the check fails here instead of passing silently.
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

	/// The mirror case: a *correct* pairing must get past the binding check. The proof
	/// is garbage, so verification still fails — but with a different error, which is
	/// what distinguishes "envelope rejected" from "envelope accepted, proof bad".
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

		// Hyperbridge's testnet deployment is a parachain tracker; `StandaloneChain` is
		// the envelope the upstream advisory names as the smuggling vector.
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
}
