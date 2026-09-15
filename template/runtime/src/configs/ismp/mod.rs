//! ISMP / Hyperbridge configuration.
//!
//! Solochain path — [`ismp_grandpa::consensus::GrandpaConsensusClient`], never
//! `ismp-parachain`: Hyperbridge verifies Orbinum's own GRANDPA finality instead of
//! taking consensus over, so the validator set stays sovereign.
//!
//! `handle_unsigned` is unsigned and fee-less by design, so a relayer needs no funded
//! account here; `validate_unsigned` rejects forged proofs at the pool. Known gap: a
//! batch of almost-valid messages costs a node full verification and the submitter
//! nothing. Bounding it would need a chain-wide `BaseCallFilter`.

pub mod network;
pub mod slot_duration;

use crate::*;
use alloc::{boxed::Box, vec::Vec};
use frame_support::{parameter_types, PalletId};
use frame_system::{EnsureRoot, EnsureSigned};
use ismp::{host::StateMachine, router::IsmpRouter};
use sp_runtime::traits::AccountIdConversion;

parameter_types! {
	/// Verifies consensus and state proofs on Orbinum's behalf; which deployment depends
	/// on the build feature. See [`network::coprocessor`].
	pub const Coprocessor: Option<StateMachine> = network::coprocessor();

	/// See [`network::HOST_STATE_MACHINE_ID`] for why it must never change.
	pub const HostStateMachine: StateMachine = network::host_state_machine();

	/// The ISMP treasury: where message charges accumulate, and the account
	/// `WeightFeeHandler` is given for inbound fees it does not currently collect.
	pub const IsmpTreasuryPalletId: PalletId = PalletId(*b"orb/ismp");
	/// The same pallet id as an account, for `Config::FeeDestination`.
	pub IsmpTreasuryAccount: AccountId = IsmpTreasuryPalletId::get().into_account_truncating();

	/// 0.01 ORB per signed dispatch, plus a per-byte term, paid to the ISMP treasury and
	/// never refunded. Starting values only — Root moves both with `set_message_fee`.
	///
	/// Ten times `pallet_relayer`'s 0.001 ORB anti-spam floor, because a cross-chain
	/// dispatch costs this chain real gas on the far side where a shielded relay does not,
	/// and a hundredth of the 1 ORB ceiling that the same pallet already settled on as
	/// "room to react to price swings" (`configs/privacy.rs:23-24`).
	///
	/// Not escrowed in `FeeMetadata`, deliberately — a refundable anti-spam charge is not a
	/// charge, because it can be recycled every timeout. See the pallet's
	/// `outbound::fee_for`.
	pub const IsmpDefaultMessageFee: Balance = 10_000_000_000_000_000;
	/// 0.000001 ORB per byte: a full 8 KiB body adds ~0.008 ORB, roughly doubling the price
	/// of the largest message this chain will carry. Hyperbridge prices its own outbound
	/// traffic per byte for the same reason (`pallet-bandwidth`).
	pub const IsmpDefaultMessageByteFee: Balance = 1_000_000_000_000;
	/// 1 ORB, the same ceiling `pallet_relayer` uses for `MaxMinRelayFee`: far enough above
	/// the default to absorb a token repricing, far below where a typo would price dispatch
	/// out of reach until the next runtime upgrade.
	pub const IsmpMaxMessageFee: Balance = 1_000_000_000_000_000_000;
	/// Ten minutes: two finality rounds — Orbinum→Hyperbridge, Hyperbridge→destination —
	/// each with its challenge period. Shorter can only expire.
	pub const IsmpMinSignedTimeout: u64 = 10 * 60;
	/// A week. The fee comes back only by expiring, so a signer may not set "never".
	pub const IsmpMaxSignedTimeout: u64 = 7 * 24 * 60 * 60;
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
	/// Root-only: it decides whose cross-chain proofs this chain trusts.
	type AdminOrigin = EnsureRoot<AccountId>;
	type HostStateMachine = HostStateMachine;
	type TimestampProvider = Timestamp;
	type Balance = Balance;
	type Currency = Balances;
	type Router = Router;
	type Coprocessor = Coprocessor;

	/// GRANDPA only: the client carries `envelope_matches_state_machine` internally, and
	/// the wiring test below asserts that rejection so a fork without it cannot pass
	/// silently.
	type ConsensusClients = (ismp_grandpa::consensus::GrandpaConsensusClient<Runtime>,);

	type OffchainDB = ();

	/// `POLICY = false` makes message *delivery* free for the submitter: `on_executed`
	/// returns `Pays::No` before charging anyone (`fee_handler.rs:172`).
	///
	/// This is the inbound side, and it is separate from the fee an outbound message
	/// carries — that one lives in `FeeMetadata`: zero from Root, `IsmpMessageFee` from a
	/// signed account, and anti-spam rather than relayer pay in either case since Orbinum
	/// self-relays. Turning `POLICY` on would bill whoever submits an inbound message for
	/// its execution weight, which is a mainnet-economics decision.
	type FeeHandler = pallet_ismp::fee_handler::WeightFeeHandler<
		AccountId,
		Balances,
		<Runtime as pallet_transaction_payment::Config>::WeightToFee,
		IsmpTreasuryPalletId,
		false,
	>;
}

// Commitment retention stays at the pallet default: 10,240 heights is ~17h against a 6s
// counterparty. `update_commitment_caps` (root) overrides it per chain, worth reaching for
// only if we add a client for a sub-second chain.

impl ismp_grandpa::Config for Runtime {
	type IsmpHost = pallet_ismp::Pallet<Runtime>;

	/// Root-only: the pallet drops datagrams from any chain absent from the whitelist.
	type RootOrigin = EnsureRoot<AccountId>;

	/// Benchmarked: the unit impl charges a flat 10 ms regardless of `n`, so a
	/// 100-entry batch cost the same as one.
	type WeightInfo = crate::weights::ismp_grandpa::SubstrateWeight<Runtime>;
}

#[cfg(test)]
mod tests {
	use super::*;
	use ismp::module::IsmpModule;

	/// Asserts both halves of the [`UnroutedModule`] asymmetry — see its docs for why
	/// "tidying" the three to match would strand our own outbound requests.
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

	/// `router_resolves_every_id` stays green with the match arm deleted — every id
	/// falls through to `UnroutedModule`. This is the test that notices.
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

	/// The whole inbound path, through the REAL runtime router rather than the pallet's
	/// mock: a message from an accepted source reaches our module and is handled.
	///
	/// Worth its own test because the pallet's tests call `IsmpModuleCallback` directly.
	/// This is the only place that proves the runtime hands a real `PostRequest` to it —
	/// the step a message from Hyperbridge actually takes, and one nothing else covers.
	#[test]
	fn an_accepted_source_reaches_our_module_through_the_real_router() {
		sp_io::TestExternalities::default().execute_with(|| {
			let coprocessor = Coprocessor::get().expect("a coprocessor is configured");
			pallet_ismp_messaging::AcceptedSources::<Runtime>::insert(coprocessor, ());

			// Addressed the way Hyperbridge addresses us: source is the coprocessor, dest
			// is this chain, `to` is our 8-byte module id.
			let request = ismp::router::PostRequest {
				source: coprocessor,
				dest: network::host_state_machine(),
				nonce: 0,
				from: alloc::vec![9, 9, 9, 9],
				to: pallet_ismp_messaging::PALLET_ID_BYTES.to_vec(),
				timeout_timestamp: 0,
				body: pallet_ismp_messaging::Message::Ping { nonce: 1 }.encode(),
			};

			let module = Router
				.module_for_id(request.to.clone())
				.expect("our id resolves");
			assert!(
				module.on_accept(request).is_ok(),
				"an accepted source must be handled, not refused"
			);
			assert_eq!(
				pallet_ismp_messaging::InboundCount::<Runtime>::get(),
				1,
				"the arrival must be counted by the pallet the router chose"
			);
		});
	}

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
	/// Any signed account may dispatch, paying `IsmpDefaultMessageFee`. Root is always allowed
	/// on top of this and pays nothing — the pallet checks it first — so automation such
	/// as `confirm_delivery` is unaffected by how wide or narrow this is set.
	///
	/// Open since spec 15. The earlier objection — that delivery cost falls on a relayer
	/// on the far side, so a local fee is the wrong currency — still holds for *paying
	/// relayers*; this fee does not try to. It is anti-spam pricing on a self-relayed
	/// channel, charged to the treasury and never refunded — see the pallet's
	/// `outbound::fee_for`.
	type DispatchOrigin = EnsureSigned<AccountId>;
	type DefaultMessageFee = IsmpDefaultMessageFee;
	type DefaultMessageByteFee = IsmpDefaultMessageByteFee;
	type MaxMessageFee = IsmpMaxMessageFee;
	/// The ISMP treasury account, `orb/ismp` — already declared for the inbound fee handler
	/// and unused while that stays disabled, so message charges accumulate somewhere Root
	/// can reach rather than in `ISMPFEES`, which mixes with upstream's escrow accounting.
	type FeeDestination = IsmpTreasuryAccount;
	type MinSignedTimeout = IsmpMinSignedTimeout;
	type MaxSignedTimeout = IsmpMaxSignedTimeout;

	/// Bounds the cost of decoding a remote party's bytes, and is the range the weights
	/// are measured over. Keep this and the benchmark's upper bound equal.
	type MaxBodyLen = ConstU32<8192>;

	/// Storage keys per GET.
	///
	/// Low on purpose: this bounds work we impose on a REMOTE chain and a relayer, since
	/// every key is a separate membership proof they must produce and include. 16 covers
	/// any realistic read — a handful of storage items, or one map's worth of entries —
	/// and a caller who needs more can send a second request.
	type MaxGetKeys = ConstU32<16>;

	/// 128 bytes per storage key: double the longest shape the protocol documents (52, an
	/// EVM address plus a slot hash), because nothing upstream enforces that spec. See the
	/// pallet's `Config::MaxGetKeyLen`.
	type MaxGetKeyLen = ConstU32<128>;

	type WeightInfo = pallet_ismp_messaging::weights::SubstrateWeight<Runtime>;
}

#[cfg(test)]
mod consensus_binding_tests {
	use super::*;
	use grandpa_verifier_primitives::{ConsensusState, FinalityProof};
	use ismp::host::IsmpHost;
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
