//! Where an incoming ISMP request is delivered: our own module, or a fallback that
//! refuses delivery but lets our own requests time out.

use crate::Runtime;
use alloc::{boxed::Box, vec::Vec};
use frame_support::weights::Weight;
use ismp::router::IsmpRouter;

/// Fallback for ISMP callbacks addressed to a module we do not host.
///
/// `on_accept`/`on_response` reject; `on_timeout` must not. Upstream's timeout handler
/// (`ismp/src/handlers/timeout.rs`) resolves the module before deleting the request
/// commitment and propagates its error, so erring here would make our own requests
/// impossible to time out and strand any fee escrowed via `fund_message`.
#[derive(Default)]
pub struct UnroutedModule;

impl ismp::module::IsmpModule for UnroutedModule {
	fn on_accept(&self, request: ismp::router::PostRequest) -> Result<Weight, anyhow::Error> {
		Err(ismp::Error::ModuleNotFound(request.to).into())
	}

	fn on_response(&self, response: ismp::router::GetResponse) -> Result<Weight, anyhow::Error> {
		Err(ismp::Error::ModuleNotFound(response.get.from).into())
	}

	/// Always `Ok`; see the type docs.
	fn on_timeout(&self, _request: ismp::router::Request) -> Result<Weight, anyhow::Error> {
		Ok(Weight::zero())
	}
}

/// Routes an incoming ISMP request to the module that should handle it.
///
/// `orb/msgs` reaches [`pallet_ismp_messaging`]; everything else gets
/// [`UnroutedModule`], so every id resolves.
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::configs::ismp::{network, Coprocessor};
	use ismp::{host::StateMachine, module::IsmpModule};
	use scale_codec::Encode;

	/// Delivery is refused, timeouts are not (see [`UnroutedModule`]).
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

	/// Catches a deleted match arm, which `router_resolves_every_id` would not.
	#[test]
	fn router_resolves_our_id_to_our_module() {
		sp_io::TestExternalities::default().execute_with(|| {
			let router = Router;
			let ours = router
				.module_for_id(pallet_ismp_messaging::PALLET_ID_BYTES.to_vec())
				.expect("our id resolves");

			// Both modules err here (the whitelist is empty); only ours reports an
			// unaccepted source.
			let err = ours
				.on_accept(sample_post())
				.expect_err("empty whitelist rejects");
			assert!(
				alloc::format!("{err:?}").contains("unaccepted source"),
				"expected our module's rejection, got: {err:?}"
			);
		});
	}

	/// A message from an accepted source reaches our module through the runtime router,
	/// not the pallet's mock (the pallet's tests call `IsmpModuleCallback` directly).
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
				// Only our module reports "unaccepted source".
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
