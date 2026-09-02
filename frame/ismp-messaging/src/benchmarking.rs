//! Benchmarks for `pallet-ismp-messaging`.
//!
//! Regenerate with:
//!
//! ```text
//! ./target/release/orbinum-node benchmark pallet \
//!   --chain=dev \
//!   --pallet=pallet_ismp_messaging \
//!   --extrinsic='*' \
//!   --steps=50 --repeat=20 \
//!   --wasm-execution=compiled \
//!   --output=./frame/ismp-messaging/src/weights.rs \
//!   --template=./scripts/frame-weight-template.hbs
//! ```
//!
//! Two things here are easy to get wrong. The `Linear` upper bound is `T::MaxBodyLen`,
//! the same constant the runtime enforces — drift would measure a range the runtime
//! allows exceeding. And the padded body still decodes: [`Message::Data`] carries a
//! `Vec<u8>`, so growing the payload grows a field that is really parsed. If padding
//! made it undecodable, the benchmark would measure the cost of *refusing* a message
//! while attributing it to *accepting* one. Each benchmark asserts its intended outcome
//! to stop that.

use super::*;
use crate::{AcceptedSources, InboundCount, inbound::IsmpModuleCallback, payload::Message};
use alloc::{vec, vec::Vec};
use frame_benchmarking::v2::*;
use frame_support::traits::Get;
use frame_system::RawOrigin;
use ismp::{
	host::StateMachine,
	module::IsmpModule,
	router::{GetRequest, GetResponse, PostRequest, Request, StorageValue},
};
use scale_codec::Encode;

/// A counterparty distinct from the coprocessor, so the benchmark exercises the real
/// shape: a message routed *through* Hyperbridge rather than *to* it.
fn counterparty() -> StateMachine {
	StateMachine::Kusama(1000)
}

/// A body of exactly `n` bytes that still decodes as a [`Message`].
///
/// Built by shrinking the `data` field until the SCALE encoding lands on the target, so
/// the measured cost is decoding a real message rather than rejecting a malformed one.
fn body_of_len(n: u32) -> Vec<u8> {
	let n = n as usize;
	// `Message::Data` encodes as: variant (1) + nonce (8) + compact len + data.
	let overhead = Message::Data {
		nonce: 0,
		data: vec![],
	}
	.encode()
	.len();
	if n <= overhead {
		return Message::Ping { nonce: 0 }.encode();
	}
	let mut body = Message::Data {
		nonce: 0,
		data: vec![0u8; n - overhead],
	}
	.encode();
	// A compact length prefix can grow by a byte as `data` crosses a threshold.
	while body.len() > n {
		let shorter = body.len() - n;
		let data_len = n - overhead - shorter;
		body = Message::Data {
			nonce: 0,
			data: vec![0u8; data_len],
		}
		.encode();
	}
	body
}

fn sample_post<T: Config>(source: StateMachine, body: Vec<u8>) -> PostRequest {
	PostRequest {
		source,
		dest: <T as pallet_ismp::Config>::HostStateMachine::get(),
		nonce: 0,
		from: b"remote01".to_vec(),
		to: PALLET_ID_BYTES.to_vec(),
		timeout_timestamp: 0,
		body,
	}
}

#[benchmarks]
mod benchmarks {
	use super::*;

	/// Worst case: a full-length body, plus the commitment and offchain-index writes
	/// that `dispatch_request` performs.
	#[benchmark]
	fn dispatch_post(b: Linear<0, { T::MaxBodyLen::get() }>) {
		let body = body_of_len(b);
		let to = b"demo/mod".to_vec();

		#[extrinsic_call]
		dispatch_post(RawOrigin::Root, counterparty(), to, body, 0u64);

		// Proves the dispatcher accepted it — otherwise this measures the cost of an
		// early rejection.
		assert!(pallet_ismp::Nonce::<T>::get() > 0);
	}

	/// Worst case: one storage write plus the event.
	#[benchmark]
	fn accept_source() {
		let source = counterparty();

		#[extrinsic_call]
		accept_source(RawOrigin::Root, source);

		assert!(AcceptedSources::<T>::contains_key(source));
	}

	/// Worst case: removing an entry that exists.
	#[benchmark]
	fn remove_source() {
		let source = counterparty();
		AcceptedSources::<T>::insert(source, ());

		#[extrinsic_call]
		remove_source(RawOrigin::Root, source);

		assert!(!AcceptedSources::<T>::contains_key(source));
	}

	/// Worst case: an accepted source and a full-length body that decodes, i.e. the
	/// path that does all the work rather than any of the rejection paths.
	///
	/// Not an extrinsic, so `#[block]` rather than `#[extrinsic_call]`.
	#[benchmark]
	fn on_accept(b: Linear<0, { T::MaxBodyLen::get() }>) {
		let source = counterparty();
		AcceptedSources::<T>::insert(source, ());
		let request = sample_post::<T>(source, body_of_len(b));
		let module = IsmpModuleCallback::<T>::default();

		#[block]
		{
			module
				.on_accept(request)
				.expect("accepted source, decodable body");
		}

		// If this were 0 the benchmark measured a rejection, not an acceptance.
		assert_eq!(InboundCount::<T>::get(), 1);
	}

	/// Worst case: every queried key present, so each value is inspected.
	#[benchmark]
	fn on_response(n: Linear<0, 64>) {
		let values = (0..n)
			.map(|i| StorageValue {
				key: i.encode(),
				value: Some(i.encode()),
			})
			.collect::<Vec<_>>();
		let response = GetResponse {
			get: GetRequest {
				source: <T as pallet_ismp::Config>::HostStateMachine::get(),
				dest: counterparty(),
				nonce: 0,
				from: PALLET_ID_BYTES.to_vec(),
				keys: vec![],
				height: 0,
				context: vec![],
				timeout_timestamp: 0,
			},
			values,
		};
		let module = IsmpModuleCallback::<T>::default();

		#[block]
		{
			module
				.on_response(response)
				.expect("responses are always handled");
		}
	}

	/// Worst case: a POST timeout, which carries the larger request variant.
	#[benchmark]
	fn on_timeout() {
		let request = Request::Post(sample_post::<T>(counterparty(), body_of_len(0)));
		let module = IsmpModuleCallback::<T>::default();

		#[block]
		{
			module
				.on_timeout(request)
				.expect("timeouts must never error");
		}
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
