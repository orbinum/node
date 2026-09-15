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
//!   --heap-pages=4096 \
//!   --output=./frame/ismp-messaging/src/weights.rs \
//!   --template=./scripts/benchmarks/frame-weight-template.hbs
//! ```
//!
//! The template path and `--heap-pages` are copied from the `Executed Command` block that
//! the generator itself recorded in `weights.rs`, which is the only record of what actually
//! produced the current numbers. An earlier version of this comment named
//! `./scripts/frame-weight-template.hbs`, which does not exist — the command failed for
//! anyone who pasted it.
//!
//! **After regenerating**, `declared_proof_sizes_stay_within_a_sane_ceiling` in `tests.rs`
//! is the thing to run first: the CLI has a bug that writes an absurd `proof_size`, and the
//! header in `weights.rs` that documents it is deleted by the very regeneration that can
//! reintroduce it. See that header for the hand-correction to re-apply.
//!
//! Two things here are easy to get wrong. The `Linear` upper bound is `T::MaxBodyLen`,
//! the same constant the runtime enforces — drift would measure a range the runtime
//! allows exceeding. And the padded body still decodes: [`Message::Data`] carries a
//! `Vec<u8>`, so growing the payload grows a field that is really parsed. If padding
//! made it undecodable, the benchmark would measure the cost of *refusing* a message
//! while attributing it to *accepting* one. Each benchmark asserts its intended outcome
//! to stop that.
//!
//! Dispatches are measured from a **signed, funded** caller, not Root: that is the path
//! that also pays the message charge — one balance transfer more than Root's — and the
//! weight must cover the dearer of the two.

use super::*;
use crate::{AcceptedSources, InboundCount, inbound::IsmpModuleCallback, payload::Message};
use alloc::{vec, vec::Vec};
use frame_benchmarking::v2::*;
use frame_support::traits::{
	Get,
	fungible::{Inspect, Mutate},
};
use frame_system::RawOrigin;
use ismp::{
	host::StateMachine,
	module::IsmpModule,
	router::{GetRequest, GetResponse, PostRequest, Request, StorageValue},
};
use scale_codec::Encode;
use sp_runtime::{SaturatedConversion, traits::Saturating};

/// A counterparty distinct from the coprocessor, so the benchmark exercises the real
/// shape: a message routed *through* Hyperbridge rather than *to* it.
fn counterparty() -> StateMachine {
	StateMachine::Kusama(1000)
}

/// A finite timeout inside `MaxSignedTimeout`: the signed path refuses `0`.
const TIMEOUT: u64 = 3_600;

type Currency<T> = <T as pallet_ismp::Config>::Currency;

/// A caller who can afford the worst case, so the dispatch measured is the one that pays.
///
/// The charge is flat + per byte, so a full-length body costs far more than the flat fee
/// alone: funding only a few multiples of `MessageFee` fails the largest `Linear` step with
/// `InsufficientBalance` and measures a rejection instead of a dispatch.
fn funded_caller<T: Config>() -> T::AccountId {
	let who: T::AccountId = whitelisted_caller();
	// Priced on `max_chargeable_size`, so the funding covers the dearest shape — a full GET
	// can out-cost a full POST, and funding only the body's worth made the largest step of
	// `dispatch_get` fail with `InsufficientBalance`, measuring a rejection.
	let worst = crate::MessageFee::<T>::get().saturating_add(
		crate::MessageByteFee::<T>::get()
			.saturating_mul(crate::outbound::max_chargeable_size::<T>().saturated_into()),
	);
	// Ten worst-case messages: enough for every step of every benchmark in this module.
	Currency::<T>::set_balance(&who, worst.saturating_mul(10u32.into()));
	who
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
	/// that `dispatch_request` performs, plus the charge a signed caller pays.
	#[benchmark]
	fn dispatch_post(b: Linear<0, { T::MaxBodyLen::get() }>) {
		let caller = funded_caller::<T>();
		let before = Currency::<T>::balance(&caller);
		let body = body_of_len(b);
		let to = b"demo/mod".to_vec();

		#[extrinsic_call]
		dispatch_post(
			RawOrigin::Signed(caller.clone()),
			counterparty(),
			to,
			body,
			TIMEOUT,
		);

		// Proves the dispatcher accepted it — otherwise this measures the cost of an
		// early rejection — and that the charge really moved, so it is in the number.
		assert!(pallet_ismp::Nonce::<T>::get() > 0);
		assert!(Currency::<T>::balance(&caller) < before);
	}

	/// Worst case: every key slot used, **each key at its maximum length**. Each key is a
	/// separate membership proof the destination must later produce, but on *this* chain the
	/// cost is the per-key encoding into the request plus the same charge and commitment
	/// writes as a POST.
	///
	/// Keys are `MaxGetKeyLen` bytes, not `i.encode()`. The earlier form measured 4-byte keys
	/// while the runtime accepted far longer ones, so the component was varied over key COUNT
	/// with key SIZE pinned at its minimum — the dimension that actually drives cost held at
	/// the cheapest value.
	#[benchmark]
	fn dispatch_get(k: Linear<1, { T::MaxGetKeys::get() }>) {
		let caller = funded_caller::<T>();
		let before = Currency::<T>::balance(&caller);
		let key_len = T::MaxGetKeyLen::get() as usize;
		let keys = (0..k).map(|_| vec![0u8; key_len]).collect::<Vec<_>>();

		#[extrinsic_call]
		dispatch_get(
			RawOrigin::Signed(caller.clone()),
			counterparty(),
			keys,
			1u64,
			TIMEOUT,
		);

		assert!(pallet_ismp::Nonce::<T>::get() > 0);
		assert!(Currency::<T>::balance(&caller) < before);
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

	/// Worst case: two storage writes and an event.
	///
	/// Prices the largest legal message exactly at the ceiling — the flat term takes what
	/// the per-byte term leaves — so the benchmark exercises the branch that computes the
	/// worst case rather than an early rejection.
	///
	/// Divided by `max_chargeable_size`, the same quantity the extrinsic checks against: a
	/// GET is priced on its keys, so dividing by `MaxBodyLen` alone would overshoot the
	/// ceiling on any chain where a full GET outweighs a full body, and the benchmark would
	/// measure the rejection instead of the write.
	#[benchmark]
	fn set_message_fee() {
		let max = T::MaxMessageFee::get();
		let worst: <T as pallet_ismp::Config>::Balance =
			crate::outbound::max_chargeable_size::<T>().saturated_into();
		let byte_fee = max / worst;
		let fee = max.saturating_sub(byte_fee.saturating_mul(worst));

		#[extrinsic_call]
		set_message_fee(RawOrigin::Root, fee, byte_fee);

		assert_eq!(crate::MessageFee::<T>::get(), fee);
		assert_eq!(crate::MessageByteFee::<T>::get(), byte_fee);
	}

	/// Worst case: one storage write and an event.
	#[benchmark]
	fn set_outbound_paused() {
		#[extrinsic_call]
		set_outbound_paused(RawOrigin::Root, true);

		assert!(crate::OutboundPaused::<T>::get());
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

	/// Worst case: every queried key present at full length, and the confirmation branch
	/// taken.
	///
	/// Three things here were previously measured at their cheapest, and each one is the
	/// dimension that drives the real cost:
	///
	/// - The range was a hardcoded `Linear<0, 64>`, tracking no constant. `values` comes back
	///   one-per-requested-key (`handlers/response.rs:85-89`), so `MaxGetKeys` is what bounds
	///   it — the same drift the module header warns about, in the one benchmark that had it.
	/// - Keys were `i.encode()`, four bytes. `inbound::on_response` finds its key by
	///   comparing `Vec<u8>`s, so cost scales with key LENGTH, not count. `MaxGetKeyLen` is
	///   the bound the runtime enforces.
	/// - `context` was empty, so `confirmed_commitment` returned `None` and the
	///   `DeliveryConfirmed` branch — the expensive one, a `find` plus a `Vec<u8>::decode` —
	///   never ran at all. A 32-byte context and a matching receipt key make it run.
	#[benchmark]
	fn on_response(n: Linear<0, { T::MaxGetKeys::get() }>) {
		let commitment = sp_core::H256::repeat_byte(7);
		let receipt_key = crate::receipts::request_receipt_key(commitment);
		let key_len = T::MaxGetKeyLen::get() as usize;

		// Padding first, the receipt key LAST, so the `find` in `on_response` scans every
		// entry before it matches. Putting it first made the search succeed on its first
		// comparison and short-circuit — measuring the cheapest case under a doc comment
		// promising the dearest. Each padding key is full length and differs from the receipt
		// key, so every comparison does real work before failing.
		let mut values = (1..n)
			.map(|i| StorageValue {
				key: {
					let mut k = vec![0u8; key_len];
					k[0] = i as u8;
					k
				},
				value: Some(vec![0u8; 32]),
			})
			.collect::<Vec<_>>();
		if n > 0 {
			values.push(StorageValue {
				key: receipt_key,
				value: Some(vec![0u8; 32].encode()),
			});
		}

		let response = GetResponse {
			get: GetRequest {
				source: <T as pallet_ismp::Config>::HostStateMachine::get(),
				dest: counterparty(),
				nonce: 0,
				from: PALLET_ID_BYTES.to_vec(),
				keys: vec![],
				height: 0,
				context: commitment.as_bytes().to_vec(),
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

	/// Worst case: a POST timeout at full body length.
	///
	/// `on_timeout` hashes the request to name it in the event, and `hash_request` clones and
	/// SCALE-encodes the whole thing — so cost scales with the body. The comment here always
	/// claimed "the larger request variant" while the code passed an empty body.
	#[benchmark]
	fn on_timeout() {
		let request = Request::Post(sample_post::<T>(
			counterparty(),
			body_of_len(T::MaxBodyLen::get()),
		));
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
