//! Receiving messages: the [`IsmpModule`] callbacks.
//!
//! By the time `on_accept` runs, `ismp/src/handlers/request.rs` has verified a
//! membership proof, rejected duplicates and timed-out requests, confirmed the request
//! is addressed to this chain, and enforced the proxy rules; routing itself proved
//! `request.to` is our module id. Re-checking any of that here would be dead code.
//!
//! What the protocol does *not* decide is whether we want to hear from that chain —
//! hence the [`AcceptedSources`] check below, plus a size bound and a decode.
//!
//! `request.from` is deliberately **not** checked: the chain is pinned by
//! `AcceptedSources` and the contents by the membership proof, so constraining the
//! sending module would break the general case for no security gain. It is recorded in
//! the event instead. A decision, not an oversight.
//!
//! Every event here carries the request's `commitment`. It is not in the callback
//! arguments, but it is free to derive: `hash_request` over the request we were handed is
//! the protocol's own canonical hash — the same value `dispatch_request` returns to the
//! sender and that `pallet-ismp` puts in `PostRequestHandled`. Emitting it is what lets an
//! indexer join an arrival, a rejection or an expiry to the message it belongs to; without
//! it those events are anonymous and a timeout can never be matched to what timed out.
//!
//! **A malformed payload returns `Ok`.** `handle_unsigned` is `#[transactional]` and
//! collects per-request results with `collect::<Result<Vec<_>, _>>()`, so one `Err`
//! reverts the whole batch — including unrelated messages a relayer delivered
//! alongside. An unaccepted *source* does return `Err`, because there the handler
//! deletes the receipt and leaves the request able to time out so the sender recovers.

use crate::{
	AcceptedSources, Config, Event, InboundCount, Message, Pallet, RejectReason, RequestKind,
	WeightInfo,
};
use core::marker::PhantomData;
use frame_support::traits::Get;
use ismp::{
	error::Error as IsmpError,
	messaging::hash_request,
	module::IsmpModule,
	router::{GetResponse, PostRequest, Request},
};
use scale_codec::Decode;
use sp_runtime::Weight;

/// Routes ISMP callbacks into this pallet.
///
/// Separate from `Pallet<T>` so the router hands out something with no other
/// responsibilities, and so the callbacks can be unit-tested without standing up the
/// full message pipeline.
pub struct IsmpModuleCallback<T: Config>(PhantomData<T>);

impl<T: Config> Default for IsmpModuleCallback<T> {
	fn default() -> Self {
		Self(PhantomData)
	}
}

impl<T: Config> IsmpModule for IsmpModuleCallback<T> {
	fn on_accept(&self, request: PostRequest) -> Result<Weight, anyhow::Error> {
		// Erring here is deliberate: it lets the sender's request time out and recover.
		if !AcceptedSources::<T>::contains_key(request.source) {
			Err(IsmpError::Custom(alloc::format!(
				"message from unaccepted source: {}",
				request.source
			)))?
		}

		let body_len = request.body.len() as u32;
		let nonce = request.nonce;
		let timeout_timestamp = request.timeout_timestamp;

		// Hashed once, before any early return: every exit from this callback emits an
		// event and all three need the same value. `Request::Post` is the shape the
		// sender committed to, so this reproduces its commitment exactly rather than
		// inventing a local identifier.
		let commitment = hash_request::<pallet_ismp::Pallet<T>>(&Request::Post(request.clone()));

		// Size before decode, so decoding cost is bounded by a value we chose.
		if body_len > T::MaxBodyLen::get() {
			Pallet::<T>::deposit_event(Event::MessageRejected {
				source: request.source,
				reason: RejectReason::TooLarge,
				commitment,
				body_len,
				nonce,
				timeout_timestamp,
			});
			return Ok(T::WeightInfo::on_accept(body_len));
		}

		// `Ok` on a decode failure — see the module docs.
		let Ok(_message) = Message::decode(&mut &request.body[..]) else {
			Pallet::<T>::deposit_event(Event::MessageRejected {
				source: request.source,
				reason: RejectReason::Undecodable,
				commitment,
				body_len,
				nonce,
				timeout_timestamp,
			});
			return Ok(T::WeightInfo::on_accept(body_len));
		};

		InboundCount::<T>::mutate(|n| *n = n.saturating_add(1));
		Pallet::<T>::deposit_event(Event::MessageReceived {
			source: request.source,
			from: request.from,
			body_len,
			commitment,
			nonce,
			timeout_timestamp,
		});

		// No dispatch from inside a callback: it would write a commitment inside a
		// transaction that can still revert, and add unmetered weight to an extrinsic
		// whose declared weight we do not control. Replying happens in a later block.
		Ok(T::WeightInfo::on_accept(body_len))
	}

	fn on_response(&self, response: GetResponse) -> Result<Weight, anyhow::Error> {
		// `handlers/response.rs` already proved this answers a GET *we* dispatched, at
		// the exact height requested, and not twice. Nothing is left to validate.
		let keys = response.values.len() as u32;
		// `value` is an `Option` because a proof of *absence* is a valid answer.
		let found = response.values.iter().filter(|v| v.value.is_some()).count() as u32;

		// Read off `response.get` BEFORE it is moved into `Request::Get` below. `height` is
		// the one real remote block number this pallet ever sees — the height on the other
		// chain that the read was proven against.
		let dest = response.get.dest;
		let height = response.get.height;
		let nonce = response.get.nonce;
		let timeout_timestamp = response.get.timeout_timestamp;

		// The GET we dispatched, not the response: `RequestDispatched` recorded the
		// request's commitment, so hashing the request is what joins the two. Hashing the
		// response instead would produce a value nothing else on this chain has seen.
		let commitment = hash_request::<pallet_ismp::Pallet<T>>(&Request::Get(response.get));

		Pallet::<T>::deposit_event(Event::GetResponseReceived {
			keys,
			found,
			commitment,
			dest,
			height,
			nonce,
			timeout_timestamp,
		});
		Ok(T::WeightInfo::on_response(keys))
	}

	fn on_timeout(&self, request: Request) -> Result<Weight, anyhow::Error> {
		// Never `Err`, for either variant: the timeout handler resolves the module
		// *before* `delete_request_commitment` and propagates with `?`, so an error
		// strands our own commitment and any escrowed fee. Upstream's
		// `pallet-ismp-demo` errs on `Request::Get` — copying that would be a live bug
		// the moment we dispatch one.
		// One match over borrows, extended to a tuple rather than reaching for
		// `request.body()` / `request.source_module()`: those accessors CLONE the body, and
		// this callback runs inside a `Pays::No` extrinsic where the weight is not ours to
		// spend. A GET has no body, hence 0.
		let (dest, kind, nonce, timeout_timestamp, body_len) = match &request {
			Request::Post(post) => (
				post.dest,
				RequestKind::Post,
				post.nonce,
				post.timeout_timestamp,
				post.body.len() as u32,
			),
			Request::Get(get) => (
				get.dest,
				RequestKind::Get,
				get.nonce,
				get.timeout_timestamp,
				0,
			),
		};

		// Same hash `dispatch_request` returned when this was sent, so the expiry closes
		// out the exact `RequestDispatched` it belongs to. The information was already in
		// hand and previously discarded, which left a timeout unattributable.
		let commitment = hash_request::<pallet_ismp::Pallet<T>>(&request);

		Pallet::<T>::deposit_event(Event::RequestTimedOut {
			dest,
			commitment,
			kind,
			nonce,
			timeout_timestamp,
			body_len,
		});
		Ok(T::WeightInfo::on_timeout())
	}
}
