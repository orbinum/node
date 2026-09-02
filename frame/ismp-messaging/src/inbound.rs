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
//! **A malformed payload returns `Ok`.** `handle_unsigned` is `#[transactional]` and
//! collects per-request results with `collect::<Result<Vec<_>, _>>()`, so one `Err`
//! reverts the whole batch — including unrelated messages a relayer delivered
//! alongside. An unaccepted *source* does return `Err`, because there the handler
//! deletes the receipt and leaves the request able to time out so the sender recovers.

use crate::{
	AcceptedSources, Config, Event, InboundCount, Message, Pallet, RejectReason, WeightInfo,
};
use core::marker::PhantomData;
use frame_support::traits::Get;
use ismp::{
	error::Error as IsmpError,
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

		// Size before decode, so decoding cost is bounded by a value we chose.
		if body_len > T::MaxBodyLen::get() {
			Pallet::<T>::deposit_event(Event::MessageRejected {
				source: request.source,
				reason: RejectReason::TooLarge,
			});
			return Ok(T::WeightInfo::on_accept(body_len));
		}

		// `Ok` on a decode failure — see the module docs.
		let Ok(_message) = Message::decode(&mut &request.body[..]) else {
			Pallet::<T>::deposit_event(Event::MessageRejected {
				source: request.source,
				reason: RejectReason::Undecodable,
			});
			return Ok(T::WeightInfo::on_accept(body_len));
		};

		InboundCount::<T>::mutate(|n| *n = n.saturating_add(1));
		Pallet::<T>::deposit_event(Event::MessageReceived {
			source: request.source,
			from: request.from,
			body_len,
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

		Pallet::<T>::deposit_event(Event::GetResponseReceived { keys, found });
		Ok(T::WeightInfo::on_response(keys))
	}

	fn on_timeout(&self, request: Request) -> Result<Weight, anyhow::Error> {
		// Never `Err`, for either variant: the timeout handler resolves the module
		// *before* `delete_request_commitment` and propagates with `?`, so an error
		// strands our own commitment and any escrowed fee. Upstream's
		// `pallet-ismp-demo` errs on `Request::Get` — copying that would be a live bug
		// the moment we dispatch one.
		let dest = match &request {
			Request::Post(post) => post.dest,
			Request::Get(get) => get.dest,
		};

		Pallet::<T>::deposit_event(Event::RequestTimedOut { dest });
		Ok(T::WeightInfo::on_timeout())
	}
}
