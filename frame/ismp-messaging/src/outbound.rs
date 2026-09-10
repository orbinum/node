//! Building and dispatching outgoing requests.
//!
//! `dest` is the recipient, not the route. Hyperbridge is the coprocessor:
//! `pallet-ismp` consults `T::Coprocessor` on its own, and a caller names the chain it
//! actually wants to reach. Pinning `dest` to the coprocessor — which an earlier
//! revision did — reduces the bridge to a conversation with the bridge.

use crate::{Config, Error, Event, PALLET_ID_BYTES, Pallet, RequestKind};
use alloc::vec::Vec;
use frame_support::{ensure, traits::Get, traits::UnixTime};
use ismp::{
	dispatcher::{DispatchGet, DispatchPost, DispatchRequest, FeeMetadata, IsmpDispatcher},
	host::StateMachine,
};
use pallet_ismp::pallet::ModuleId;
use sp_runtime::{DispatchResult, traits::AccountIdConversion};

/// Validate and dispatch a POST request to `dest`.
///
/// `timeout` is **relative seconds**; `0` means the request never expires
/// (`ismp::router::get_timeout`), which is not the same as expiring at once.
pub fn post<T: Config>(
	dest: StateMachine,
	to: Vec<u8>,
	body: Vec<u8>,
	timeout: u64,
) -> DispatchResult {
	// Local mistakes, caught before spending a nonce and a commitment on a message that
	// can only fail or hang. A message to ourselves is never meaningful.
	ensure!(
		dest != <T as pallet_ismp::Config>::HostStateMachine::get(),
		Error::<T>::DestinationIsSelf
	);

	// `ModuleId::from_bytes` accepts only 8, 20 or 32 bytes — the length *is* the type
	// tag. Otherwise the destination rejects it after we have already paid to relay it.
	ensure!(
		ModuleId::from_bytes(&to).is_ok(),
		Error::<T>::InvalidModuleId
	);

	ensure!(
		body.len() as u32 <= T::MaxBodyLen::get(),
		Error::<T>::BodyTooLarge
	);

	// Not the destination — just confirms a route exists. Dispatching without one would
	// commit a message nothing can carry.
	ensure!(
		<T as pallet_ismp::Config>::Coprocessor::get().is_some(),
		Error::<T>::CoprocessorNotSet
	);

	// Captured BEFORE the dispatch, and before `body` is moved into `DispatchPost`.
	//
	// The nonce must be read pre-dispatch: `next_nonce` returns the value it then
	// increments (`pallet-ismp-2606.1.0/src/host.rs:117`), so reading it afterwards would
	// report the NEXT message's nonce. Reading it here costs nothing extra — the dispatch
	// touches the same storage item in the same overlay.
	let nonce = pallet_ismp::Nonce::<T>::get();
	let body_len = body.len() as u32;

	// Reproduces the dispatcher's own branch (`dispatcher.rs:134`) rather than assuming
	// `now + timeout`: a timeout of 0 stays 0 and means "never expires". Computing
	// `now + 0` here would emit a deadline in the past for a message that has none.
	let timeout_timestamp = if timeout == 0 {
		0
	} else {
		<<T as pallet_ismp::Config>::TimestampProvider as UnixTime>::now()
			.as_secs()
			.saturating_add(timeout)
	};

	let post = DispatchPost {
		dest,
		from: PALLET_ID_BYTES.to_vec(),
		to: to.clone(),
		timeout,
		body,
	};

	let commitment = pallet_ismp::Pallet::<T>::default()
		.dispatch_request(
			DispatchRequest::Post(post),
			// Zero fee, deliberately: Orbinum self-relays, and Hyperbridge's docs call
			// that the intended integration — the relayer is paid offchain in BRIDGE
			// rather than per-message on-chain. `dispatch_request` skips the transfer
			// entirely when the fee is zero, so nothing is escrowed and nobody is owed.
			//
			// A non-zero fee is what Hyperbridge's permissionless relayer network reads
			// to decide whether a message is worth delivering. Setting one only makes
			// sense alongside dropping self-relay, and `Currency` would have to stop
			// being the native token first — an external relayer cannot sell it.
			FeeMetadata {
				payer: payer::<T>(),
				fee: Default::default(),
			},
		)
		.map_err(|_| Error::<T>::DispatchFailed)?;

	Pallet::<T>::deposit_event(Event::RequestDispatched {
		dest,
		to,
		commitment,
		nonce,
		timeout_timestamp,
		body_len,
		kind: RequestKind::Post,
	});
	Ok(())
}

/// Read state from `dest` at `height`.
///
/// The mirror of [`post`], and the asymmetry is what makes it useful: a POST is handed to a
/// module on the destination, which may refuse it — `pallet-ismp-demo` on Hyperbridge, for
/// one, rejects any `Substrate(_)` source outright. A GET is answered by a relayer reading
/// the destination's storage and proving it, so nothing on the far side can turn us away.
/// The answer lands back here in our own `on_response` — carried by our own relaying
/// script for now, since Tesseract only delivers GET responses to EVM sources.
///
/// `timeout` is **relative seconds**; `0` means the request never expires.
pub fn get<T: Config>(
	dest: StateMachine,
	keys: Vec<Vec<u8>>,
	height: u64,
	timeout: u64,
) -> DispatchResult {
	// Reading our own state over ISMP is never meaningful: the round trip proves something
	// we can already read directly.
	ensure!(
		dest != <T as pallet_ismp::Config>::HostStateMachine::get(),
		Error::<T>::DestinationIsSelf
	);

	// A keyless GET still costs a dispatch, a relayer round trip and a response, and
	// answers nothing.
	ensure!(!keys.is_empty(), Error::<T>::NoKeysRequested);

	// Each key is a separate membership proof the destination must produce, so this bounds
	// work we impose on someone else — the same reason a body is bounded.
	ensure!(
		keys.len() as u32 <= T::MaxGetKeys::get(),
		Error::<T>::TooManyKeys
	);

	// Rejected here rather than left to expire. `handlers/response.rs:71` requires the
	// proof height to EQUAL the requested height, so a height no relayer can prove is not
	// a slow request — it is one that can never be answered, and failing now says so.
	ensure!(height > 0, Error::<T>::InvalidGetHeight);

	// Same reasoning as `post`: not the destination, just proof a route exists.
	ensure!(
		<T as pallet_ismp::Config>::Coprocessor::get().is_some(),
		Error::<T>::CoprocessorNotSet
	);

	// Captured before the dispatch consumes the nonce, and before `keys` is moved.
	let nonce = pallet_ismp::Nonce::<T>::get();
	let timeout_timestamp = if timeout == 0 {
		0
	} else {
		<<T as pallet_ismp::Config>::TimestampProvider as UnixTime>::now()
			.as_secs()
			.saturating_add(timeout)
	};

	let get = DispatchGet {
		dest,
		from: PALLET_ID_BYTES.to_vec(),
		keys,
		height,
		timeout,
		// Application metadata travels with the request and comes back on the response.
		// Nothing here needs it, and it is remote-visible, so it stays empty.
		context: Default::default(),
	};

	let commitment = pallet_ismp::Pallet::<T>::default()
		.dispatch_request(
			DispatchRequest::Get(get),
			// Zero fee, for the same reason as `post` — see the note there.
			FeeMetadata {
				payer: payer::<T>(),
				fee: Default::default(),
			},
		)
		.map_err(|_| Error::<T>::DispatchFailed)?;

	Pallet::<T>::deposit_event(Event::RequestDispatched {
		dest,
		// A GET addresses storage, not a module, so there is no `to`. Our own module id
		// goes here because that is what the protocol records as `from` and what the
		// response is routed back to.
		to: PALLET_ID_BYTES.to_vec(),
		commitment,
		nonce,
		timeout_timestamp,
		// A GET has no body. Reported as 0 rather than omitted so the column means the
		// same thing on every row.
		body_len: 0,
		kind: RequestKind::Get,
	});
	Ok(())
}

/// Account recorded as the fee payer.
///
/// Derived from the pallet id because Root has no account; the fee is zero, so nothing
/// is debited. Becomes the signer when the origin opens to signed accounts.
pub fn payer<T: Config>() -> T::AccountId {
	frame_support::PalletId(*b"orb/msgs").into_account_truncating()
}
