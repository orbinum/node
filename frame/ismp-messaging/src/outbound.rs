//! Building and dispatching outgoing requests.
//!
//! `dest` is the recipient, not the route. Hyperbridge is the coprocessor:
//! `pallet-ismp` consults `T::Coprocessor` on its own, and a caller names the chain it
//! actually wants to reach. Pinning `dest` to the coprocessor — which an earlier
//! revision did — reduces the bridge to a conversation with the bridge.

use crate::{Config, Error, Event, PALLET_ID_BYTES, Pallet, RequestKind};
use alloc::vec::Vec;
use frame_support::{
	ensure,
	traits::{Get, UnixTime, fungible::Mutate, tokens::Preservation},
};
use ismp::{
	dispatcher::{DispatchGet, DispatchPost, DispatchRequest, FeeMetadata, IsmpDispatcher},
	host::StateMachine,
};
use pallet_ismp::pallet::ModuleId;
use sp_runtime::{
	DispatchError, DispatchResult, SaturatedConversion,
	traits::{AccountIdConversion, Saturating},
};

/// Longest a `to` module id can be, in bytes.
///
/// Not ours to choose: `ModuleId::from_bytes` takes the length as the type tag — 8 for a
/// pallet, 20 for an EVM contract, 32 for an account, nothing else parses.
const MAX_MODULE_ID_LEN: u64 = 32;

/// Validate and dispatch a POST request to `dest`.
///
/// `payer` is `None` for Root and the signer otherwise — see [`fee_for`] for what each
/// pays. `timeout` is **relative seconds**; `0` means the request never expires
/// (`ismp::router::get_timeout`), which is not the same as expiring at once, and is
/// therefore refused when someone is paying.
pub fn post<T: Config>(
	payer: Option<T::AccountId>,
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

	// Body AND module id, because both travel: Hyperbridge bills a POST by the whole
	// ABI-encoded request (`gargantua/src/ismp.rs:383`, `ismp/core/src/abi.rs:64-76`), `to`
	// included. At most 32 bytes' worth, since `ModuleId::from_bytes` admits no longer id.
	let size = (body.len() as u64).saturating_add(to.len() as u64);
	let fee = fee_for::<T>(payer, timeout, size)?;

	// Captured BEFORE the dispatch, and before `body` is moved into `DispatchPost`.
	//
	// The nonce must be read pre-dispatch: `next_nonce` returns the value it then
	// increments (`pallet-ismp-2606.1.0/src/host.rs:117`), so reading it afterwards would
	// report the NEXT message's nonce. Reading it here costs nothing extra — the dispatch
	// touches the same storage item in the same overlay.
	let nonce = pallet_ismp::Nonce::<T>::get();
	let body_len = body.len() as u32;

	// Reproduces the dispatcher's own branch (`dispatcher.rs:135`) rather than assuming
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

	// `fee.fee` is zero on every path (see `fee_for`), so `dispatch_request` skips its own
	// transfer entirely (`pallet-ismp/src/dispatcher.rs:97-107`): nothing is escrowed here,
	// and nothing upstream can refund.
	let commitment = pallet_ismp::Pallet::<T>::default()
		.dispatch_request(DispatchRequest::Post(post), fee)
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
/// `payer` and `timeout` follow the same rules as [`post`].
pub fn get<T: Config>(
	payer: Option<T::AccountId>,
	dest: StateMachine,
	keys: Vec<Vec<u8>>,
	height: u64,
	timeout: u64,
	context: Vec<u8>,
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

	// And each key's LENGTH, which the count alone does not bound. `dispatch_get`'s weight
	// is charged per key, on the stated assumption that a key is a storage key rather than
	// a payload (`weights.rs:212-214`), so an unbounded key makes that assumption false.
	//
	// Bounded by `MaxGetKeyLen` rather than `MaxBodyLen`: see that constant for why the
	// protocol's own key shapes make 52 bytes the real maximum. Borrowing the body's bound
	// here let one GET carry `MaxGetKeys × MaxBodyLen` bytes — sixteen times a full POST,
	// for less declared weight than one.
	ensure!(
		keys.iter()
			.all(|k| k.len() as u32 <= T::MaxGetKeyLen::get()),
		Error::<T>::KeyTooLarge
	);

	// `context` travels on the wire and comes back inside `GetResponse.get`, so it is
	// attacker-visible bytes whose cost nothing else bounds: `dispatch_get`'s weight is
	// measured per KEY, not per context byte. Reuses `MaxBodyLen` because it is the same
	// kind of thing a POST body is — opaque application bytes we agree to carry.
	ensure!(
		context.len() as u32 <= T::MaxBodyLen::get(),
		Error::<T>::BodyTooLarge
	);

	// Rejected here rather than left to expire. `handlers/response.rs:72` requires the
	// proof height to EQUAL the requested height, so a height no relayer can prove is not
	// a slow request — it is one that can never be answered, and failing now says so.
	ensure!(height > 0, Error::<T>::InvalidGetHeight);

	// Same reasoning as `post`: not the destination, just proof a route exists.
	ensure!(
		<T as pallet_ismp::Config>::Coprocessor::get().is_some(),
		Error::<T>::CoprocessorNotSet
	);

	// Keys AND context: both travel, and the context comes back inside `GetResponse.get`.
	// Summed in `u64` because `sum::<u32>()` uses plain `+` and this profile has no
	// `overflow-checks` — a wrap would hand `fee_for` a near-zero size, i.e. a free message.
	let size = keys
		.iter()
		.fold(0u64, |acc, k| acc.saturating_add(k.len() as u64))
		.saturating_add(context.len() as u64);
	let fee = fee_for::<T>(payer, timeout, size)?;

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
		context,
	};

	let commitment = pallet_ismp::Pallet::<T>::default()
		.dispatch_request(DispatchRequest::Get(get), fee)
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

/// The fee a dispatch carries, and the rules that come with paying one.
///
/// Root (`None`) pays nothing and skips every check — it is this chain's own automation. A
/// signer pays [`crate::MessageFee`] plus [`crate::MessageByteFee`] per byte, **to the
/// treasury, not escrowed**, and that distinction is the whole design.
///
/// `FeeMetadata.fee` is relayer pay, so the protocol refunds it when nobody delivers
/// (`pallet-ismp/src/host.rs:322-334`). An anti-spam charge placed there inherits the refund,
/// and a refundable charge is not a charge: dispatch, wait out the minimum timeout, take it
/// back, repeat — free forever, while this chain pays real gas for every message. So the
/// charge is taken here into [`Config::FeeDestination`] and `FeeMetadata.fee` goes out at
/// zero, which is also what upstream tells self-relaying integrators to do
/// (`developers/polkadot/fees.mdx:11`).
fn fee_for<T: Config>(
	payer: Option<T::AccountId>,
	timeout: u64,
	size: u64,
) -> Result<FeeMetadata<T::AccountId, <T as pallet_ismp::Config>::Balance>, DispatchError> {
	let Some(who) = payer else {
		return Ok(FeeMetadata {
			payer: pallet_account::<T>(),
			fee: Default::default(),
		});
	};

	ensure!(
		!crate::OutboundPaused::<T>::get(),
		Error::<T>::OutboundPaused
	);

	ensure!(timeout != 0, Error::<T>::TimeoutRequired);
	ensure!(
		timeout >= T::MinSignedTimeout::get(),
		Error::<T>::TimeoutTooShort
	);
	ensure!(
		timeout <= T::MaxSignedTimeout::get(),
		Error::<T>::TimeoutTooLong
	);

	// Saturating: `size` is already bounded by [`max_chargeable_size`] — every guard above
	// ran before this — so this cannot be reached with a real call. A saturating add is the
	// right shape for a price anyway, and an overflowing one would wrap to a cheaper fee,
	// which is the wrong direction to fail.
	let fee = crate::MessageFee::<T>::get()
		.saturating_add(crate::MessageByteFee::<T>::get().saturating_mul(size.saturated_into()));

	// Transferred, not merely checked: `Expendable` because `ExistentialDeposit` is zero on
	// this chain, so there is no minimum to preserve and a sender may legitimately spend
	// their last planck. A shortfall fails here with a named error, before a nonce or a
	// commitment is spent on it.
	<T as pallet_ismp::Config>::Currency::transfer(
		&who,
		&T::FeeDestination::get(),
		fee,
		Preservation::Expendable,
	)
	.map_err(|_| Error::<T>::InsufficientBalance)?;

	// Zero on the wire: see above. The payer is still recorded, so the protocol's own
	// accounting names the account that sent the message even though nothing is escrowed.
	Ok(FeeMetadata {
		payer: who,
		fee: Default::default(),
	})
}

/// The largest `size` [`fee_for`] can ever be handed, across every dispatch shape.
///
/// A POST is priced on its body plus its module id; a GET on the sum of its key lengths plus
/// its context. The worst case is whichever of the two totals is larger — today always the
/// GET, since its context term alone is a whole `MaxBodyLen`, but the `max` stays because
/// that is a property of the current constants, not a guarantee. [`crate::Pallet::set_message_fee`] checks its
/// ceiling against this same value, which is the point of it living here: the two were
/// computed separately once, the ceiling used only `MaxBodyLen`, and a per-byte fee at the
/// cap therefore priced the largest GET at sixteen times the ceiling it had just passed.
/// One function, one answer, no way for them to drift apart again.
pub fn max_chargeable_size<T: Config>() -> u64 {
	// A POST is charged its body plus its module id, and `ModuleId::from_bytes` caps that id
	// at 32 bytes (8, 20 or 32 — the length is the type tag).
	let post = u64::from(T::MaxBodyLen::get()).saturating_add(MAX_MODULE_ID_LEN);
	// Widened BEFORE multiplying: two `u32`s do not fit in one. Saturating in `u32` would
	// clamp to `u32::MAX` and so *understate* the worst case, which is what lets
	// `set_message_fee` admit a fee that prices the largest message above the ceiling.
	let get = u64::from(T::MaxGetKeys::get()) * u64::from(T::MaxGetKeyLen::get());
	// Plus the context, which travels on the wire and is charged with the keys.
	let get = get.saturating_add(u64::from(T::MaxBodyLen::get()));
	post.max(get)
}

/// Account recorded as the payer of a Root dispatch.
///
/// Root has no account, so the pallet's own stands in. Its fee is always zero, so it is
/// never actually debited — it is a label in the commitment metadata, nothing more.
pub fn pallet_account<T: Config>() -> T::AccountId {
	frame_support::PalletId(*b"orb/msgs").into_account_truncating()
}
