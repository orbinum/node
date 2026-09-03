//! Building and dispatching outgoing requests.
//!
//! `dest` is the recipient, not the route. Hyperbridge is the coprocessor:
//! `pallet-ismp` consults `T::Coprocessor` on its own, and a caller names the chain it
//! actually wants to reach. Pinning `dest` to the coprocessor — which an earlier
//! revision did — reduces the bridge to a conversation with the bridge.

use crate::{Config, Error, Event, PALLET_ID_BYTES, Pallet};
use alloc::vec::Vec;
use frame_support::{ensure, traits::Get};
use ismp::{
	dispatcher::{DispatchPost, DispatchRequest, FeeMetadata, IsmpDispatcher},
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
			// Zero fee: relayer fees are disabled runtime-wide. A non-zero value would
			// escrow funds that only a timeout releases.
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
