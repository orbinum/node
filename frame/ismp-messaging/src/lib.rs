//! Cross-chain messaging over ISMP, with Hyperbridge as the transport.
//!
//! Hyperbridge is the **coprocessor**: it verifies our consensus and carries the
//! message. It is the route, not the recipient — so [`Call::dispatch_post`] takes
//! `dest` as a parameter and `pallet-ismp` handles routing on its own. An earlier
//! version pinned the destination to the coprocessor, which let Orbinum talk *to*
//! Hyperbridge but never *through* it.
//!
//! `pallet_ismp` exposes no send extrinsic — its calls are only `handle_unsigned`,
//! `create_consensus_client`, `update_consensus_state`, `fund_message` and
//! `update_commitment_caps` — so originating a request means calling
//! [`ismp::dispatcher::IsmpDispatcher`] from a pallet of your own. That is why this
//! one exists.
//!
//! [`outbound`] builds and dispatches; [`inbound`] handles the `IsmpModule` callbacks;
//! [`payload`] is the versioned wire format.
//!
//! Deliberately not feature-gated: a pallet that exists only under `--features test`
//! means the binary being validated is not the binary that ships.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod inbound;
pub mod outbound;
pub mod payload;
pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use pallet::*;
pub use payload::Message;
pub use weights::WeightInfo;

use frame_support::PalletId;
use pallet_ismp::pallet::ModuleId;

/// This pallet's ISMP module identifier — how counterparties address messages to us.
///
/// `ModuleId::from_bytes` infers the variant **from the length alone**: 8 bytes is a
/// pallet, 20 an EVM contract, 32 an account, anything else an error. An earlier value
/// here was 7 bytes, which parses as nothing; it went unnoticed only because our own
/// router ignored the id, while Hyperbridge's runtime would have rejected every message.
///
/// Wire format: changing it once messages are in flight orphans them.
pub const PALLET_ID: ModuleId = ModuleId::Pallet(PalletId(*b"orb/msgs"));

/// [`PALLET_ID`] as raw bytes, for the router's comparison and for `DispatchPost.from`.
pub const PALLET_ID_BYTES: &[u8] = b"orb/msgs";

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::vec::Vec;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use ismp::host::StateMachine;

	#[pallet::pallet]
	// ISMP wire types are variable-length by design, so no `MaxEncodedLen`.
	// `AcceptedSources` is root-written and bounded by governance, not by the type.
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_ismp::Config {
		// No `type RuntimeEvent`: inherited from `frame_system::Config` on this SDK
		// line, and re-declaring it is deprecated.

		/// Origin permitted to dispatch outgoing messages.
		///
		/// Root for now. Opening this is an economics decision: delivery is paid by the
		/// **relayer, on the far side of the bridge**, so a local deposit is the wrong
		/// currency on the wrong chain. ISMP's answer is a non-zero `FeeMetadata.fee`,
		/// escrowed on dispatch and paid to whoever delivers.
		type DispatchOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Largest message body accepted, in bytes, in either direction.
		///
		/// Bounds the cost of SCALE-decoding attacker-supplied input, and is the range
		/// the weights are measured over. Keep it and the benchmark's upper bound equal.
		#[pallet::constant]
		type MaxBodyLen: Get<u32>;

		/// Benchmarked weights.
		type WeightInfo: WeightInfo;
	}

	/// State machines whose messages this chain will accept.
	///
	/// `pallet-ismp` proves an inbound request was included in its source chain's state
	/// or proxied by our coprocessor; it does **not** decide whether we want to hear
	/// from that chain. This map is that decision, and the extension point for reaching
	/// more chains — one entry per counterparty. Empty means accept nothing.
	#[pallet::storage]
	pub type AcceptedSources<T: Config> =
		StorageMap<_, Blake2_128Concat, StateMachine, (), OptionQuery>;

	/// Count of successfully handled inbound messages.
	///
	/// A liveness signal that costs one `u64` write. Bodies are deliberately not stored:
	/// inbound delivery is `Pays::No`, so per-message storage would be unbounded growth
	/// paid for by a remote party.
	#[pallet::storage]
	pub type InboundCount<T: Config> = StorageValue<_, u64, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A request was accepted by the ISMP dispatcher and is awaiting a relayer.
		RequestDispatched {
			/// The chain it is addressed to — not necessarily the coprocessor.
			dest: StateMachine,
			/// The receiving module on `dest`.
			to: Vec<u8>,
			/// Commitment, which is how the request is looked up over RPC.
			commitment: sp_core::H256,
		},
		/// A message arrived and was handled.
		MessageReceived {
			/// Which chain it came from.
			source: StateMachine,
			/// The sending module on that chain, recorded but not authorised — see
			/// [`inbound`] for why.
			from: Vec<u8>,
			/// Body length. The body itself is not emitted: it is remote-controlled
			/// data and every event is stored in the block.
			body_len: u32,
		},
		/// A message arrived from an accepted source but could not be understood.
		///
		/// Deliberately not an error. See [`inbound`].
		MessageRejected {
			/// Which chain it came from.
			source: StateMachine,
			/// Why it was not handled.
			reason: RejectReason,
		},
		/// A response to one of our GET requests arrived.
		GetResponseReceived {
			/// How many keys were queried.
			keys: u32,
			/// How many of them existed. `keys - found` were proven absent.
			found: u32,
		},
		/// A request we dispatched expired without being delivered.
		RequestTimedOut {
			/// Where it had been addressed.
			dest: StateMachine,
		},
		/// A counterparty was added to [`AcceptedSources`].
		SourceAccepted { source: StateMachine },
		/// A counterparty was removed from [`AcceptedSources`].
		SourceRemoved { source: StateMachine },
	}

	/// Why an inbound message was not acted on.
	#[derive(
		Clone,
		Copy,
		PartialEq,
		Eq,
		Debug,
		Encode,
		Decode,
		DecodeWithMemTracking,
		TypeInfo,
		MaxEncodedLen
	)]
	pub enum RejectReason {
		/// Body exceeded [`Config::MaxBodyLen`].
		TooLarge,
		/// Body did not decode as a [`Message`].
		Undecodable,
	}

	#[pallet::error]
	pub enum Error<T> {
		/// No coprocessor configured, so nothing can carry the message.
		CoprocessorNotSet,
		/// Body exceeded [`Config::MaxBodyLen`].
		BodyTooLarge,
		/// `to` is not a valid module id: it must be 8, 20 or 32 bytes.
		InvalidModuleId,
		/// The destination is this chain.
		DestinationIsSelf,
		/// `pallet-ismp` refused the request.
		DispatchFailed,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Send a POST message to `dest`.
		///
		/// `dest` is the final recipient — Hyperbridge routes to it. `timeout` is
		/// **relative seconds**, and `0` means *never expires*, not *expires
		/// immediately* (`ismp::router::get_timeout`).
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::dispatch_post(body.len() as u32))]
		pub fn dispatch_post(
			origin: OriginFor<T>,
			dest: StateMachine,
			to: Vec<u8>,
			body: Vec<u8>,
			timeout: u64,
		) -> DispatchResult {
			T::DispatchOrigin::ensure_origin(origin)?;
			outbound::post::<T>(dest, to, body, timeout)
		}

		/// Start accepting messages from `source`.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::accept_source())]
		pub fn accept_source(origin: OriginFor<T>, source: StateMachine) -> DispatchResult {
			ensure_root(origin)?;
			AcceptedSources::<T>::insert(source, ());
			Self::deposit_event(Event::SourceAccepted { source });
			Ok(())
		}

		/// Stop accepting messages from `source`.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::remove_source())]
		pub fn remove_source(origin: OriginFor<T>, source: StateMachine) -> DispatchResult {
			ensure_root(origin)?;
			AcceptedSources::<T>::remove(source);
			Self::deposit_event(Event::SourceRemoved { source });
			Ok(())
		}
	}
}
