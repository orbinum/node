//! Cross-chain messaging over ISMP, with Hyperbridge as the transport.
//!
//! Exists because `pallet_ismp` has no send extrinsic: originating a request means
//! calling [`ismp::dispatcher::IsmpDispatcher`] from a pallet of your own.
//! [`Call::dispatch_post`] takes `dest` as a parameter — Hyperbridge is the route, not
//! the recipient.
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
/// pallet, 20 an EVM contract, 32 an account, anything else an error — so this must stay
/// exactly 8 bytes.
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

		type WeightInfo: WeightInfo;
	}

	/// State machines whose messages this chain will accept.
	///
	/// `pallet-ismp` proves an inbound request was included in its source chain's state;
	/// it does **not** decide whether we want to hear from that chain. This map is that
	/// decision — one entry per counterparty, empty means accept nothing.
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
			to: Vec<u8>,
			/// How the request is looked up over RPC.
			commitment: sp_core::H256,
		},
		/// A message arrived and was handled.
		MessageReceived {
			source: StateMachine,
			/// Recorded but not authorised — see [`inbound`] for why.
			from: Vec<u8>,
			/// The body itself is not emitted: it is remote-controlled data and every
			/// event is stored in the block.
			body_len: u32,
		},
		/// Arrived from an accepted source but could not be understood. Deliberately not
		/// an error — see [`inbound`].
		MessageRejected {
			source: StateMachine,
			reason: RejectReason,
		},
		/// A response to one of our GET requests arrived.
		GetResponseReceived {
			keys: u32,
			/// `keys - found` were proven absent.
			found: u32,
		},
		/// A request we dispatched expired without being delivered.
		RequestTimedOut {
			dest: StateMachine,
		},
		SourceAccepted {
			source: StateMachine,
		},
		SourceRemoved {
			source: StateMachine,
		},
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
		TooLarge,
		/// Did not decode as a [`Message`].
		Undecodable,
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Nothing can carry the message.
		CoprocessorNotSet,
		/// Exceeded [`Config::MaxBodyLen`].
		BodyTooLarge,
		/// See [`PALLET_ID`] for the accepted lengths.
		InvalidModuleId,
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

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::accept_source())]
		pub fn accept_source(origin: OriginFor<T>, source: StateMachine) -> DispatchResult {
			ensure_root(origin)?;
			AcceptedSources::<T>::insert(source, ());
			Self::deposit_event(Event::SourceAccepted { source });
			Ok(())
		}

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
