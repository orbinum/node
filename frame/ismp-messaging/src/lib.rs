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
pub mod receipts;
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
use sp_runtime::traits::Saturating;

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

		/// Who, besides Root, may dispatch outgoing messages — and therefore who pays.
		///
		/// Root always may, and pays nothing: it is this chain's own automation, and it
		/// has no account to debit. Anyone this origin admits pays [`MessageFee`] and must
		/// set a finite timeout — not to get the money back, which never happens, but so the
		/// commitment it leaves behind can eventually be reclaimed.
		type DispatchOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Self::AccountId>;

		/// Starting value for [`MessageFee`], the flat part of what a signed dispatch
		/// costs. Root moves it afterwards with [`Pallet::set_message_fee`].
		///
		/// **Paid to [`Config::FeeDestination`], never refunded** — `crate::outbound::fee_for`
		/// explains why an anti-spam charge must not go through `FeeMetadata.fee`.
		#[pallet::constant]
		type DefaultMessageFee: Get<<Self as pallet_ismp::Config>::Balance>;

		/// Starting value for [`MessageByteFee`], charged on the body of a POST or the keys
		/// of a GET — see `crate::outbound::fee_for` for why size is priced at all.
		#[pallet::constant]
		type DefaultMessageByteFee: Get<<Self as pallet_ismp::Config>::Balance>;

		/// Ceiling on what a single message may be priced at, enforced by
		/// [`Pallet::set_message_fee`].
		///
		/// The fees are adjustable because the right price tracks what the token is worth,
		/// which a constant in the WASM cannot. This keeps that dial from becoming a
		/// foot-gun: a mistyped value cannot price dispatch out of reach until the next
		/// upgrade.
		///
		/// Bounds the **worst-case total** — `fee + byte_fee × `[`outbound::max_chargeable_size`]
		/// — not each term alone, since the per-byte term multiplies. Transposing the two
		/// same-typed arguments of `set_message_fee` is the easy way to reach that.
		#[pallet::constant]
		type MaxMessageFee: Get<<Self as pallet_ismp::Config>::Balance>;

		/// Where message charges go. A treasury or burn account — never one the dispatching
		/// user controls.
		type FeeDestination: Get<Self::AccountId>;

		/// Shortest timeout, in seconds, a signed dispatch may set.
		///
		/// A request is checked against its deadline twice — when Hyperbridge accepts it
		/// and again at the destination (`handlers/request.rs:62-65`, run by the proxy on
		/// each hop) — so one too short to clear two finality rounds can only expire. The
		/// charge is spent either way: refusing the send up front says so, instead of taking
		/// the fee for a message that was never going to arrive.
		#[pallet::constant]
		type MinSignedTimeout: Get<u64>;

		/// Longest timeout, in seconds, a signed dispatch may set.
		///
		/// A request that never expires leaves a commitment nothing will ever clear, so a
		/// signer may not set `0` (never expires) or `u64::MAX`. The fee is not the reason —
		/// it is never refunded — the storage is. Root is exempt: it pays nothing, and its
		/// automation legitimately sends messages that need not expire.
		#[pallet::constant]
		type MaxSignedTimeout: Get<u64>;

		/// Largest message body accepted, in bytes, in either direction.
		///
		/// Bounds the cost of SCALE-decoding attacker-supplied input, and is the range
		/// the weights are measured over. Keep it and the benchmark's upper bound equal.
		#[pallet::constant]
		type MaxBodyLen: Get<u32>;

		/// Largest number of storage keys a single GET may request.
		///
		/// Bounds work we impose on someone else: every key in a GET is a separate
		/// membership proof the relayer must fetch from the destination and the
		/// destination must include. An unbounded GET is a cheap way to make a remote
		/// chain and a relayer do expensive work, so it is capped for the same reason
		/// [`Config::MaxBodyLen`] caps a body.
		#[pallet::constant]
		type MaxGetKeys: Get<u32>;

		/// Longest a single GET storage key may be, in bytes.
		///
		/// The protocol's key shapes are the ceiling: EVM keys are 20 or 52 bytes
		/// (`ismp/src/router.rs:124-126`), Substrate child-trie keys 47-51. A key outside
		/// those shapes cannot have a proof verified against it, so refusing it here turns a
		/// request that could only expire into an immediate error.
		///
		/// Set above the documented maximum, not at it: nothing upstream enforces this — the
		/// protocol type is a bare `Vec<Vec<u8>>` — so the bound is ours alone and leaves
		/// room. Separate from [`Config::MaxBodyLen`], which this used to borrow: sharing one
		/// constant let a GET carry sixteen times a full POST for less declared weight.
		#[pallet::constant]
		type MaxGetKeyLen: Get<u32>;

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

	#[pallet::type_value]
	pub fn DefaultMessageFeeValue<T: Config>() -> <T as pallet_ismp::Config>::Balance {
		T::DefaultMessageFee::get()
	}

	#[pallet::type_value]
	pub fn DefaultMessageByteFeeValue<T: Config>() -> <T as pallet_ismp::Config>::Balance {
		T::DefaultMessageByteFee::get()
	}

	/// Flat charge per signed dispatch. Starts at [`Config::DefaultMessageFee`]; Root moves
	/// it with [`Pallet::set_message_fee`].
	///
	/// Adjustable rather than constant because the right price tracks what ORB is worth,
	/// and a constant in the WASM cannot: correcting it would otherwise cost a build and a
	/// `setCode`. Same reasoning, and the same shape, as `pallet_relayer`'s `MinRelayFee`.
	#[pallet::storage]
	pub type MessageFee<T: Config> =
		StorageValue<_, <T as pallet_ismp::Config>::Balance, ValueQuery, DefaultMessageFeeValue<T>>;

	/// Per-byte charge on top of [`MessageFee`].
	#[pallet::storage]
	pub type MessageByteFee<T: Config> = StorageValue<
		_,
		<T as pallet_ismp::Config>::Balance,
		ValueQuery,
		DefaultMessageByteFeeValue<T>,
	>;

	/// Emergency brake on signed outbound dispatch, set by Root.
	///
	/// Opening `DispatchOrigin` made dispatch reachable by anyone; closing it again would
	/// otherwise need a runtime upgrade, at the moment that hour is most expensive.
	///
	/// Root is unaffected — the check sits in the signed branch of `outbound::fee_for` — so
	/// this chain's own automation keeps working while paused.
	#[pallet::storage]
	pub type OutboundPaused<T: Config> = StorageValue<_, bool, ValueQuery>;

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
			/// The nonce this message went out with, read before the dispatcher consumed
			/// it. `next_nonce` returns the pre-increment value
			/// (`pallet-ismp-2606.1.0/src/host.rs:117`), so this is the nonce a receiver
			/// will see and the one `pallet_ismp`'s own `Request` event reports.
			nonce: u64,
			/// Absolute expiry in unix seconds, reproducing the dispatcher's own branch
			/// (`dispatcher.rs:135`): **`0` means never expires**, not "expired in 1970".
			/// Anything downstream that renders this as a date must special-case zero.
			timeout_timestamp: u64,
			/// Size of the body, which is deliberately not emitted — it is the only thing
			/// this event says about the payload.
			body_len: u32,
			/// Which of the two request shapes this was.
			kind: RequestKind,
		},
		/// A message arrived and was handled.
		MessageReceived {
			source: StateMachine,
			/// Recorded but not authorised — see [`inbound`] for why.
			from: Vec<u8>,
			/// The body itself is not emitted: it is remote-controlled data and every
			/// event is stored in the block.
			body_len: u32,
			/// The sender's commitment for this request, so an observer can join this
			/// arrival to the `Request` the other chain emitted. Derived with the
			/// protocol's own `hash_request`, so it is the same value `pallet-ismp`
			/// reports in `PostRequestHandled` for the very same message.
			commitment: sp_core::H256,
			/// The SENDER's nonce, from the request itself — not one of ours. Lets an
			/// arrival be checked against what the other chain said it sent.
			nonce: u64,
			/// The deadline the sender set, in unix seconds. `0` means never expires.
			timeout_timestamp: u64,
		},
		/// Arrived from an accepted source but could not be understood. Deliberately not
		/// an error — see [`inbound`].
		MessageRejected {
			source: StateMachine,
			reason: RejectReason,
			/// Present for the same reason as on [`Event::MessageReceived`]: without it a
			/// rejection cannot be attributed to a message, and the sender sees only a
			/// timeout.
			commitment: sp_core::H256,
			/// Size of what was refused. Emitted here and the body deliberately is not:
			/// this is the one event whose firing a remote sender controls, so the payload
			/// stays off-chain while its size — already computed — is recorded.
			body_len: u32,
			nonce: u64,
			timeout_timestamp: u64,
		},
		/// A response to one of our GET requests arrived.
		GetResponseReceived {
			keys: u32,
			/// `keys - found` were proven absent.
			found: u32,
			/// Commitment of the GET this answers — `hash_request` over the original
			/// request, which is what `RequestDispatched` recorded. Without it the two
			/// counters describe an anonymous event that cannot be tied to any request.
			commitment: sp_core::H256,
			/// The chain that was read.
			dest: StateMachine,
			/// The REMOTE block height the read was proven against.
			///
			/// The only genuine remote block number this pallet ever sees. An inbound POST
			/// carries none: its proof is verified against Hyperbridge's state rather than
			/// the origin's, so the origin's height never travels on the wire.
			height: u64,
			nonce: u64,
			timeout_timestamp: u64,
		},
		/// A request we dispatched expired without being delivered.
		RequestTimedOut {
			dest: StateMachine,
			/// Which request expired. `on_timeout` receives the whole `Request`, so this
			/// is recoverable at no cost — and it is the only thing that closes out the
			/// `RequestDispatched` row this expiry belongs to.
			commitment: sp_core::H256,
			/// POST or GET. Two different failures: a POST never reached the destination,
			/// a GET's answer never came back.
			kind: RequestKind,
			nonce: u64,
			timeout_timestamp: u64,
			/// `0` for a GET, which has no body.
			body_len: u32,
		},
		// `source` is deliberately absent from this event: `on_timeout` only fires for
		// requests we hold a commitment for (`handlers/timeout.rs:145` — "if we have a
		// commitment, it came from us"), so it is always `HostStateMachine` and would be a
		// constant on the wire. Same rule that keeps `from`/`to` off the events where they
		// cannot vary.
		/// A message this chain dispatched was proven delivered.
		///
		/// Emitted when a [`Call::confirm_delivery`] GET comes back with the receipt
		/// present. There is deliberately **no negative counterpart**: an empty answer
		/// proves the receipt was absent at the height read, which may simply be a height
		/// before delivery. Nothing here can ever say "not delivered".
		DeliveryConfirmed {
			/// The POST being confirmed — read back from the GET's `context`, not the
			/// GET's own commitment, which is a different message entirely.
			commitment: sp_core::H256,
			/// The account that delivered it, as the destination recorded it. Opaque
			/// bytes: a Substrate account is 32 bytes, an EVM relayer 20.
			relayer: Vec<u8>,
			/// The remote height the receipt was proven at. The same field
			/// [`Event::GetResponseReceived`] carries, and the only real remote block
			/// number this pallet ever observes.
			height: u64,
		},
		SourceAccepted {
			source: StateMachine,
		},
		SourceRemoved {
			source: StateMachine,
		},
		/// Signed outbound dispatch was paused or resumed by Root.
		OutboundPauseSet {
			paused: bool,
		},
		/// Root changed what a signed dispatch costs.
		MessageFeeUpdated {
			fee: <T as pallet_ismp::Config>::Balance,
			byte_fee: <T as pallet_ismp::Config>::Balance,
		},
	}

	/// Which kind of ISMP request an event refers to.
	///
	/// One byte, carried on every dispatch and timeout event because a POST expiring and a
	/// GET expiring are different failures — the POST never reached the destination, the
	/// GET's answer never came back — and an indexer cannot tell them apart otherwise.
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
	pub enum RequestKind {
		Post,
		Get,
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
		/// A GET with no keys asks for nothing and would still cost a round trip.
		NoKeysRequested,
		/// Exceeded [`Config::MaxGetKeys`].
		TooManyKeys,
		/// A single GET key exceeded [`Config::MaxGetKeyLen`].
		///
		/// Distinct from [`Error::TooManyKeys`]: the count was fine, one key was not. A
		/// storage key is short; a long one is a payload wearing a key's name, and the
		/// weight charged per key does not cover it.
		KeyTooLarge,
		/// Signed outbound dispatch is paused by Root. Root itself is unaffected.
		OutboundPaused,
		/// A fee update exceeded [`Config::MaxMessageFee`].
		MessageFeeTooHigh,
		/// A signed dispatch set `timeout == 0`, which means *never expires*, so nothing
		/// would ever reclaim its commitment. Root may: its messages are this chain's own
		/// automation, and it pays nothing.
		TimeoutRequired,
		/// A signed dispatch set a timeout below [`Config::MinSignedTimeout`] — too short to
		/// clear Hyperbridge and the destination, so it could only ever expire.
		TimeoutTooShort,
		/// A signed dispatch exceeded [`Config::MaxSignedTimeout`].
		TimeoutTooLong,
		/// The signer cannot cover the charge. Taken before anything is
		/// written, so a failed send costs only the transaction fee.
		InsufficientBalance,
		/// A GET must name the height to read at, and `0` is never a real one.
		///
		/// The response handler requires the proof height to equal the requested height
		/// exactly (`ismp-2606.1.0/src/handlers/response.rs:72`), so a height nobody can
		/// prove leaves the request hanging until it expires rather than failing fast.
		InvalidGetHeight,
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
			let payer = Self::payer_of(origin)?;
			outbound::post::<T>(payer, dest, to, body, timeout)
		}

		/// Read state from `dest` over ISMP.
		///
		/// A GET is answered differently from a POST, and the difference is the point: no
		/// module runs on the destination. A relayer reads the requested keys, proves them
		/// against a state commitment we already hold, and the answer arrives back here as
		/// [`Event::GetResponseReceived`] via our own `on_response`. So a destination
		/// cannot refuse us the way a receiving module can refuse a POST.
		///
		/// "A relayer" is not the public one: Tesseract delivers GET responses only to EVM
		/// sources (`tesseract/messaging/messaging/src/events.rs:314-336`), so on this chain
		/// the answer is carried by `scripts/hyperbridge/relay-get-response.mjs`. The proof
		/// is verified here regardless of who submits it.
		///
		/// `height` must be one this chain can already prove — a height for which
		/// `pallet-ismp` holds a state commitment of `dest`. The response handler compares
		/// it for equality, not as a lower bound, so an unprovable height means the request
		/// simply expires.
		///
		/// `keys` are proven against what this chain holds of `dest`. For the coprocessor
		/// that is its ISMP **child trie** root, not its state root
		/// (`ismp-grandpa/src/consensus.rs:138-147`), so a GET to Hyperbridge can only read
		/// keys inside `:child_storage:default:ISMPv2`.
		///
		/// `timeout` is **relative seconds**; `0` means *never expires*.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::dispatch_get(keys.len() as u32))]
		pub fn dispatch_get(
			origin: OriginFor<T>,
			dest: StateMachine,
			keys: Vec<Vec<u8>>,
			height: u64,
			timeout: u64,
		) -> DispatchResult {
			let payer = Self::payer_of(origin)?;
			// No context: a plain read has nothing to correlate. `confirm_delivery` is the
			// call that fills it.
			outbound::get::<T>(payer, dest, keys, height, timeout, Default::default())
		}

		/// Ask the coprocessor to prove that `commitment` was delivered.
		///
		/// A POST leaves no trace here once dispatched: upstream #840 removed
		/// `PostResponse`, so the destination cannot answer, and nothing on this chain
		/// changes when a message lands. What the destination *does* write is a receipt,
		/// and this dispatches a GET that reads it — see [`crate::receipts`].
		///
		/// **What it proves.** The receipt read is Hyperbridge's, not the final
		/// destination's: `ismp-grandpa` gives this chain the coprocessor's ISMP child trie
		/// root and nothing else, so an `Evm(_)` destination's storage is not provable here
		/// at all. Hyperbridge's proxy re-dispatches through the same `on_accept` that
		/// writes receipts, so a receipt there means **the coprocessor accepted and
		/// forwarded it** — one hop short of execution on the far side, but proven rather
		/// than taken on an RPC's word.
		///
		/// **`height` must be one this chain can already prove**, and the handler compares
		/// it for equality rather than as a lower bound
		/// (`ismp/src/handlers/response.rs:72`). Since nothing tells us which block the
		/// receipt was written in, confirming means retrying at heights we hold commitments
		/// for until one answers. A height we cannot prove does not fail fast — it expires.
		///
		/// A GET that comes back empty proves the receipt was **absent at that height**,
		/// which is not the same as undelivered: it may simply predate it. Hence
		/// [`Event::DeliveryConfirmed`] and no negative counterpart.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::dispatch_get(1))]
		pub fn confirm_delivery(
			origin: OriginFor<T>,
			commitment: sp_core::H256,
			height: u64,
			timeout: u64,
		) -> DispatchResult {
			let payer = Self::payer_of(origin)?;

			// The coprocessor, not the message's destination: it is the only chain whose
			// state this runtime can verify, and the only one whose receipt is reachable.
			let dest = <T as pallet_ismp::Config>::Coprocessor::get()
				.ok_or(Error::<T>::CoprocessorNotSet)?;

			outbound::get::<T>(
				payer,
				dest,
				receipts::confirmation_keys(commitment),
				height,
				timeout,
				commitment.as_bytes().to_vec(),
			)
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

		/// Set what a signed dispatch costs: a flat part and a per-byte part.
		///
		/// Root only, and bounded by what the **largest possible message** would cost —
		/// `fee + byte_fee × `[`outbound::max_chargeable_size`] — against
		/// [`Config::MaxMessageFee`]. Checking each
		/// term separately would miss the case the ceiling is for, since the per-byte term
		/// multiplies. Takes effect on the next dispatch; messages already in flight keep
		/// the price they paid.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::set_message_fee())]
		pub fn set_message_fee(
			origin: OriginFor<T>,
			fee: <T as pallet_ismp::Config>::Balance,
			byte_fee: <T as pallet_ismp::Config>::Balance,
		) -> DispatchResult {
			ensure_root(origin)?;
			// Saturating, so an absurd `byte_fee` is refused rather than wrapping to a
			// small total and passing the check.
			//
			// Priced on `max_chargeable_size`, NOT on `MaxBodyLen`: a GET is charged on the
			// sum of its key lengths, which can exceed a body. Using the body's bound here
			// let `set_message_fee(0, ceiling / MaxBodyLen)` pass and then price the largest
			// GET far above the ceiling it had just cleared.
			let worst_case = fee.saturating_add(byte_fee.saturating_mul(
				sp_runtime::SaturatedConversion::saturated_into(
					outbound::max_chargeable_size::<T>(),
				),
			));
			ensure!(
				worst_case <= T::MaxMessageFee::get(),
				Error::<T>::MessageFeeTooHigh
			);
			MessageFee::<T>::put(fee);
			MessageByteFee::<T>::put(byte_fee);
			Self::deposit_event(Event::MessageFeeUpdated { fee, byte_fee });
			Ok(())
		}

		/// Pause or resume signed outbound dispatch. See [`OutboundPaused`].
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::set_outbound_paused())]
		pub fn set_outbound_paused(origin: OriginFor<T>, paused: bool) -> DispatchResult {
			ensure_root(origin)?;
			OutboundPaused::<T>::put(paused);
			Self::deposit_event(Event::OutboundPauseSet { paused });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		/// Who is dispatching, and so who pays: `None` for Root, which is exempt, and the
		/// account for anyone [`Config::DispatchOrigin`] admits.
		///
		/// Root is checked first and unconditionally, so a runtime that later narrows
		/// `DispatchOrigin` — even to `EnsureNever` — keeps its own automation working.
		fn payer_of(origin: OriginFor<T>) -> Result<Option<T::AccountId>, DispatchError> {
			if ensure_root(origin.clone()).is_ok() {
				return Ok(None);
			}
			T::DispatchOrigin::ensure_origin(origin)
				.map(Some)
				.map_err(Into::into)
		}
	}
}
