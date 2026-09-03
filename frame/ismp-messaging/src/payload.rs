//! The wire format for messages Orbinum sends and accepts.
//!
//! Codec indices are pinned explicitly: the discriminant is wire format, so letting it
//! shift when a variant is inserted would make old messages decode as the wrong thing —
//! the same class of mistake as moving a pallet index. Append with the next free index;
//! never renumber.

use alloc::vec::Vec;
use scale_codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;

/// An application message carried in a POST body.
#[derive(
	Clone,
	PartialEq,
	Eq,
	Debug,
	Encode,
	Decode,
	DecodeWithMemTracking,
	TypeInfo
)]
pub enum Message {
	/// A liveness probe. The smallest thing that proves the channel works end to end.
	#[codec(index = 0)]
	Ping {
		/// Echoed back by a counterparty that answers, so a reply can be matched to
		/// the message that caused it.
		nonce: u64,
	},

	/// Opaque application payload.
	///
	/// Deliberately untyped: the pallet is transport. It also gives the benchmark a
	/// variant whose encoded length varies, so the weight curve is measured against a
	/// body that actually decodes.
	#[codec(index = 1)]
	Data {
		/// Echoed back by a counterparty that answers.
		nonce: u64,
		/// Application bytes.
		data: Vec<u8>,
	},
}
