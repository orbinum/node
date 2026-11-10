//! Shielded pool calls in ORB: the amount, and a shield's commitment and memo.
//!
//! ORB only: other assets have their own decimals, so their amounts cannot be shown as
//! ORB, and such a call is not text-signable. The app derives the commitment and seals
//! the memo; the person compares their fingerprints with what it shows.

use super::Line;
use crate::{
	signature::text::format::{fingerprint, hash_fingerprint, orb},
	Runtime,
};
use alloc::{vec, vec::Vec};
use pallet_shielded_pool::Call;

pub(super) fn lines(call: &Call<Runtime>) -> Option<Vec<Line>> {
	Some(match call {
		Call::shield {
			asset_id: 0,
			amount,
			commitment,
			encrypted_memo,
			proof: _,
			circuit_version: _,
		} => vec![
			(b"amount", orb(*amount)),
			(b"commitment", fingerprint(commitment.as_bytes())),
			(b"memo", hash_fingerprint(encrypted_memo.as_bytes())),
		],
		Call::claim_fees {
			asset_id: 0,
			amount,
		} => vec![(b"amount", orb(*amount))],
		_ => return None,
	})
}
