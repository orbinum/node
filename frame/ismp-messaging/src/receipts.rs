//! Reading a destination's delivery receipt.
//!
//! A POST this chain dispatches leaves no trace here once it is handed over. The protocol
//! removed `PostResponse` in upstream #840 (`ismp/src/messaging.rs`: *"the protocol no
//! longer carries `PostResponse`"*), so the destination cannot answer, `on_accept` is the
//! only inbound callback, and a delivered POST is indistinguishable from one still in
//! flight by looking at our own state.
//!
//! What a chain that handles the message *does* leave is a receipt. `handlers/request.rs:112`
//! writes `RequestReceipts[commitment] = relayer` before invoking the receiving module, and
//! `:122-125` **deletes it again if that module errs**. So a receipt's presence proves that
//! chain accepted and handled the message without error — a stronger statement than the
//! `PostRequestHandled` event, which an observer on another chain cannot verify anyway.
//!
//! **Whose receipt matters.** [`crate::Pallet::confirm_delivery`] reads the COPROCESSOR's,
//! not the final destination's, because the coprocessor's ISMP child trie is the only remote
//! state this chain can verify. On Hyperbridge the "receiving module" is its proxy, which
//! re-dispatches onward — so a receipt there proves the message was accepted and forwarded,
//! one hop short of execution on the far side. See that call's docs before reading any
//! stronger claim into a confirmation.
//!
//! That receipt is ordinary storage, and storage is what a GET proves. This module builds
//! the key; [`crate::outbound::get`] carries it.

use alloc::{vec, vec::Vec};
use sp_core::H256;

/// Storage prefix for the receipt map inside the ISMP child trie.
///
/// Wire format, not a name we choose: `pallet-ismp` builds its key as the literal ASCII
/// prefix followed by the raw commitment, with **no hashing of either part**
/// (`pallet-ismp/src/child_trie.rs:71-76`). A GET asks for the key the destination
/// actually wrote, so this string must match theirs byte for byte.
pub const REQUEST_RECEIPTS_PREFIX: &[u8] = b"RequestReceipts";

/// The child trie the receipt lives in, named by `pallet-ismp`'s `CHILD_TRIE_PREFIX`.
///
/// Recorded for the benefit of whoever builds the proof — a GET names keys, not tries, and
/// the relayer resolves the trie from the destination's own configuration.
pub const ISMP_CHILD_TRIE: &[u8] = b"ISMPv2";

/// The storage key of `commitment`'s delivery receipt on the destination chain.
///
/// Mirrors `pallet-ismp`'s `request_receipt_storage_key`. Reproduced rather than imported
/// because it is a *remote* chain's key: we build it to ask someone else for their storage,
/// and their prefix could in principle diverge from the one our own dependency compiles in.
/// A test pins it against a receipt captured from Hyperbridge.
pub fn request_receipt_key(commitment: H256) -> Vec<u8> {
	let mut key = REQUEST_RECEIPTS_PREFIX.to_vec();
	key.extend_from_slice(&commitment.0);
	key
}

/// The GET keys that confirm delivery of `commitment` — exactly one.
///
/// A separate function from [`request_receipt_key`] so the call site reads as "confirm this
/// message" rather than "read this key", and so widening it later (a second key, say) does
/// not change every caller.
pub fn confirmation_keys(commitment: H256) -> Vec<Vec<u8>> {
	vec![request_receipt_key(commitment)]
}

/// Reads the confirmed POST commitment out of a GET's `context`.
///
/// The GET that confirms a delivery has its own commitment, unrelated to the POST it
/// proves, so the response has to carry the link. `DispatchGet.context` is application
/// metadata that travels with the request and comes back inside `GetResponse.get`
/// (`ismp/src/router.rs`), which is what makes a storage map unnecessary: nothing is
/// written when the GET is dispatched, so nothing is orphaned when it expires.
///
/// `None` for any context that is not exactly 32 bytes — an ordinary GET dispatched by
/// someone else, or a future context shape. Returning `None` means "this is not a
/// confirmation", never "the message was not delivered".
pub fn confirmed_commitment(context: &[u8]) -> Option<H256> {
	(context.len() == 32).then(|| H256::from_slice(context))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Captured from Hyperbridge (Gargantua) on 2026-09-11 by reading the child trie
	/// directly over `childstate_getStorage`. The message is the first Orbinum POST
	/// executed on BSC testnet (block 130431639).
	const REAL_COMMITMENT: [u8; 32] =
		hex_literal::hex!("92c95a9bb4e51198b679186b1f8f5224e0bccb1b749744eeea081c8a67fc8de7");

	#[test]
	fn receipt_key_matches_the_one_hyperbridge_answered() {
		let key = request_receipt_key(H256::from(REAL_COMMITMENT));

		// The exact bytes that returned the relayer account from Gargantua's child trie.
		// A typo in the prefix yields an empty proof, which reads as "not delivered" — the
		// single failure this whole feature exists to avoid — so the value is pinned here
		// rather than trusted to the constant above.
		let expected = {
			let mut v = b"RequestReceipts".to_vec();
			v.extend_from_slice(&REAL_COMMITMENT);
			v
		};
		assert_eq!(key, expected);
		assert_eq!(key.len(), 15 + 32);
	}

	#[test]
	fn prefix_is_not_hashed() {
		// `pallet-ismp` concatenates a plain ASCII prefix; it does not hash it the way a
		// `StorageMap` would. Asserting the readable prefix survives means a future
		// "improvement" that hashes it fails here instead of silently querying a key no
		// chain has ever written.
		let key = request_receipt_key(H256::repeat_byte(0xab));
		assert!(key.starts_with(b"RequestReceipts"));
		assert_eq!(&key[15..], &[0xab; 32]);
	}

	#[test]
	fn one_key_per_confirmation() {
		// Each key in a GET is a separate membership proof the destination must produce.
		// Confirmation asks for exactly one, which keeps it well inside `MaxGetKeys`.
		let keys = confirmation_keys(H256::from(REAL_COMMITMENT));
		assert_eq!(keys.len(), 1);
		assert_eq!(keys[0], request_receipt_key(H256::from(REAL_COMMITMENT)));
	}

	#[test]
	fn context_round_trips_the_commitment() {
		let commitment = H256::from(REAL_COMMITMENT);
		assert_eq!(
			confirmed_commitment(commitment.as_bytes()),
			Some(commitment)
		);
	}

	#[test]
	fn a_context_that_is_not_a_commitment_is_not_a_confirmation() {
		// An empty context is what every GET this pallet dispatched before confirmation
		// existed carries. Reading one as a confirmation would attribute a delivery to
		// commitment zero.
		assert_eq!(confirmed_commitment(&[]), None);
		assert_eq!(confirmed_commitment(&[0u8; 31]), None);
		assert_eq!(confirmed_commitment(&[0u8; 33]), None);
	}
}
