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
