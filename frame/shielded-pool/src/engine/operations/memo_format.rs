// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The memo rules: the one check every memo stored with a new commitment
//! passes ([`ensure_storable`]), and the memo format rule it enforces from a
//! scheduled block on.
//!
//! # The format rule
//!
//! From a scheduled block on, every memo declares its format in nonce byte 1
//! (`TAGGED` or `HANDSHAKE`, see [`MemoFormat`](crate::types::MemoFormat)). A wallet finds a tagged note
//! by lookup, so it may skip the trial ECDH for one it does not predict. That is
//! safe only if no memo after some leaf can be in the old, undeclared format,
//! which no wallet-side rule can promise: an outdated client would still write
//! one. The chain promises it instead, and records the first leaf the promise
//! covers (`TaggedMemosFromLeaf`).
//!
//! The rule is block-based, not leaf-based: it binds every call executed in a
//! block at or past `TaggedMemosFrom`, and the leaf is recorded in that block's
//! `on_initialize`, before any extrinsic runs. So no call's outputs straddle the
//! recorded leaf: a two-output transfer has either both outputs below it, under
//! the old rules, or both at or past it, both checked.
//!
//! Only public bytes are read. Whether a declared tag is the right one depends on
//! keys the chain never sees; a sender who lies about it hides its own payment,
//! which it could always do with a garbage memo. A public memo (zero ephemeral
//! key) and a dummy memo get no exemption: they declare a format like any other.
//! A minted note (`MintOperation`) stores no memo, so there is nothing to check.
//!
//! # Scheduling
//!
//! [`schedule`] (`AdminOrigin`) sets `TaggedMemosFrom`:
//! * it must be a future block, so that block's `on_initialize` records the leaf;
//! * it can be moved, earlier or later, any number of times until the rule is in
//!   force ([`is_active`]); from then on it is fixed for good, since wallets skip
//!   trial ECDH from the recorded leaf on;
//! * there is no upper bound: a start far in the future binds nothing and can be
//!   moved back, which is also how a pending start is called off;
//! * nothing is computed from it, only compared, so no value overflows.

use crate::{
	pallet::{Config, Error, Event, Pallet, TaggedMemosFrom, TaggedMemosFromLeaf},
	storage::MerkleRepository,
	types::EncryptedMemo,
};
use frame_support::{ensure, pallet_prelude::*};
use frame_system::pallet_prelude::BlockNumberFor;

/// Storage reads [`schedule`] makes: `TaggedMemosFromLeaf` and `TaggedMemosFrom`
/// (the block number is whitelisted). It writes `TaggedMemosFrom` once.
pub const SCHEDULE_READS: u64 = 2;

/// Sets the block the rule starts at. See the module docs for the rules.
pub fn schedule<T: Config>(from: BlockNumberFor<T>) -> DispatchResult {
	ensure!(!is_active::<T>(), Error::<T>::TaggedMemosAlreadyActive);
	ensure!(
		from > frame_system::Pallet::<T>::block_number(),
		Error::<T>::TaggedMemosStartInPast
	);
	TaggedMemosFrom::<T>::put(from);
	Pallet::<T>::deposit_event(Event::TaggedMemosScheduled { from });
	Ok(())
}

/// Run in `on_initialize`: in the first block at or past the scheduled one,
/// records the next leaf index as the rule's first leaf. Every leaf this
/// block's extrinsics insert comes after, so every one of them is under the
/// rule. Returns the weight it used.
pub fn record_activation<T: Config>(now: BlockNumberFor<T>) -> Weight {
	let db = T::DbWeight::get();
	if TaggedMemosFromLeaf::<T>::exists() {
		return db.reads(1);
	}
	match TaggedMemosFrom::<T>::get() {
		Some(from) if now >= from => {
			let from_leaf = MerkleRepository::get_tree_size::<T>();
			TaggedMemosFromLeaf::<T>::put(from_leaf);
			Pallet::<T>::deposit_event(Event::TaggedMemosActivated { from_leaf });
			// Two reads above, the tree size, and the leaf plus the event written.
			db.reads_writes(3, 2)
		}
		_ => db.reads(2),
	}
}

/// Whether memos must declare their format now. True from the block the rule
/// starts at, even before its `on_initialize` ran: pool admission validates
/// against the next block on the parent's state.
pub fn is_active<T: Config>() -> bool {
	TaggedMemosFromLeaf::<T>::exists()
		|| TaggedMemosFrom::<T>::get()
			.is_some_and(|from| frame_system::Pallet::<T>::block_number() >= from)
}

/// The one check every memo stored with a new commitment passes, at every call
/// that stores one (shield, transfer outputs, unshield and bound-spend change),
/// before the proof is verified: full size (`InvalidMemoSize`), then, while the
/// rule is in force, a declared format (`MemoFormatOutdated`). Every size is
/// checked before any format, so a short memo is refused as such whatever its
/// second byte holds, and the rule's storage is not read for a memo refused
/// anyway.
pub fn ensure_storable<T: Config>(memos: &[EncryptedMemo]) -> Result<(), Error<T>> {
	ensure!(
		memos.iter().all(EncryptedMemo::is_valid_size),
		Error::<T>::InvalidMemoSize
	);
	if memos.is_empty() || !is_active::<T>() {
		return Ok(());
	}
	ensure!(
		memos.iter().all(|memo| memo.format().is_some()),
		Error::<T>::MemoFormatOutdated
	);
	Ok(())
}
