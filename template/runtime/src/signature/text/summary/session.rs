// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Session keys, leaving the validator set, and a remark.

use super::{labels::bytes, Line};
use crate::{
	opaque::SessionKeys,
	signature::text::format::{hash_fingerprint, hex},
	RuntimeCall,
};
use alloc::{vec, vec::Vec};

pub(super) fn lines(call: &RuntimeCall) -> Option<Vec<Line>> {
	Some(match call {
		// Keys a validator signs blocks and finality votes with: whoever holds them can get
		// it slashed, so the person sees which keys they register.
		RuntimeCall::Session(pallet_session::Call::set_keys {
			keys: SessionKeys { aura, grandpa },
			proof: _,
		}) => vec![
			(b"aura key", hex(aura.as_ref())),
			(b"grandpa key", hex(grandpa.as_ref())),
		],
		RuntimeCall::System(frame_system::Call::remark { remark }) => vec![
			(b"length", bytes(remark.len())),
			(b"remark", hash_fingerprint(remark)),
		],
		RuntimeCall::Session(pallet_session::Call::purge_keys {})
		| RuntimeCall::ValidatorSet(pallet_validator_set::Call::deregister_validator {}) => Vec::new(),
		_ => return None,
	})
}
