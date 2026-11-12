// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Orbinum-local ISMP runtime API, re-exported as `crate::runtime_api`.
//!
//! Neither `Coprocessor` nor `HostStateMachine` is a `#[pallet::constant]` and
//! upstream has no accessor, so without this API a running node cannot be asked for
//! them.

use ismp::host::StateMachine;

sp_api::decl_runtime_apis! {
	/// Build-dependent ISMP identities that are otherwise compile-time only.
	pub trait OrbinumIsmpApi {
		/// The Hyperbridge deployment this build talks to; `None` if ISMP proxying is
		/// disabled.
		fn coprocessor() -> Option<StateMachine>;

		/// The slot duration to whitelist the coprocessor with.
		fn hyperbridge_slot_duration() -> u64;
	}
}
