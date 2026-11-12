// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pallet's types: the wire format of the messages it carries ([`payload`]) and
//! the module id counterparties address it by ([`module_id`]).
//!
//! The event enums [`RequestKind`](crate::RequestKind) and
//! [`RejectReason`](crate::RejectReason) are declared in `pallet` instead: a type's
//! module path is part of the runtime metadata.

pub mod module_id;
pub mod payload;

pub use module_id::{PALLET_ID, PALLET_ID_BYTES};
pub use payload::Message;
