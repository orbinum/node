// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pallet's types: the admission vocabulary ([`admission`]), the node
//! version a block author declares ([`version`]) and what the runtime plugs in
//! ([`traits`]).

pub mod admission;
pub mod traits;
pub mod version;

pub use admission::{AdmissionMode, BanTerm, Inadmissible};
pub use version::NodeVersion;
