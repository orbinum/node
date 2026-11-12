// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! What every command shares: the node's types, and its client, databases, import
//! queue and transaction pool (`partial`).

mod partial;
pub mod types;

pub use partial::{new_partial, Partial};
