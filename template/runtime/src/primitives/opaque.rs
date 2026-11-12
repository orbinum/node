// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Extrinsic-agnostic types for the CLI, so a node keeps syncing across upgrades that
//! change the core data structures; and the session keys.
//!
//! A module of the crate root: `SessionKeys`' path is part of the metadata.

use crate::{Aura, BlockNumber, Grandpa};
use alloc::vec::Vec;
use sp_runtime::{generic, impl_opaque_keys, traits::BlakeTwo256};

pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type BlockId = generic::BlockId<Block>;

impl_opaque_keys! {
	pub struct SessionKeys {
		pub aura: Aura,
		pub grandpa: Grandpa,
	}
}
