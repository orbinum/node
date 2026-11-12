// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The pallet configurations through the runtime.
//!
//! - `block_author`: the block author, from the Aura pre-digest to its account.
//! - `block_limits`: what a block may hold.
//! - `weights`: Substrate weights and fees priced like EVM gas.
//! - `evm_fees`: where an EVM transaction's base fee and tip go.
//! - `offchain`: bare extrinsics built by offchain code.
//! - `governance`: the origin each privileged role requires.

mod block_author;
mod block_limits;
mod evm_fees;
mod governance;
mod offchain;
mod weights;
