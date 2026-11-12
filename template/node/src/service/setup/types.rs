// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Types the service is assembled from.

use orbinum_runtime::{opaque::Block, Hash};

pub use crate::client::TransactionPool;
use crate::client::{Backend, Client};

/// Chooses the best chain to build on: the longest.
pub type SelectChain = sc_consensus::LongestChain<Backend, Block>;
/// GRANDPA's block import, wrapped by Frontier's.
pub type GrandpaBlockImport =
	sc_consensus_grandpa::GrandpaBlockImport<Backend, Block, Client, SelectChain>;
/// What the GRANDPA voter needs from the block import.
pub type GrandpaLinkHalf = sc_consensus_grandpa::LinkHalf<Block, Client, SelectChain>;
/// The libp2p network backend.
pub type Network = sc_network::NetworkWorker<Block, Hash>;

/// Blocks between the justifications GRANDPA imports and generates.
pub const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;
