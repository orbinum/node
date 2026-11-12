// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Orbinum's own RPCs: ZK verifier, privacy, chain and ISMP.

use std::sync::Arc;

use fc_rpc_v2::{ChainApiServer, ChainRpc, PrivacyApiServer, PrivacyRpc};
use jsonrpsee::{
	types::{error::INVALID_PARAMS_CODE, ErrorObjectOwned, Params},
	RpcModule,
};
use pallet_ismp_rpc::{BlockNumberOrHash, IsmpApiServer, IsmpRpcHandler};
use pallet_zk_verifier_rpc::{ZkVerifier, ZkVerifierApiServer};
use sp_blockchain::HeaderBackend;

use super::MergeResult;
use crate::client::{Backend, Client};
use orbinum_runtime::Hash;

/// `zkVerifier_*`, `privacy_*`, the chain RPC and `ismp_*`.
pub fn merge(
	io: &mut RpcModule<()>,
	client: &Arc<Client>,
	backend: &Arc<Backend>,
	ismp_max_event_blocks: u32,
) -> MergeResult {
	io.merge(ZkVerifier::new(client.clone()).into_rpc())?;
	io.merge(PrivacyRpc::new(client.clone()).into_rpc())?;
	io.merge(ChainRpc::new(client.clone()).into_rpc())?;
	// `new` fails if the backend has no offchain storage: relayers could not see our
	// outgoing requests.
	let mut ismp = IsmpRpcHandler::new(client.clone(), backend.clone())?.into_rpc();
	// Upstream runs these inline on the async workers over any range: each block
	// re-executes the runtime. Served on the blocking pool, within a bounded range.
	ismp.remove_method("ismp_queryEvents");
	ismp.remove_method("ismp_queryEventsWithMetadata");
	let (c, max) = (client.clone(), ismp_max_event_blocks);
	ismp.register_blocking_method("ismp_queryEvents", move |params, handler, _| {
		let (from, to) = event_range(&c, params, max)?;
		handler.query_events(from, to)
	})?;
	let (c, max) = (client.clone(), ismp_max_event_blocks);
	ismp.register_blocking_method("ismp_queryEventsWithMetadata", move |params, handler, _| {
		let (from, to) = event_range(&c, params, max)?;
		handler.query_events_with_metadata(from, to)
	})?;
	io.merge(ismp)?;
	Ok(())
}

type Block = BlockNumberOrHash<Hash>;

/// The `[from, to]` of an `ismp_queryEvents*` call, refused if it spans more
/// than `max` blocks. A block this node does not know is left to the handler.
fn event_range(
	client: &Client,
	params: Params,
	max: u32,
) -> Result<(Block, Block), ErrorObjectOwned> {
	let mut seq = params.sequence();
	let (from, to): (Block, Block) = (seq.next()?, seq.next()?);
	let number = |b: &Block| match b {
		BlockNumberOrHash::Number(n) => Some(*n),
		BlockNumberOrHash::Hash(h) => client.number(*h).ok().flatten(),
	};
	if let (Some(start), Some(end)) = (number(&from), number(&to)) {
		if end >= start && end - start >= max {
			return Err(ErrorObjectOwned::owned(
				INVALID_PARAMS_CODE,
				format!("range spans more than {max} blocks"),
				None::<()>,
			));
		}
	}
	Ok((from, to))
}
