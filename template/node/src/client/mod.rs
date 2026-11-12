// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! The client, its backend and transaction pool, and the host functions the runtime
//! executes with.

use sc_executor::WasmExecutor;

use orbinum_runtime::{opaque::Block, RuntimeApi};

#[cfg(test)]
mod tests;

/// `frame-benchmarking`'s host functions, registered only in benchmarking builds.
#[cfg(feature = "runtime-benchmarks")]
type BenchmarkingHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
#[cfg(not(feature = "runtime-benchmarks"))]
type BenchmarkingHostFunctions = ();

/// Native Poseidon, registered with `poseidon-native` (default).
#[cfg(feature = "poseidon-native")]
type PoseidonHostFunctions =
	orbinum_zk_core::host_interface::poseidon_host_interface::HostFunctions;
#[cfg(not(feature = "poseidon-native"))]
type PoseidonHostFunctions = ();

/// Host functions the runtime can call.
pub type HostFunctions = (
	sp_io::SubstrateHostFunctions,
	BenchmarkingHostFunctions,
	cumulus_primitives_proof_size_hostfunction::storage_proof_size::HostFunctions,
	orbinum_zk_verifier::host_interface::groth_16_host_interface::HostFunctions,
	PoseidonHostFunctions,
);

/// Full backend.
pub type Backend = sc_service::TFullBackend<Block>;
/// Full client.
pub type Client = sc_service::TFullClient<Block, RuntimeApi, WasmExecutor<HostFunctions>>;
/// The transaction pool.
pub type TransactionPool = sc_transaction_pool::TransactionPoolHandle<Block, Client>;
