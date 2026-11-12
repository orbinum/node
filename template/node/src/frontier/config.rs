// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Ethereum-compatibility command-line settings.

/// Where Frontier keeps its Ethereum mapping and log index.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum BackendType {
	/// RocksDb or ParityDb, the same as the node's database.
	#[default]
	KeyValue,
	/// SQLite, with log indexing.
	Sql,
}

/// The Ethereum-compatibility configuration used to run a node.
#[derive(Clone, Debug, clap::Parser)]
pub struct EthConfiguration {
	/// Maximum number of logs in a query.
	#[arg(long, default_value = "10000")]
	pub max_past_logs: u32,

	/// Maximum block range for eth_getLogs.
	#[arg(long, default_value = "1024")]
	pub max_block_range: u32,

	/// Maximum fee history cache size, in blocks.
	#[arg(long, default_value = "2048")]
	pub fee_history_limit: u64,

	/// Sign `eth_sendTransaction` with the well-known development keys. Development chains
	/// only: the check reads the spec's `chainType`, so a custom JSON spec that says
	/// `Development` passes it.
	#[arg(long)]
	pub enable_dev_signer: bool,

	/// `eth_call` and `eth_estimateGas` run with at most `block.gas_limit *
	/// execute_gas_limit_multiplier` gas, and no timeout. The default (1) caps a call at
	/// one block's compute; a higher value lets any caller of a public endpoint spend that
	/// many blocks of CPU per request.
	#[arg(long, default_value = "1")]
	pub execute_gas_limit_multiplier: u64,

	/// Size in bytes (SCALE-encoded) of the LRU cache for Ethereum blocks (default 64 MiB).
	/// Filled only by RPC reads; a limit below one block keeps just the latest one.
	#[arg(long, default_value = "67108864")]
	pub eth_log_block_cache: usize,

	/// Size in bytes (SCALE-encoded) of the LRU cache for transaction statuses (default
	/// 64 MiB).
	#[arg(long, default_value = "67108864")]
	pub eth_statuses_cache: usize,

	/// Frontier backend type.
	#[arg(long, value_enum, ignore_case = true, default_value_t = BackendType::default())]
	pub frontier_backend_type: BackendType,

	/// SQL backend's connection pool size.
	#[arg(long, default_value = "100")]
	pub frontier_sql_backend_pool_size: u32,

	/// SQL backend's query timeout, in VM ops.
	#[arg(long, default_value = "10000000")]
	pub frontier_sql_backend_num_ops_timeout: u32,

	/// SQL backend's auxiliary thread limit.
	#[arg(long, default_value = "4")]
	pub frontier_sql_backend_thread_count: u32,

	/// SQL backend's cache size, in bytes (default 200 MiB).
	#[arg(long, default_value = "209715200")]
	pub frontier_sql_backend_cache_size: u64,

	/// Allow RPC submission of unprotected legacy transactions (without EIP-155 chain id).
	#[arg(long, default_value_t = false)]
	pub rpc_allow_unprotected_txs: bool,

	/// Maximum pending pubsub notifications per subscriber before it is dropped.
	#[arg(long, default_value = "512")]
	pub pubsub_max_pending_notifications: usize,

	/// Maximum retained bytes across the reorg-aware log journal.
	#[arg(long, default_value = "536870912")]
	pub logs_journal_max_total_bytes: usize,
}

#[cfg(test)]
mod tests {
	use crate::cli::Cli;
	use clap::Parser;

	fn eth(args: &[&str]) -> super::EthConfiguration {
		Cli::try_parse_from(std::iter::once("orbinum-node").chain(args.iter().copied()))
			.expect("valid arguments")
			.eth
	}

	#[test]
	fn eth_call_gas_is_capped_at_one_block_by_default() {
		assert_eq!(eth(&[]).execute_gas_limit_multiplier, 1);
		assert_eq!(
			eth(&["--execute-gas-limit-multiplier", "3"]).execute_gas_limit_multiplier,
			3
		);
	}
}
