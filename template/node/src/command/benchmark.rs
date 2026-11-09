//! `benchmark`: pallet, block, storage, overhead, extrinsic and machine benchmarks.

use frame_benchmarking_cli::{BenchmarkCmd, ExtrinsicFactory, SUBSTRATE_REFERENCE_HARDWARE};
use sc_cli::SubstrateCli;

use super::chain_ops::ChainOps;
use crate::{
	benchmarking::{
		dev_ecdsa_account, inherent_benchmark_data, RemarkBuilder, TransferKeepAliveBuilder,
	},
	cli::Cli,
	client::HostFunctions,
};
use orbinum_runtime::{Hashing, EXISTENTIAL_DEPOSIT};

/// Runs `cmd`.
pub fn run(cli: &Cli, cmd: &BenchmarkCmd) -> sc_cli::Result<()> {
	let runner = cli.create_runner(cmd)?;
	match cmd {
		BenchmarkCmd::Pallet(cmd) => runner.sync_run(|config| {
			cmd.run_with_spec::<Hashing, HostFunctions>(Some(config.chain_spec))
		}),
		BenchmarkCmd::Block(cmd) => {
			runner.sync_run(|mut config| cmd.run(ChainOps::new(&mut config, &cli.eth)?.client))
		}
		BenchmarkCmd::Storage(cmd) => runner.sync_run(|mut config| {
			let ChainOps {
				client, backend, ..
			} = ChainOps::new(&mut config, &cli.eth)?;
			let db = backend.expose_db();
			let storage = backend.expose_storage();
			let shared_cache = backend.expose_shared_trie_cache();
			cmd.run(config, client, db, storage, shared_cache)
		}),
		BenchmarkCmd::Overhead(cmd) => runner.sync_run(|mut config| {
			let client = ChainOps::new(&mut config, &cli.eth)?.client;
			let ext_builder = RemarkBuilder::new(client.clone());
			cmd.run(
				config.chain_spec.name().into(),
				client,
				inherent_benchmark_data()?,
				Vec::new(),
				&ext_builder,
				false,
			)
		}),
		BenchmarkCmd::Extrinsic(cmd) => runner.sync_run(|mut config| {
			let client = ChainOps::new(&mut config, &cli.eth)?.client;
			let ext_factory = ExtrinsicFactory(vec![
				Box::new(RemarkBuilder::new(client.clone())),
				Box::new(TransferKeepAliveBuilder::new(
					client.clone(),
					dev_ecdsa_account("Alice"),
					EXISTENTIAL_DEPOSIT,
				)),
			]);
			cmd.run(client, inherent_benchmark_data()?, Vec::new(), &ext_factory)
		}),
		BenchmarkCmd::Machine(cmd) => {
			runner.sync_run(|config| cmd.run(&config, SUBSTRATE_REFERENCE_HARDWARE.clone()))
		}
	}
}
