// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Subcommand dispatch.
//!
//! - `chain_ops`: the components the chain subcommands run on.
//! - `purge`: `purge-chain`, Frontier's database included.
//! - `benchmark`: the `benchmark` subcommands.

#[cfg(feature = "runtime-benchmarks")]
mod benchmark;
mod chain_ops;
mod purge;

use futures::TryFutureExt;
use sc_cli::SubstrateCli;

use self::chain_ops::ChainOps;
use crate::{
	cli::{self, Cli, Subcommand},
	service,
};

/// Parses the command line and runs the node or the subcommand.
pub fn run() -> sc_cli::Result<()> {
	let mut cli = Cli::from_args();
	cli::apply_ismp_requirements(&mut cli.run);

	match &cli.subcommand {
		Some(Subcommand::Key(cmd)) => cmd.run(&cli),
		Some(Subcommand::BuildSpec(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
		}
		Some(Subcommand::CheckBlock(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
			let ops = ChainOps::new(&mut config, &cli.eth)?;
			Ok((cmd.run(ops.client, ops.import_queue), ops.task_manager))
		}),
		Some(Subcommand::ExportBlocks(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
			let ops = ChainOps::new(&mut config, &cli.eth)?;
			Ok((cmd.run(ops.client, config.database), ops.task_manager))
		}),
		Some(Subcommand::ExportState(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
			let ops = ChainOps::new(&mut config, &cli.eth)?;
			Ok((cmd.run(ops.client, config.chain_spec), ops.task_manager))
		}),
		Some(Subcommand::ImportBlocks(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
			let ops = ChainOps::new(&mut config, &cli.eth)?;
			Ok((cmd.run(ops.client, ops.import_queue), ops.task_manager))
		}),
		Some(Subcommand::PurgeChain(cmd)) => purge::run(&cli, cmd),
		Some(Subcommand::Revert(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
			let ops = ChainOps::new(&mut config, &cli.eth)?;
			let aux_revert = Box::new(move |client, _, blocks| {
				sc_consensus_grandpa::revert(client, blocks)?;
				Ok(())
			});
			Ok((
				cmd.run(ops.client, ops.backend, Some(aux_revert)),
				ops.task_manager,
			))
		}),
		#[cfg(feature = "runtime-benchmarks")]
		Some(Subcommand::Benchmark(cmd)) => benchmark::run(&cli, cmd),
		#[cfg(not(feature = "runtime-benchmarks"))]
		Some(Subcommand::Benchmark) => Err("Benchmarking wasn't enabled when building the node. \
			You can enable it with `--features runtime-benchmarks`."
			.into()),
		Some(Subcommand::FrontierDb(cmd)) => cli.create_runner(cmd)?.sync_run(|mut config| {
			let ops = ChainOps::new(&mut config, &cli.eth)?;
			let fc_db::Backend::KeyValue(frontier_backend) = ops.frontier_backend else {
				return Err("frontier-db supports only `--frontier-backend-type key-value`".into());
			};
			cmd.run(ops.client, frontier_backend)
		}),
		None => {
			let runner = cli.create_runner(&cli.run)?;
			cli::ensure_dev_only_flags(
				&runner.config().chain_spec.chain_type(),
				cli.sealing,
				cli.eth.enable_dev_signer,
			)?;
			runner.run_node_until_exit(|config| async move {
				service::new_full(
					config,
					cli.eth,
					cli.sealing,
					!cli.no_hardware_benchmarks,
					cli.ismp_max_event_blocks,
				)
				.map_err(Into::into)
				.await
			})
		}
	}
}
