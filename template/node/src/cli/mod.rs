// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Command-line arguments.
//!
//! - `substrate_cli`: node identity and the chain spec ids `--chain` accepts.
//! - `overrides`: settings the node enforces over the operator's flags.

mod overrides;
mod substrate_cli;

pub use overrides::{apply_ismp_requirements, ensure_dev_only_flags};

use crate::frontier::EthConfiguration;

/// Available sealing methods.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Sealing {
	/// Seal on `engine_createBlock` RPC calls.
	#[default]
	Manual,
	/// Seal a block whenever a transaction enters the pool.
	Instant,
}

#[derive(Debug, clap::Parser)]
pub struct Cli {
	#[command(subcommand)]
	pub subcommand: Option<Subcommand>,

	#[allow(missing_docs)]
	#[command(flatten)]
	pub run: sc_cli::RunCmd,

	/// Seal blocks on demand instead of with Aura and GRANDPA. Development chains only:
	/// the check reads the spec's `chainType`, so a custom JSON spec that says
	/// `Development` passes it.
	#[arg(long, value_enum, ignore_case = true)]
	pub sealing: Option<Sealing>,

	/// Disable automatic hardware benchmarks.
	#[arg(long)]
	pub no_hardware_benchmarks: bool,

	/// Most blocks one `ismp_queryEvents*` call may span: each re-executes the
	/// runtime at every block of its range. A relayer catching up after a long
	/// outage may need more on the node it reads from.
	#[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u32).range(1..))]
	pub ismp_max_event_blocks: u32,

	#[command(flatten)]
	pub eth: EthConfiguration,
}

#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
	/// Key management CLI utilities.
	#[command(subcommand)]
	Key(sc_cli::KeySubcommand),

	/// Build a chain specification.
	BuildSpec(sc_cli::BuildSpecCmd),

	/// Validate blocks.
	CheckBlock(sc_cli::CheckBlockCmd),

	/// Export blocks.
	ExportBlocks(sc_cli::ExportBlocksCmd),

	/// Export the state of a given block into a chain spec.
	ExportState(sc_cli::ExportStateCmd),

	/// Import blocks.
	ImportBlocks(sc_cli::ImportBlocksCmd),

	/// Remove the whole chain.
	PurgeChain(sc_cli::PurgeChainCmd),

	/// Revert the chain to a previous state.
	Revert(sc_cli::RevertCmd),

	/// Sub-commands concerned with benchmarking.
	#[cfg(feature = "runtime-benchmarks")]
	#[command(subcommand)]
	Benchmark(frame_benchmarking_cli::BenchmarkCmd),

	/// Sub-commands concerned with benchmarking.
	#[cfg(not(feature = "runtime-benchmarks"))]
	Benchmark,

	/// Frontier database meta columns information.
	FrontierDb(fc_cli::FrontierDbCmd),
}

#[cfg(test)]
mod tests {
	use super::Cli;
	use clap::CommandFactory;

	#[test]
	fn cli_definition_is_consistent() {
		Cli::command().debug_assert();
	}
}
