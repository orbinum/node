// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! `purge-chain`: the Frontier database, then the chain's.

use crate::{cli::Cli, frontier};

/// Purges the Frontier database of the configured backend type, then the chain database.
pub fn run(cli: &Cli, cmd: &sc_cli::PurgeChainCmd) -> sc_cli::Result<()> {
	use sc_cli::SubstrateCli;
	let runner = cli.create_runner(cmd)?;
	runner.sync_run(|config| {
		frontier::backend::purge(&config, cli.eth.frontier_backend_type, cmd)?;
		cmd.run(config.database)
	})
}
