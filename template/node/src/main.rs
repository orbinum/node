// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Orbinum node binary.

#![allow(clippy::result_large_err)]

fn main() -> sc_cli::Result<()> {
	orbinum_node::run()
}
