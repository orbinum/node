//! Orbinum node binary.

#![allow(clippy::result_large_err)]

fn main() -> sc_cli::Result<()> {
	orbinum_node::run()
}
