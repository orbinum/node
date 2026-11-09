//! Node identity and the chain spec ids `--chain` accepts.

use sc_cli::{ChainSpec, SubstrateCli};

use super::Cli;
use crate::chain_spec;

impl SubstrateCli for Cli {
	fn impl_name() -> String {
		"Orbinum Node".into()
	}

	fn impl_version() -> String {
		env!("SUBSTRATE_CLI_IMPL_VERSION").into()
	}

	fn description() -> String {
		env!("CARGO_PKG_DESCRIPTION").into()
	}

	fn author() -> String {
		env!("CARGO_PKG_AUTHORS").into()
	}

	fn support_url() -> String {
		concat!(env!("CARGO_PKG_REPOSITORY"), "/issues").into()
	}

	fn copyright_start_year() -> i32 {
		2021
	}

	/// `dev`, `local` (also the empty id), `testnet` and `mainnet`, by short or full id;
	/// anything else is a path to a chain spec file.
	fn load_spec(&self, id: &str) -> Result<Box<dyn ChainSpec>, String> {
		Ok(match id {
			"dev" => Box::new(chain_spec::development_config(self.sealing.is_some())?),
			"" | "local" => Box::new(chain_spec::local_testnet_config()?),
			"testnet" | "orbinum_testnet" => Box::new(chain_spec::orbinum_testnet_config()?),
			"mainnet" | "orbinum_mainnet" => Box::new(chain_spec::orbinum_mainnet_config()?),
			path => Box::new(chain_spec::ChainSpec::from_json_file(path.into())?),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use clap::Parser;
	use sc_chain_spec::ChainType;

	fn cli(args: &[&str]) -> Cli {
		Cli::try_parse_from(std::iter::once("orbinum-node").chain(args.iter().copied()))
			.expect("valid arguments")
	}

	fn spec(id: &str) -> Box<dyn ChainSpec> {
		cli(&[]).load_spec(id).expect("known chain spec id")
	}

	#[test]
	fn short_and_full_ids_load_the_same_specs() {
		assert_eq!(spec("dev").id(), "dev");
		assert_eq!(spec("dev").chain_type(), ChainType::Development);
		assert_eq!(spec("local").id(), "local_testnet");
		assert_eq!(spec("").id(), "local_testnet");
		assert_eq!(spec("local").chain_type(), ChainType::Local);
		assert_eq!(spec("testnet").id(), "orbinum_testnet");
		assert_eq!(spec("orbinum_testnet").id(), "orbinum_testnet");
		assert_eq!(spec("testnet").chain_type(), ChainType::Live);
	}

	#[test]
	fn dev_spec_enables_manual_seal_only_with_sealing() {
		let manual_seal = |cli: Cli| {
			let json = cli.load_spec("dev").unwrap().as_json(false).unwrap();
			let spec: serde_json::Value = serde_json::from_str(&json).unwrap();
			spec["genesis"]["runtimeGenesis"]["patch"]["manualSeal"]["enable"].clone()
		};
		assert_eq!(manual_seal(cli(&[])), serde_json::Value::Bool(false));
		assert_eq!(
			manual_seal(cli(&["--sealing", "instant"])),
			serde_json::Value::Bool(true)
		);
	}

	#[test]
	fn mainnet_is_refused_until_configured() {
		for id in ["mainnet", "orbinum_mainnet"] {
			let Err(err) = cli(&[]).load_spec(id) else {
				panic!("mainnet is not configured");
			};
			assert!(err.contains("mainnet genesis not configured"), "{err}");
		}
	}

	#[test]
	fn other_ids_are_spec_files() {
		let Err(err) = cli(&[]).load_spec("no-such-chain") else {
			panic!("no such file");
		};
		assert!(!err.is_empty());
	}
}
