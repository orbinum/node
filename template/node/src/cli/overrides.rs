// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Settings the node enforces over the operator's flags.

use sc_chain_spec::ChainType;

use super::Sealing;

/// RPC response size, in MiB, GRANDPA finality proofs and ISMP queries need. The default
/// (15 MiB) truncates them.
pub const MIN_RPC_RESPONSE_MB: u32 = 150;

/// Applies what ISMP needs from every node:
///
/// - Offchain indexing, always on. `pallet-ismp` stores outgoing requests with
///   `offchain_index::set`, a no-op without it: `ismp_queryRequests` then answers an
///   empty list with no error and relayers never see our messages.
/// - RPC response size of at least [`MIN_RPC_RESPONSE_MB`]; a larger value from the
///   operator is kept. Applies to `--rpc-port`: an `--experimental-rpc-endpoint` carries
///   its own `max-response-size`.
///
/// The request size stays the operator's. The default (15 MiB) fits the largest request
/// ISMP sends, an unsigned `handle_unsigned` extrinsic: Normal class, so at most 85% of
/// the 8 MiB block length, about 13.6 MiB hex-encoded.
///
/// RPC methods are left to the operator: the ISMP queries are not `unsafe`, so a relayer
/// reaches them under `--rpc-methods safe`.
pub fn apply_ismp_requirements(run: &mut sc_cli::RunCmd) {
	run.offchain_worker_params.indexing_enabled = true;
	let rpc = &mut run.rpc_params;
	rpc.rpc_max_response_size = rpc.rpc_max_response_size.max(MIN_RPC_RESPONSE_MB);
}

/// Refuses the flags that are only safe on a development chain:
///
/// - `--sealing`: blocks without Aura's author check, no GRANDPA, and `engine_*` RPCs
///   that let any caller seal or finalize.
/// - `--enable-dev-signer`: `eth_sendTransaction` signs with the publicly known dev keys.
///
/// The chain type is the spec's own, so a custom JSON spec with `"chainType":
/// "Development"` lets both through: the operator's choice, like the flags themselves.
pub fn ensure_dev_only_flags(
	chain_type: &ChainType,
	sealing: Option<Sealing>,
	enable_dev_signer: bool,
) -> Result<(), String> {
	if *chain_type == ChainType::Development {
		return Ok(());
	}
	let flag = match (sealing, enable_dev_signer) {
		(Some(_), _) => "--sealing",
		(None, true) => "--enable-dev-signer",
		(None, false) => return Ok(()),
	};
	Err(format!(
		"`{flag}` is only allowed on development chains, and this chain spec is {chain_type:?}"
	))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cli::Cli;
	use clap::Parser;

	fn run_cmd(args: &[&str]) -> sc_cli::RunCmd {
		let mut cli =
			Cli::try_parse_from(std::iter::once("orbinum-node").chain(args.iter().copied()))
				.expect("valid arguments");
		apply_ismp_requirements(&mut cli.run);
		cli.run
	}

	#[test]
	fn request_size_is_not_raised() {
		let run = run_cmd(&["--rpc-max-request-size", "15"]);
		assert_eq!(run.rpc_params.rpc_max_request_size, 15);
		let run = run_cmd(&[]);
		assert_eq!(run.rpc_params.rpc_max_request_size, 15);
	}

	#[test]
	fn response_floor_still_applies() {
		let run = run_cmd(&[]);
		assert_eq!(run.rpc_params.rpc_max_response_size, MIN_RPC_RESPONSE_MB);
		let run = run_cmd(&["--rpc-max-response-size", "149"]);
		assert_eq!(run.rpc_params.rpc_max_response_size, MIN_RPC_RESPONSE_MB);
	}

	#[test]
	fn higher_rpc_payload_limits_are_kept() {
		let run = run_cmd(&[
			"--rpc-max-request-size",
			"300",
			"--rpc-max-response-size",
			"151",
		]);
		assert_eq!(run.rpc_params.rpc_max_request_size, 300);
		assert_eq!(run.rpc_params.rpc_max_response_size, 151);
	}

	#[test]
	fn offchain_indexing_is_always_on() {
		assert!(run_cmd(&[]).offchain_worker_params.indexing_enabled);
		assert!(
			run_cmd(&["--enable-offchain-indexing", "false"])
				.offchain_worker_params
				.indexing_enabled
		);
	}

	#[test]
	fn dev_only_flags_pass_on_development_chains() {
		let dev = ChainType::Development;
		assert!(ensure_dev_only_flags(&dev, Some(Sealing::Manual), true).is_ok());
		assert!(ensure_dev_only_flags(&dev, Some(Sealing::Instant), false).is_ok());
		assert!(ensure_dev_only_flags(&dev, None, true).is_ok());
	}

	#[test]
	fn dev_only_flags_are_refused_elsewhere() {
		for chain_type in [
			ChainType::Local,
			ChainType::Live,
			ChainType::Custom("staging".into()),
		] {
			assert!(ensure_dev_only_flags(&chain_type, None, false).is_ok());
			let err = ensure_dev_only_flags(&chain_type, Some(Sealing::Manual), false).unwrap_err();
			assert!(err.contains("--sealing"), "{err}");
			let err = ensure_dev_only_flags(&chain_type, None, true).unwrap_err();
			assert!(err.contains("--enable-dev-signer"), "{err}");
		}
	}

	#[test]
	fn sealing_and_dev_signer_parse_from_the_command_line() {
		let cli =
			Cli::try_parse_from(["orbinum-node", "--sealing", "manual", "--enable-dev-signer"])
				.expect("valid arguments");
		assert_eq!(cli.sealing, Some(Sealing::Manual));
		assert!(cli.eth.enable_dev_signer);
	}
}
