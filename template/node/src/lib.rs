//! The Orbinum node: CLI, chain specs, service and RPC.
//!
//! | Module | Contents |
//! |---|---|
//! | `cli` | command-line arguments, chain spec ids and the flags the node enforces |
//! | `command` | subcommand dispatch |
//! | `chain_spec` | the dev, local, testnet and mainnet chain specs |
//! | `client` | the client, its backend and the host functions it executes with |
//! | `service` | node assembly: import queue, network, RPC, consensus |
//! | `frontier` | Ethereum compatibility: CLI settings, mapping database, background tasks |
//! | `rpc` | the RPC methods the node serves |
//! | `author_version` | the node version declared in authored blocks |
//! | `benchmarking` | extrinsic builders for `benchmark overhead` and `benchmark extrinsic` |

#![warn(missing_docs)]
#![allow(
	clippy::type_complexity,
	clippy::too_many_arguments,
	clippy::large_enum_variant,
	clippy::result_large_err
)]
#![cfg_attr(feature = "runtime-benchmarks", warn(unused_crate_dependencies))]

mod author_version;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
mod chain_spec;
mod cli;
mod client;
mod command;
mod frontier;
mod rpc;
mod service;

pub use command::run;
