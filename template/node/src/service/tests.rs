//! The RPC a dev node serves, built the way [`super::new_full`] builds it.
//!
//! The node runs in-process with no p2p listen addresses, no bootnodes and no mDNS, so it
//! never connects to peers; its RPC server listens on a random localhost port.

use std::{
	collections::BTreeSet,
	future::Future,
	sync::atomic::{AtomicUsize, Ordering},
	time::Duration,
};

use clap::Parser;
use futures::channel::mpsc;
use jsonrpsee::{core::params::ArrayParams, RpcModule};
use sc_cli::SubstrateCli;
use sc_consensus_grandpa::SharedVoterState;
use sc_rpc::DenyUnsafe;

use super::{consensus::grandpa, network, new_partial, rpc, Partial, RpcParams};
use crate::{cli::Cli, frontier::FrontierParts};

/// Runs `f` on the RPC module `spawn_tasks` serves for a dev node started with `args`,
/// while the node runs.
fn with_dev_rpc<T, F>(args: &[&str], f: impl FnOnce(RpcModule<()>) -> F) -> T
where
	F: Future<Output = T>,
{
	// `--tmp` shares one directory per process: each node gets its own.
	static NODES: AtomicUsize = AtomicUsize::new(0);
	let base_path = std::env::temp_dir().join(format!(
		"orbinum-node-rpc-test-{}-{}",
		std::process::id(),
		NODES.fetch_add(1, Ordering::Relaxed)
	));
	let base_path = base_path.to_str().expect("UTF-8 temp dir");
	let base = [
		"orbinum-node",
		"--dev",
		"--base-path",
		base_path,
		"--no-prometheus",
		"--no-telemetry",
		"--no-mdns",
		"--rpc-port",
		"0",
	];
	let mut cli = Cli::try_parse_from(base.iter().chain(args)).expect("valid arguments");
	crate::cli::apply_ismp_requirements(&mut cli.run);

	let runtime = sc_cli::build_runtime().expect("tokio runtime");
	let mut config = cli
		.create_configuration(&cli.run, runtime.handle().clone())
		.expect("dev configuration");
	config.network.listen_addresses.clear();
	let manual_seal = cli.sealing.is_some();

	let (output, task_manager) = runtime.block_on(async move {
		let Partial {
			client,
			backend,
			mut task_manager,
			import_queue,
			keystore_container,
			transaction_pool,
			grandpa_link,
			frontier_backend,
			storage_override,
			..
		} = new_partial(&config, &cli.eth, manual_seal).expect("partial components");
		let net = network::build(
			&config,
			&client,
			&backend,
			&transaction_pool,
			import_queue,
			&grandpa_link,
			&task_manager,
			manual_seal,
		)
		.expect("network");
		let (command_sink, _commands_stream) = mpsc::channel(1);
		let rpc_builder = rpc::builder(
			RpcParams {
				client: client.clone(),
				backend: backend.clone(),
				transaction_pool: transaction_pool.clone(),
				network: net.network.clone(),
				sync_service: net.sync_service.clone(),
				frontier: FrontierParts::new(&cli.eth, frontier_backend, storage_override),
				grandpa: grandpa::rpc_deps(&grandpa_link, &backend, SharedVoterState::empty()),
				command_sink: cli.sealing.map(|_| command_sink),
				is_authority: config.role.is_authority(),
				ismp_max_event_blocks: cli.ismp_max_event_blocks,
			},
			&cli.eth,
			&task_manager,
			None,
		)
		.expect("RPC builder");
		let rpc = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
			config,
			client,
			backend,
			task_manager: &mut task_manager,
			keystore: keystore_container.keystore(),
			transaction_pool,
			rpc_builder,
			network: net.network,
			system_rpc_tx: net.system_rpc_tx,
			tx_handler_controller: net.tx_handler_controller,
			sync_service: net.sync_service,
			telemetry: None,
			tracing_execute_block: None,
		})
		.expect("every RPC method name is unique");
		let output = f((*rpc.handle()).clone()).await;
		(output, task_manager)
	});

	// The RPC runtime `spawn_tasks` keeps alive cannot be dropped inside an async context.
	drop(task_manager);
	runtime.shutdown_timeout(Duration::from_secs(5));
	let _ = std::fs::remove_dir_all(base_path);
	output
}

/// The methods `spawn_tasks` serves for a dev node started with `args`.
fn rpc_methods(args: &[&str]) -> BTreeSet<String> {
	with_dev_rpc(args, |module| async move {
		module.method_names().map(String::from).collect()
	})
}

fn namespaces(methods: &BTreeSet<String>) -> BTreeSet<&str> {
	methods
		.iter()
		.map(|method| method.split_once('_').map_or(method.as_str(), |(ns, _)| ns))
		.collect()
}

/// Namespaces every node serves, with or without manual seal.
const NAMESPACES: &[&str] = &[
	"account",
	"author",
	"bitswap",
	"chain",
	"chainHead",
	"chainSpec",
	"childstate",
	"debug",
	"eth",
	"grandpa",
	"ismp",
	"net",
	"offchain",
	"payment",
	"privacy",
	"state",
	// `subscribe_newHead` / `unsubscribe_newHead`: aliases of `chain_subscribeNewHeads`.
	"subscribe",
	"system",
	"transaction",
	"transactionWatch",
	"unsubscribe",
	"web3",
	"zkVerifier",
];

#[test]
fn rpc_method_set() {
	let methods = rpc_methods(&[]);
	let mut expected: BTreeSet<&str> = NAMESPACES.iter().copied().collect();
	if cfg!(feature = "txpool") {
		expected.insert("txpool");
	}
	assert_eq!(namespaces(&methods), expected, "{methods:#?}");
	for method in [
		"grandpa_proveFinality",
		"grandpa_roundState",
		"ismp_queryRequests",
		"eth_sendRawTransaction",
		"eth_sendTransaction",
		"system_accountNextIndex",
	] {
		assert!(methods.contains(method), "missing {method}");
	}
}

#[test]
fn engine_methods_only_with_sealing() {
	assert!(!rpc_methods(&[]).iter().any(|m| m.starts_with("engine_")));
	let sealed = rpc_methods(&["--sealing", "manual"]);
	assert!(sealed.contains("engine_createBlock"));
	assert!(sealed.contains("engine_finalizeBlock"));
}

/// The methods that dump the transaction pool answer only where the server allows
/// unsafe methods; a call without the server's `DenyUnsafe` extension is denied.
#[test]
fn unsafe_pool_methods_are_denied_on_safe_endpoints() {
	let mut methods = vec!["eth_pendingTransactions"];
	if cfg!(feature = "txpool") {
		methods.extend(["txpool_content", "txpool_inspect"]);
	}
	with_dev_rpc(&[], |module| async move {
		// The in-memory module carries `DenyUnsafe::No`; the server sets its own per
		// connection.
		let with = |deny_unsafe: Option<DenyUnsafe>| {
			let mut module = module.clone();
			let extensions = module.extensions_mut();
			extensions.remove::<DenyUnsafe>();
			if let Some(deny_unsafe) = deny_unsafe {
				extensions.insert(deny_unsafe);
			}
			module
		};
		let (none, safe, unsafe_allowed) = (
			with(None),
			with(Some(DenyUnsafe::Yes)),
			with(Some(DenyUnsafe::No)),
		);
		for method in methods {
			for (denied, case) in [(&none, "no extension"), (&safe, "DenyUnsafe::Yes")] {
				let err = denied
					.call::<_, serde_json::Value>(method, ArrayParams::new())
					.await
					.expect_err(method);
				assert!(
					err.to_string().contains("unsafe"),
					"{method}, {case}: {err}"
				);
			}
			unsafe_allowed
				.call::<_, serde_json::Value>(method, ArrayParams::new())
				.await
				.unwrap_or_else(|e| panic!("{method}, DenyUnsafe::No: {e}"));
		}
	});
}

/// `ismp_queryEvents*` re-execute the runtime at each block of their range:
/// a range over `--ismp-max-event-blocks` is refused before any is read.
#[test]
fn ismp_event_queries_are_bounded() {
	with_dev_rpc(&["--ismp-max-event-blocks", "5"], |module| async move {
		for method in ["ismp_queryEvents", "ismp_queryEventsWithMetadata"] {
			// Within the range, the call reaches upstream's handler, which fails on any
			// range that includes genesis (it reads genesis' parent).
			let within = module
				.call::<_, serde_json::Value>(method, [0u32, 0])
				.await
				.expect_err("upstream refuses genesis");
			assert!(
				!within.to_string().contains("more than"),
				"{method}: {within}"
			);
			let err = module
				.call::<_, serde_json::Value>(method, [0u32, 5])
				.await
				.expect_err("six blocks");
			assert!(
				err.to_string().contains("more than 5 blocks"),
				"{method}: {err}"
			);
		}
	});
}
