//! Offchain workers.

use std::sync::Arc;

use futures::FutureExt;
use sc_client_api::Backend as _;
use sc_network::service::traits::NetworkService;
use sc_service::{error::Error as ServiceError, Configuration, KeystoreContainer, TaskManager};
use sc_transaction_pool_api::OffchainTransactionPoolFactory;

use crate::client::{Backend, Client};
use crate::service::setup::types::TransactionPool;

/// Spawns the offchain workers when `--offchain-worker` enables them for this role.
pub fn spawn(
	config: &Configuration,
	task_manager: &TaskManager,
	client: &Arc<Client>,
	backend: &Arc<Backend>,
	keystore_container: &KeystoreContainer,
	transaction_pool: &Arc<TransactionPool>,
	network: &Arc<dyn NetworkService>,
) -> Result<(), ServiceError> {
	if !config.offchain_worker.enabled {
		return Ok(());
	}
	let offchain_workers = sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
		runtime_api_provider: client.clone(),
		is_validator: config.role.is_authority(),
		keystore: Some(keystore_container.keystore()),
		offchain_db: backend.offchain_storage(),
		transaction_pool: Some(OffchainTransactionPoolFactory::new(
			transaction_pool.clone(),
		)),
		network_provider: Arc::new(network.clone()),
		enable_http_requests: true,
		custom_extensions: |_| vec![],
	})?;
	task_manager.spawn_handle().spawn(
		"offchain-workers-runner",
		"offchain-worker",
		offchain_workers
			.run(client.clone(), task_manager.spawn_handle())
			.boxed(),
	);
	Ok(())
}
