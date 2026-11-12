// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Frontier's mapping database: where it lives, opening it and purging it.

use std::{num::NonZeroU32, path::PathBuf, sync::Arc};

use sc_service::{error::Error as ServiceError, Configuration, DatabaseSource};

use super::{BackendType, EthConfiguration, FrontierBackend};
use crate::client::Client;
use fc_storage::StorageOverride;
use orbinum_runtime::opaque::Block;

/// The chain's config directory, where the Frontier database lives.
pub fn db_config_dir(config: &Configuration) -> PathBuf {
	config.base_path.config_dir(config.chain_spec.id())
}

fn sql_dir(config: &Configuration) -> PathBuf {
	db_config_dir(config).join("sql")
}

/// Opens the backend `--frontier-backend-type` selects, creating it if missing.
pub fn open(
	config: &Configuration,
	eth_config: &EthConfiguration,
	client: Arc<Client>,
	storage_override: Arc<dyn StorageOverride<Block>>,
) -> Result<FrontierBackend, ServiceError> {
	match eth_config.frontier_backend_type {
		BackendType::KeyValue => Ok(FrontierBackend::KeyValue(Arc::new(
			fc_db::kv::Backend::open(client, &config.database, &db_config_dir(config))?,
		))),
		BackendType::Sql => {
			let db_path = sql_dir(config);
			std::fs::create_dir_all(&db_path)?;
			let url = PathBuf::from("sqlite:///")
				.join(db_path)
				.join("frontier.db3");
			let url = url.to_str().ok_or_else(|| {
				ServiceError::Other(format!("SQL backend path is not UTF-8: {url:?}"))
			})?;
			let backend = futures::executor::block_on(fc_db::sql::Backend::new(
				fc_db::sql::BackendConfig::Sqlite(fc_db::sql::SqliteBackendConfig {
					path: url,
					create_if_missing: true,
					thread_count: eth_config.frontier_sql_backend_thread_count,
					cache_size: eth_config.frontier_sql_backend_cache_size,
				}),
				eth_config.frontier_sql_backend_pool_size,
				NonZeroU32::new(eth_config.frontier_sql_backend_num_ops_timeout),
				storage_override,
			))
			.map_err(|e| ServiceError::Other(format!("failed to open the SQL backend: {e}")))?;
			Ok(FrontierBackend::Sql(Arc::new(backend)))
		}
	}
}

/// Removes the Frontier database of `backend_type`, prompting through `cmd` unless `-y`.
pub fn purge(
	config: &Configuration,
	backend_type: BackendType,
	cmd: &sc_cli::PurgeChainCmd,
) -> sc_cli::Result<()> {
	match backend_type {
		BackendType::KeyValue => {
			let dir = db_config_dir(config);
			let database = match config.database {
				DatabaseSource::RocksDb { .. } => DatabaseSource::RocksDb {
					path: fc_db::kv::frontier_database_dir(&dir, "db"),
					cache_size: 0,
				},
				DatabaseSource::ParityDb { .. } => DatabaseSource::ParityDb {
					path: fc_db::kv::frontier_database_dir(&dir, "paritydb"),
				},
				_ => return Err(format!("Cannot purge `{:?}` database", config.database).into()),
			};
			cmd.run(database)
		}
		BackendType::Sql => {
			let db_path = sql_dir(config);
			match std::fs::remove_dir_all(&db_path) {
				Ok(()) => println!("{db_path:?} removed."),
				Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
					eprintln!("{db_path:?} did not exist.")
				}
				Err(err) => {
					return Err(format!("Cannot purge `{db_path:?}` database: {err:?}").into())
				}
			}
			Ok(())
		}
	}
}
