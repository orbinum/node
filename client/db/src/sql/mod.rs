// This file is part of Frontier.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{cmp::Ordering, collections::HashSet, num::NonZeroU32, str::FromStr, sync::Arc};

use futures::TryStreamExt;
use scale_codec::{Decode, Encode};
use sqlx::{
	query::Query,
	sqlite::{
		SqliteArguments, SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteQueryResult,
	},
	ConnectOptions, Error, Execute, QueryBuilder, Row, Sqlite,
};
// Substrate
use sc_client_api::backend::{Backend as BackendT, StorageProvider};
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::{H160, H256};
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, Header as HeaderT, UniqueSaturatedInto, Zero},
};
// Frontier
use fc_api::{FilteredLog, TransactionMetadata};
use fc_storage::{StorageOverride, StorageQuerier};
use fp_consensus::{FindLogError, Hashes, Log as ConsensusLog, PostLog, PreLog};
use fp_rpc::EthereumRuntimeRPCApi;
use fp_storage::EthereumStorageSchema;

/// Represents a log item.
#[derive(Debug, Eq, PartialEq)]
pub struct Log {
	pub address: Vec<u8>,
	pub topic_1: Option<Vec<u8>>,
	pub topic_2: Option<Vec<u8>>,
	pub topic_3: Option<Vec<u8>>,
	pub topic_4: Option<Vec<u8>>,
	pub log_index: i32,
	pub transaction_index: i32,
	pub substrate_block_hash: Vec<u8>,
}

/// Represents the block metadata.
#[derive(Eq, PartialEq)]
struct BlockMetadata {
	pub substrate_block_hash: H256,
	pub block_number: i32,
	pub post_hashes: Hashes,
	pub schema: EthereumStorageSchema,
	pub is_canon: i32,
}

/// Represents the Sqlite connection options that are
/// used to establish a database connection.
#[derive(Debug)]
pub struct SqliteBackendConfig<'a> {
	pub path: &'a str,
	pub create_if_missing: bool,
	pub thread_count: u32,
	pub cache_size: u64,
}

/// Represents the indexed status of a block and if it's canon or not.
#[derive(Debug, Default)]
pub struct BlockIndexedStatus {
	pub indexed: bool,
	pub canon: bool,
}

/// Represents the backend configurations.
#[derive(Debug)]
pub enum BackendConfig<'a> {
	Sqlite(SqliteBackendConfig<'a>),
}

#[derive(Clone)]
pub struct Backend<Block> {
	/// The Sqlite connection.
	pool: SqlitePool,
	/// The additional overrides for the logs handler.
	storage_override: Arc<dyn StorageOverride<Block>>,

	/// The number of allowed operations for the Sqlite filter call.
	/// A value of `0` disables the timeout.
	num_ops_timeout: i32,
}

impl<Block> Backend<Block>
where
	Block: BlockT<Hash = H256>,
{
	/// Creates a new instance of the SQL backend.
	pub async fn new(
		config: BackendConfig<'_>,
		pool_size: u32,
		num_ops_timeout: Option<NonZeroU32>,
		storage_override: Arc<dyn StorageOverride<Block>>,
	) -> Result<Self, Error> {
		let any_pool = SqlitePoolOptions::new()
			.max_connections(pool_size)
			.connect_lazy_with(Self::connect_options(&config)?.disable_statement_logging());
		let _ = Self::create_database_if_not_exists(&any_pool).await?;
		let _ = Self::create_indexes_if_not_exist(&any_pool).await?;
		Ok(Self {
			pool: any_pool,
			storage_override,
			num_ops_timeout: num_ops_timeout
				.map(|n| n.get())
				.unwrap_or(0)
				.try_into()
				.unwrap_or(i32::MAX),
		})
	}

	fn connect_options(config: &BackendConfig) -> Result<SqliteConnectOptions, Error> {
		match config {
			BackendConfig::Sqlite(config) => {
				log::info!(target: "frontier-sql", "📑 Connection configuration: {config:?}");
				let config = sqlx::sqlite::SqliteConnectOptions::from_str(config.path)?
					.create_if_missing(config.create_if_missing)
					// https://www.sqlite.org/pragma.html#pragma_busy_timeout
					.busy_timeout(std::time::Duration::from_secs(8))
					// 200MB, https://www.sqlite.org/pragma.html#pragma_cache_size
					.pragma("cache_size", format!("-{}", config.cache_size))
					// https://www.sqlite.org/pragma.html#pragma_analysis_limit
					.pragma("analysis_limit", "1000")
					// https://www.sqlite.org/pragma.html#pragma_threads
					.pragma("threads", config.thread_count.to_string())
					// https://www.sqlite.org/pragma.html#pragma_threads
					.pragma("temp_store", "memory")
					// https://www.sqlite.org/wal.html
					.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
					// https://www.sqlite.org/pragma.html#pragma_synchronous
					.synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
				Ok(config)
			}
		}
	}

	/// Get the underlying Sqlite pool.
	pub fn pool(&self) -> &SqlitePool {
		&self.pool
	}

	/// Canonicalize the indexed blocks, marking/demarking them as canon based on the
	/// provided `retracted` and `enacted` values.
	pub async fn canonicalize(&self, retracted: &[H256], enacted: &[H256]) -> Result<(), Error> {
		let mut tx = self.pool().begin().await?;

		// Retracted
		let mut builder: QueryBuilder<Sqlite> =
			QueryBuilder::new("UPDATE blocks SET is_canon = 0 WHERE substrate_block_hash IN (");
		let mut retracted_hashes = builder.separated(", ");
		for hash in retracted.iter() {
			let hash = hash.as_bytes();
			retracted_hashes.push_bind(hash);
		}
		retracted_hashes.push_unseparated(")");
		let query = builder.build();
		query.execute(&mut *tx).await?;

		// Enacted
		let mut builder: QueryBuilder<Sqlite> =
			QueryBuilder::new("UPDATE blocks SET is_canon = 1 WHERE substrate_block_hash IN (");
		let mut enacted_hashes = builder.separated(", ");
		for hash in enacted.iter() {
			let hash = hash.as_bytes();
			enacted_hashes.push_bind(hash);
		}
		enacted_hashes.push_unseparated(")");
		let query = builder.build();
		query.execute(&mut *tx).await?;

		tx.commit().await
	}

	/// Index the block metadata for the genesis block.
	pub async fn insert_genesis_block_metadata<Client, BE>(
		&self,
		client: Arc<Client>,
	) -> Result<Option<H256>, Error>
	where
		Client: StorageProvider<Block, BE> + HeaderBackend<Block> + 'static,
		Client: ProvideRuntimeApi<Block>,
		Client::Api: EthereumRuntimeRPCApi<Block>,
		BE: BackendT<Block> + 'static,
	{
		let id = BlockId::Number(Zero::zero());
		let substrate_genesis_hash = client
			.expect_block_hash_from_id(&id)
			.map_err(|_| Error::Protocol("Cannot resolve genesis hash".to_string()))?;
		let maybe_substrate_hash: Option<H256> = if let Ok(Some(_)) =
			client.header(substrate_genesis_hash)
		{
			let has_api = client
				.runtime_api()
				.has_api_with::<dyn EthereumRuntimeRPCApi<Block>, _>(
					substrate_genesis_hash,
					|version| version >= 1,
				)
				.expect("runtime api reachable");

			log::debug!(target: "frontier-sql", "Index genesis block, has_api={has_api}, hash={substrate_genesis_hash:?}");

			if has_api {
				// The chain has frontier support from genesis.
				// Read from the runtime and store the block metadata.
				let ethereum_block = client
					.runtime_api()
					.current_block(substrate_genesis_hash)
					.expect("runtime api reachable")
					.expect("ethereum genesis block");

				let schema = StorageQuerier::new(client)
					.storage_schema(substrate_genesis_hash)
					.unwrap_or(EthereumStorageSchema::V3)
					.encode();
				let ethereum_block_hash = ethereum_block.header.hash().as_bytes().to_owned();
				let substrate_block_hash = substrate_genesis_hash.as_bytes();
				let block_number = 0i32;
				let is_canon = 1i32;

				let _ = sqlx::query(
					"INSERT OR IGNORE INTO blocks(
						ethereum_block_hash,
						substrate_block_hash,
						block_number,
						ethereum_storage_schema,
						is_canon)
					VALUES (?, ?, ?, ?, ?)",
				)
				.bind(ethereum_block_hash)
				.bind(substrate_block_hash)
				.bind(block_number)
				.bind(schema)
				.bind(is_canon)
				.execute(self.pool())
				.await?;
			}
			Some(substrate_genesis_hash)
		} else {
			None
		};
		Ok(maybe_substrate_hash)
	}

	fn insert_block_metadata_inner<Client, BE>(
		client: Arc<Client>,
		hash: H256,
		storage_override: &dyn StorageOverride<Block>,
	) -> Result<BlockMetadata, Error>
	where
		Client: StorageProvider<Block, BE> + HeaderBackend<Block> + 'static,
		BE: BackendT<Block> + 'static,
	{
		log::trace!(target: "frontier-sql", "🛠️  [Metadata] Retrieving digest data for block {hash:?}");
		if let Ok(Some(header)) = client.header(hash) {
			match fp_consensus::find_log(header.digest()) {
				Ok(log) => {
					let schema = StorageQuerier::new(client.clone())
						.storage_schema(hash)
						.unwrap_or(EthereumStorageSchema::V3);
					let log_hashes = match log {
						ConsensusLog::Post(PostLog::Hashes(post_hashes)) => post_hashes,
						ConsensusLog::Post(PostLog::Block(block)) => Hashes::from_block(block),
						ConsensusLog::Post(PostLog::BlockHash(expect_eth_block_hash)) => {
							let ethereum_block = storage_override.current_block(hash);
							match ethereum_block {
								Some(block) => {
									let got_eth_block_hash = block.header.hash();
									if got_eth_block_hash != expect_eth_block_hash {
										log::warn!(
											target: "frontier-sql",
											"Ethereum block hash mismatch: \
											frontier consensus digest ({expect_eth_block_hash:?}), \
											db state ({got_eth_block_hash:?}); \
											indexing db state tx hashes under digest block hash."
										);
										Hashes {
											block_hash: expect_eth_block_hash,
											transaction_hashes: block
												.transactions
												.iter()
												.map(|tx| tx.hash())
												.collect(),
										}
									} else {
										Hashes::from_block(block)
									}
								}
								None => {
									return Err(Error::Protocol(format!(
										"Missing ethereum block for hash mismatch {expect_eth_block_hash:?}"
									)))
								}
							}
						}
						ConsensusLog::Pre(PreLog::Block(block)) => Hashes::from_block(block),
					};

					let header_number = *header.number();
					let block_number =
						UniqueSaturatedInto::<u32>::unique_saturated_into(header_number) as i32;
					let is_canon = match client.hash(header_number) {
						Ok(Some(inner_hash)) => (inner_hash == hash) as i32,
						Ok(None) => {
							log::debug!(target: "frontier-sql", "[Metadata] Missing header for block #{block_number} ({hash:?})");
							0
						}
						Err(err) => {
							log::debug!(
								target: "frontier-sql",
								"[Metadata] Failed to retrieve header for block #{block_number} ({hash:?}): {err:?}",
							);
							0
						}
					};

					log::trace!(
						target: "frontier-sql",
						"[Metadata] Prepared block metadata for #{block_number} ({hash:?}) canon={is_canon}",
					);
					Ok(BlockMetadata {
						substrate_block_hash: hash,
						block_number,
						post_hashes: log_hashes,
						schema,
						is_canon,
					})
				}
				Err(FindLogError::NotFound) => Err(Error::Protocol(format!(
					"[Metadata] No logs found for hash {hash:?}",
				))),
				Err(FindLogError::MultipleLogs) => Err(Error::Protocol(format!(
					"[Metadata] Multiple logs found for hash {hash:?}",
				))),
			}
		} else {
			Err(Error::Protocol(format!(
				"[Metadata] Failed retrieving header for hash {hash:?}"
			)))
		}
	}

	/// Insert the block metadata for the provided block hashes.
	pub async fn insert_block_metadata<Client, BE>(
		&self,
		client: Arc<Client>,
		hash: H256,
	) -> Result<(), Error>
	where
		Client: StorageProvider<Block, BE> + HeaderBackend<Block> + 'static,
		BE: BackendT<Block> + 'static,
	{
		// Spawn a blocking task to get block metadata from substrate backend.
		let storage_override = self.storage_override.clone();
		let metadata = tokio::task::spawn_blocking(move || {
			Self::insert_block_metadata_inner(client.clone(), hash, &*storage_override)
		})
		.await
		.map_err(|_| Error::Protocol("tokio blocking metadata task failed".to_string()))??;

		let mut tx = self.pool().begin().await?;

		log::debug!(
			target: "frontier-sql",
			"🛠️  [Metadata] Starting execution of statements on db transaction"
		);
		let post_hashes = metadata.post_hashes;
		let ethereum_block_hash = post_hashes.block_hash.as_bytes();
		let substrate_block_hash = metadata.substrate_block_hash.as_bytes();
		let schema = metadata.schema.encode();
		let block_number = metadata.block_number;
		let is_canon = metadata.is_canon;

		let _ = sqlx::query(
			"INSERT OR IGNORE INTO blocks(
					ethereum_block_hash,
					substrate_block_hash,
					block_number,
					ethereum_storage_schema,
					is_canon)
				VALUES (?, ?, ?, ?, ?)",
		)
		.bind(ethereum_block_hash)
		.bind(substrate_block_hash)
		.bind(block_number)
		.bind(schema)
		.bind(is_canon)
		.execute(&mut *tx)
		.await?;
		for (i, &transaction_hash) in post_hashes.transaction_hashes.iter().enumerate() {
			let ethereum_transaction_hash = transaction_hash.as_bytes();
			let ethereum_transaction_index = i as i32;
			log::trace!(
				target: "frontier-sql",
				"[Metadata] Inserting TX for block #{block_number} - {transaction_hash:?} index {ethereum_transaction_index}",
			);
			let _ = sqlx::query(
				"INSERT OR IGNORE INTO transactions(
						ethereum_transaction_hash,
						substrate_block_hash,
						ethereum_block_hash,
						ethereum_transaction_index)
					VALUES (?, ?, ?, ?)",
			)
			.bind(ethereum_transaction_hash)
			.bind(substrate_block_hash)
			.bind(ethereum_block_hash)
			.bind(ethereum_transaction_index)
			.execute(&mut *tx)
			.await?;
		}

		sqlx::query("INSERT INTO sync_status(substrate_block_hash) VALUES (?)")
			.bind(hash.as_bytes())
			.execute(&mut *tx)
			.await?;

		log::debug!(target: "frontier-sql", "[Metadata] Ready to commit");
		tx.commit().await
	}

	/// Index the logs for the newly indexed blocks upto a `max_pending_blocks` value.
	pub async fn index_block_logs(&self, block_hash: Block::Hash) {
		let pool = self.pool().clone();
		let storage_override = self.storage_override.clone();
		let _ = async {
			// The overarching db transaction for the task.
			// Due to the async nature of this task, the same work is likely to happen
			// more than once. For example when a new batch is scheduled when the previous one
			// didn't finished yet and the new batch happens to select the same substrate
			// block hashes for the update.
			// That is expected, we are exchanging extra work for *acid*ity.
			// There is no case of unique constrain violation or race condition as already
			// existing entries are ignored.
			let mut tx = pool.begin().await?;
			// Update statement returning the substrate block hashes for this batch.
			match sqlx::query(
				"UPDATE sync_status
			SET status = 1
			WHERE substrate_block_hash IN
				(SELECT substrate_block_hash
				FROM sync_status
				WHERE status = 0 AND substrate_block_hash = ?) RETURNING substrate_block_hash",
			)
			.bind(block_hash.as_bytes())
			.fetch_one(&mut *tx)
			.await
			{
				Ok(_) => {
					// Spawn a blocking task to get log data from substrate backend.
					let logs = tokio::task::spawn_blocking(move || {
						Self::get_logs(storage_override, block_hash)
					})
					.await
					.map_err(|_| Error::Protocol("tokio blocking task failed".to_string()))?;

					for log in logs {
						let _ = sqlx::query(
							"INSERT OR IGNORE INTO logs(
						address,
						topic_1,
						topic_2,
						topic_3,
						topic_4,
						log_index,
						transaction_index,
						substrate_block_hash)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
						)
						.bind(log.address)
						.bind(log.topic_1)
						.bind(log.topic_2)
						.bind(log.topic_3)
						.bind(log.topic_4)
						.bind(log.log_index)
						.bind(log.transaction_index)
						.bind(log.substrate_block_hash)
						.execute(&mut *tx)
						.await?;
					}
					Ok(tx.commit().await?)
				}
				Err(e) => Err(e),
			}
		}
		.await
		.map_err(|e| {
			log::error!(target: "frontier-sql", "{e}");
		});
		// https://www.sqlite.org/pragma.html#pragma_optimize
		let _ = sqlx::query("PRAGMA optimize").execute(&pool).await;
		log::debug!(target: "frontier-sql", "Batch committed");
	}

	fn get_logs(
		storage_override: Arc<dyn StorageOverride<Block>>,
		substrate_block_hash: H256,
	) -> Vec<Log> {
		let mut logs: Vec<Log> = vec![];
		let mut transaction_count: usize = 0;
		let mut log_count: usize = 0;
		let receipts = storage_override
			.current_receipts(substrate_block_hash)
			.unwrap_or_default();

		transaction_count += receipts.len();
		for (transaction_index, receipt) in receipts.iter().enumerate() {
			let receipt_logs = match receipt {
				ethereum::ReceiptV4::Legacy(d)
				| ethereum::ReceiptV4::EIP2930(d)
				| ethereum::ReceiptV4::EIP1559(d)
				| ethereum::ReceiptV4::EIP7702(d) => &d.logs,
			};
			let transaction_index = transaction_index as i32;
			log_count += receipt_logs.len();
			for (log_index, log) in receipt_logs.iter().enumerate() {
				#[allow(clippy::get_first)]
				logs.push(Log {
					address: log.address.as_bytes().to_owned(),
					topic_1: log.topics.get(0).map(|l| l.as_bytes().to_owned()),
					topic_2: log.topics.get(1).map(|l| l.as_bytes().to_owned()),
					topic_3: log.topics.get(2).map(|l| l.as_bytes().to_owned()),
					topic_4: log.topics.get(3).map(|l| l.as_bytes().to_owned()),
					log_index: log_index as i32,
					transaction_index,
					substrate_block_hash: substrate_block_hash.as_bytes().to_owned(),
				});
			}
		}
		log::debug!(
			target: "frontier-sql",
			"Ready to commit {log_count} logs from {transaction_count} transactions"
		);
		logs
	}

	/// Retrieves the status if a block has been already indexed.
	pub async fn is_block_indexed(&self, block_hash: Block::Hash) -> bool {
		sqlx::query("SELECT substrate_block_hash FROM sync_status WHERE substrate_block_hash = ?")
			.bind(block_hash.as_bytes().to_owned())
			.fetch_optional(self.pool())
			.await
			.map(|r| r.is_some())
			.unwrap_or(false)
	}

	/// Retrieves the status if a block is indexed and if also marked as canon.
	pub async fn block_indexed_and_canon_status(
		&self,
		block_hash: Block::Hash,
	) -> BlockIndexedStatus {
		sqlx::query(
			"SELECT b.is_canon FROM sync_status AS s
			INNER JOIN blocks AS b
			ON s.substrate_block_hash = b.substrate_block_hash
			WHERE s.substrate_block_hash = ?",
		)
		.bind(block_hash.as_bytes().to_owned())
		.fetch_optional(self.pool())
		.await
		.map(|result| {
			result
				.map(|row| {
					let is_canon: i32 = row.get(0);
					BlockIndexedStatus {
						indexed: true,
						canon: is_canon != 0,
					}
				})
				.unwrap_or_default()
		})
		.unwrap_or_default()
	}

	/// Sets the provided block as canon.
	pub async fn set_block_as_canon(&self, block_hash: H256) -> Result<SqliteQueryResult, Error> {
		sqlx::query("UPDATE blocks SET is_canon = 1 WHERE substrate_block_hash = ?")
			.bind(block_hash.as_bytes())
			.execute(self.pool())
			.await
	}

	/// Retrieves the first missing canonical block number in decreasing order that hasn't been indexed yet.
	/// If no unindexed block exists or the table or the rows do not exist, then the function
	/// returns `None`.
	pub async fn get_first_missing_canon_block(&self) -> Option<u32> {
		match sqlx::query(
			"SELECT b1.block_number-1
			FROM blocks as b1
			WHERE b1.block_number > 0 AND b1.is_canon=1 AND NOT EXISTS (
				SELECT 1 FROM blocks AS b2
				WHERE b2.block_number = b1.block_number-1
				AND b1.is_canon=1
				AND b2.is_canon=1
			)
			ORDER BY block_number LIMIT 1",
		)
		.fetch_optional(self.pool())
		.await
		{
			Ok(result) => {
				if let Some(row) = result {
					let block_number: u32 = row.get(0);
					return Some(block_number);
				}
			}
			Err(err) => {
				log::debug!(target: "frontier-sql", "Failed retrieving missing block {err:?}");
			}
		}

		None
	}

	/// Retrieves the first pending canonical block hash in decreasing order that hasn't had
	// its logs indexed yet. If no unindexed block exists or the table or the rows do not exist,
	/// then the function returns `None`.
	pub async fn get_first_pending_canon_block(&self) -> Option<H256> {
		match sqlx::query(
			"SELECT s.substrate_block_hash FROM sync_status AS s
			INNER JOIN blocks as b
			ON s.substrate_block_hash = b.substrate_block_hash
			WHERE b.is_canon = 1 AND s.status = 0
			ORDER BY b.block_number LIMIT 1",
		)
		.fetch_optional(self.pool())
		.await
		{
			Ok(result) => {
				if let Some(row) = result {
					let block_hash_bytes: Vec<u8> = row.get(0);
					let block_hash = H256::from_slice(&block_hash_bytes[..]);
					return Some(block_hash);
				}
			}
			Err(err) => {
				log::debug!(target: "frontier-sql", "Failed retrieving missing block {err:?}");
			}
		}

		None
	}

	/// Retrieve the block hash for the last indexed canon block.
	pub async fn last_indexed_canon_block(&self) -> Result<H256, Error> {
		let row = sqlx::query(
			"SELECT b.substrate_block_hash FROM blocks AS b
			INNER JOIN sync_status AS s
			ON s.substrate_block_hash = b.substrate_block_hash
			WHERE b.is_canon=1 AND s.status = 1
			ORDER BY b.id DESC LIMIT 1",
		)
		.fetch_one(self.pool())
		.await?;
		Ok(H256::from_slice(
			&row.try_get::<Vec<u8>, _>(0).unwrap_or_default()[..],
		))
	}

	/// Create the Sqlite database if it does not already exist.
	async fn create_database_if_not_exists(pool: &SqlitePool) -> Result<SqliteQueryResult, Error> {
		sqlx::query(
			"BEGIN;
			CREATE TABLE IF NOT EXISTS logs (
				id INTEGER PRIMARY KEY,
				address BLOB NOT NULL,
				topic_1 BLOB,
				topic_2 BLOB,
				topic_3 BLOB,
				topic_4 BLOB,
				log_index INTEGER NOT NULL,
				transaction_index INTEGER NOT NULL,
				substrate_block_hash BLOB NOT NULL,
				UNIQUE (
					log_index,
					transaction_index,
					substrate_block_hash
				)
			);
			CREATE TABLE IF NOT EXISTS sync_status (
				id INTEGER PRIMARY KEY,
				substrate_block_hash BLOB NOT NULL,
				status INTEGER DEFAULT 0 NOT NULL,
				UNIQUE (
					substrate_block_hash
				)
			);
			CREATE TABLE IF NOT EXISTS blocks (
				id INTEGER PRIMARY KEY,
				block_number INTEGER NOT NULL,
				ethereum_block_hash BLOB NOT NULL,
				substrate_block_hash BLOB NOT NULL,
				ethereum_storage_schema BLOB NOT NULL,
				is_canon INTEGER NOT NULL,
				UNIQUE (
					ethereum_block_hash,
					substrate_block_hash
				)
			);
			CREATE TABLE IF NOT EXISTS transactions (
				id INTEGER PRIMARY KEY,
				ethereum_transaction_hash BLOB NOT NULL,
				substrate_block_hash BLOB NOT NULL,
				ethereum_block_hash BLOB NOT NULL,
				ethereum_transaction_index INTEGER NOT NULL,
				UNIQUE (
					ethereum_transaction_hash,
					substrate_block_hash
				)
			);
			COMMIT;",
		)
		.execute(pool)
		.await
	}

	/// Create the Sqlite database indices if it does not already exist.
	async fn create_indexes_if_not_exist(pool: &SqlitePool) -> Result<SqliteQueryResult, Error> {
		sqlx::query(
			"BEGIN;
			CREATE INDEX IF NOT EXISTS logs_main_idx ON logs (
				address,
				topic_1,
				topic_2,
				topic_3,
				topic_4
			);
			CREATE INDEX IF NOT EXISTS logs_substrate_index ON logs (
				substrate_block_hash
			);
			CREATE INDEX IF NOT EXISTS blocks_number_index ON blocks (
				block_number
			);
			CREATE INDEX IF NOT EXISTS blocks_substrate_index ON blocks (
				substrate_block_hash
			);
			CREATE INDEX IF NOT EXISTS eth_block_hash_idx ON blocks (
				ethereum_block_hash
			);
			CREATE INDEX IF NOT EXISTS eth_tx_hash_idx ON transactions (
				ethereum_transaction_hash
			);
			CREATE INDEX IF NOT EXISTS eth_tx_hash_2_idx ON transactions (
				ethereum_block_hash,
				ethereum_transaction_index
			);
			COMMIT;",
		)
		.execute(pool)
		.await
	}
}

#[async_trait::async_trait]
impl<Block: BlockT<Hash = H256>> fc_api::Backend<Block> for Backend<Block> {
	async fn block_hash(
		&self,
		ethereum_block_hash: &H256,
	) -> Result<Option<Vec<Block::Hash>>, String> {
		let ethereum_block_hash = ethereum_block_hash.as_bytes();
		let res =
			sqlx::query("SELECT substrate_block_hash FROM blocks WHERE ethereum_block_hash = ?")
				.bind(ethereum_block_hash)
				.fetch_all(&self.pool)
				.await
				.ok()
				.map(|rows| {
					rows.iter()
						.map(|row| {
							H256::from_slice(&row.try_get::<Vec<u8>, _>(0).unwrap_or_default()[..])
						})
						.collect()
				});
		Ok(res)
	}

	async fn block_hash_by_number(&self, block_number: u64) -> Result<Option<H256>, String> {
		let block_number = block_number as i64;
		sqlx::query(
			"SELECT ethereum_block_hash FROM blocks WHERE block_number = ? AND is_canon = 1",
		)
		.bind(block_number)
		.fetch_optional(&self.pool)
		.await
		.map(|maybe_row| maybe_row.map(|row| H256::from_slice(&row.get::<Vec<u8>, _>(0)[..])))
		.map_err(|e| format!("Failed to fetch block hash by number: {e}"))
	}

	async fn set_block_hash_by_number(
		&self,
		_block_number: u64,
		_ethereum_block_hash: H256,
	) -> Result<(), String> {
		Ok(())
	}

	async fn transaction_metadata(
		&self,
		ethereum_transaction_hash: &H256,
	) -> Result<Vec<TransactionMetadata<Block>>, String> {
		let ethereum_transaction_hash = ethereum_transaction_hash.as_bytes();
		let out = sqlx::query(
			"SELECT
				substrate_block_hash, ethereum_block_hash, ethereum_transaction_index
			FROM transactions WHERE ethereum_transaction_hash = ?",
		)
		.bind(ethereum_transaction_hash)
		.fetch_all(&self.pool)
		.await
		.unwrap_or_default()
		.iter()
		.map(|row| {
			let substrate_block_hash =
				H256::from_slice(&row.try_get::<Vec<u8>, _>(0).unwrap_or_default()[..]);
			let ethereum_block_hash =
				H256::from_slice(&row.try_get::<Vec<u8>, _>(1).unwrap_or_default()[..]);
			let ethereum_transaction_index = row.try_get::<i32, _>(2).unwrap_or_default() as u32;
			TransactionMetadata {
				substrate_block_hash,
				ethereum_block_hash,
				ethereum_index: ethereum_transaction_index,
			}
		})
		.collect();

		Ok(out)
	}

	fn log_indexer(&self) -> &dyn fc_api::LogIndexerBackend<Block> {
		self
	}

	async fn first_block_hash(&self) -> Result<Block::Hash, String> {
		// Retrieves the block hash for the earliest indexed block, maybe it's not canon.
		sqlx::query("SELECT substrate_block_hash FROM blocks ORDER BY block_number ASC LIMIT 1")
			.fetch_one(self.pool())
			.await
			.map(|row| H256::from_slice(&row.get::<Vec<u8>, _>(0)[..]))
			.map_err(|e| format!("Failed to fetch oldest block hash: {e}"))
	}

	async fn latest_block_hash(&self) -> Result<Block::Hash, String> {
		// Return the latest indexed canonical block hash.
		// This prevents returning stale data during reorgs.
		//
		// Note: During initial sync or after restart while mapping-sync catches up,
		// this returns the genesis block hash (first indexed block). This is consistent
		// with Geth's behavior where eth_getBlockByNumber("latest") returns block 0
		// during initial sync. Users can check sync status via eth_syncing to determine
		// if the node is still catching up.
		sqlx::query(
			"SELECT substrate_block_hash FROM blocks WHERE is_canon = 1 ORDER BY block_number DESC LIMIT 1",
		)
		.fetch_optional(self.pool())
		.await
		.map_err(|e| format!("Failed to fetch best hash: {e}"))?
		.map(|row| H256::from_slice(&row.get::<Vec<u8>, _>(0)[..]))
		.ok_or_else(|| "No canonical blocks indexed yet".to_string())
	}
}

#[async_trait::async_trait]
impl<Block: BlockT<Hash = H256>> fc_api::LogIndexerBackend<Block> for Backend<Block> {
	fn is_indexed(&self) -> bool {
		true
	}

	async fn filter_logs(
		&self,
		from_block: u64,
		to_block: u64,
		addresses: Vec<H160>,
		topics: Vec<Vec<H256>>,
	) -> Result<Vec<FilteredLog<Block>>, String> {
		let mut unique_topics: [HashSet<H256>; 4] = [
			HashSet::new(),
			HashSet::new(),
			HashSet::new(),
			HashSet::new(),
		];
		for (topic_index, topic_options) in topics.into_iter().enumerate() {
			unique_topics[topic_index].extend(topic_options);
		}

		let log_key = format!("{from_block}-{to_block}-{addresses:?}-{unique_topics:?}");
		let mut qb = QueryBuilder::new("");
		let query = build_query(&mut qb, from_block, to_block, addresses, unique_topics);
		let sql = query.sql();

		let mut conn = self
			.pool()
			.acquire()
			.await
			.map_err(|err| format!("failed acquiring sqlite connection: {err}"))?;
		let log_key2 = log_key.clone();
		conn.lock_handle()
			.await
			.map_err(|err| format!("{err:?}"))?
			.set_progress_handler(self.num_ops_timeout, move || {
				log::debug!(target: "frontier-sql", "Sqlite progress_handler triggered for {log_key2}");
				false
			});
		log::debug!(target: "frontier-sql", "Query: {sql:?} - {log_key}");

		let mut out: Vec<FilteredLog<Block>> = vec![];
		let mut rows = query.fetch(&mut *conn);
		let maybe_err = loop {
			match rows.try_next().await {
				Ok(Some(row)) => {
					// Substrate block hash
					let substrate_block_hash =
						H256::from_slice(&row.try_get::<Vec<u8>, _>(0).unwrap_or_default()[..]);
					// Ethereum block hash
					let ethereum_block_hash =
						H256::from_slice(&row.try_get::<Vec<u8>, _>(1).unwrap_or_default()[..]);
					// Block number
					let block_number = row.try_get::<i32, _>(2).unwrap_or_default() as u32;
					// Ethereum storage schema
					let ethereum_storage_schema: EthereumStorageSchema =
						Decode::decode(&mut &row.try_get::<Vec<u8>, _>(3).unwrap_or_default()[..])
							.map_err(|_| {
								"Cannot decode EthereumStorageSchema for block".to_string()
							})?;
					// Transaction index
					let transaction_index = row.try_get::<i32, _>(4).unwrap_or_default() as u32;
					// Log index
					let log_index = row.try_get::<i32, _>(5).unwrap_or_default() as u32;
					out.push(FilteredLog {
						substrate_block_hash,
						ethereum_block_hash,
						block_number,
						ethereum_storage_schema,
						transaction_index,
						log_index,
					});
				}
				Ok(None) => break None, // no more rows
				Err(err) => break Some(err),
			};
		};
		drop(rows);
		conn.lock_handle()
			.await
			.map_err(|err| format!("{err:?}"))?
			.remove_progress_handler();

		if let Some(err) = maybe_err {
			log::error!(target: "frontier-sql", "Failed to query sql db: {err:?} - {log_key}");
			return Err("Failed to query sql db with statement".to_string());
		}

		log::info!(target: "frontier-sql", "FILTER remove handler - {log_key}");
		Ok(out)
	}
}

/// Build a SQL query to retrieve a list of logs given certain constraints.
fn build_query<'a>(
	qb: &'a mut QueryBuilder<Sqlite>,
	from_block: u64,
	to_block: u64,
	addresses: Vec<H160>,
	topics: [HashSet<H256>; 4],
) -> Query<'a, Sqlite, SqliteArguments<'a>> {
	qb.push(
		"
SELECT
	l.substrate_block_hash,
	b.ethereum_block_hash,
	b.block_number,
	b.ethereum_storage_schema,
	l.transaction_index,
	l.log_index
FROM logs AS l
INNER JOIN blocks AS b
ON (b.block_number BETWEEN ",
	);
	qb.separated(" AND ")
		.push_bind(from_block as i64)
		.push_bind(to_block as i64)
		.push_unseparated(")");
	qb.push(" AND b.substrate_block_hash = l.substrate_block_hash")
		.push(" AND b.is_canon = 1")
		.push("\nWHERE 1");

	if !addresses.is_empty() {
		qb.push(" AND l.address IN (");
		let mut qb_addr = qb.separated(", ");
		addresses.iter().for_each(|addr| {
			qb_addr.push_bind(addr.as_bytes().to_owned());
		});
		qb_addr.push_unseparated(")");
	}

	for (i, topic_options) in topics.iter().enumerate() {
		match topic_options.len().cmp(&1) {
			Ordering::Greater => {
				qb.push(format!(" AND l.topic_{} IN (", i + 1));
				let mut qb_topic = qb.separated(", ");
				topic_options.iter().for_each(|t| {
					qb_topic.push_bind(t.as_bytes().to_owned());
				});
				qb_topic.push_unseparated(")");
			}
			Ordering::Equal => {
				qb.push(format!(" AND l.topic_{} = ", i + 1)).push_bind(
					topic_options
						.iter()
						.next()
						.expect("length is 1, must exist; qed")
						.as_bytes()
						.to_owned(),
				);
			}
			Ordering::Less => {}
		}
	}

	qb.push(
		"
ORDER BY b.block_number ASC, l.transaction_index ASC, l.log_index ASC
LIMIT 10001",
	);

	qb.build()
}
