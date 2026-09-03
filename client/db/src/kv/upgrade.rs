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

use std::{
	fmt, fs,
	io::{self, ErrorKind, Read, Write},
	path::{Path, PathBuf},
	sync::Arc,
};

use scale_codec::{Decode, Encode};
// Substrate
use sc_client_db::DatabaseSource;
use sp_blockchain::HeaderBackend;
use sp_core::H256;
use sp_runtime::traits::Block as BlockT;

/// Version file name.
const VERSION_FILE_NAME: &str = "db_version";

/// Current db version.
const CURRENT_VERSION: u32 = 2;

/// Number of columns in each version.
const _V1_NUM_COLUMNS: u32 = 4;
/// V2 added BLOCK_NUMBER_MAPPING as column 4 (stable2512), so NUM_COLUMNS = 5.
const V2_NUM_COLUMNS: u32 = 5;

/// Database upgrade errors.
#[derive(Debug)]
pub(crate) enum UpgradeError {
	/// Database version cannot be read from existing db_version file.
	UnknownDatabaseVersion,
	/// Database version no longer supported.
	UnsupportedVersion(u32),
	/// Database version comes from future version of the client.
	FutureDatabaseVersion(u32),
	/// Common io error.
	Io(io::Error),
}

pub(crate) type UpgradeResult<T> = Result<T, UpgradeError>;

pub(crate) struct UpgradeVersion1To2Summary {
	pub success: u32,
	pub error: Vec<H256>,
}

impl From<io::Error> for UpgradeError {
	fn from(err: io::Error) -> Self {
		UpgradeError::Io(err)
	}
}

impl fmt::Display for UpgradeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			UpgradeError::UnknownDatabaseVersion => {
				write!(
					f,
					"Database version cannot be read from existing db_version file"
				)
			}
			UpgradeError::UnsupportedVersion(version) => {
				write!(f, "Database version no longer supported: {version}")
			}
			UpgradeError::FutureDatabaseVersion(version) => {
				write!(
					f,
					"Database version comes from future version of the client: {version}"
				)
			}
			UpgradeError::Io(err) => write!(f, "Io error: {err}"),
		}
	}
}

/// Upgrade database to current version.
pub(crate) fn upgrade_db<Block: BlockT, C: HeaderBackend<Block>>(
	client: Arc<C>,
	db_path: &Path,
	source: &DatabaseSource,
) -> UpgradeResult<()> {
	let db_version = current_version(db_path)?;
	match db_version {
		0 => return Err(UpgradeError::UnsupportedVersion(db_version)),
		1 => {
			let summary: UpgradeVersion1To2Summary = match source {
				DatabaseSource::ParityDb { .. } => {
					migrate_1_to_2_parity_db::<Block, C>(client, db_path)?
				}
				#[cfg(feature = "rocksdb")]
				DatabaseSource::RocksDb { .. } => migrate_1_to_2_rocks_db::<Block, C>(client, db_path)?,
				_ => panic!("DatabaseSource required for upgrade ParityDb | RocksDb"),
			};
			if !summary.error.is_empty() {
				panic!(
					"Inconsistent migration from version 1 to 2. Failed on {:?}",
					summary.error
				);
			} else {
				log::info!("✔️ Successful Frontier DB migration from version 1 to version 2 ({:?} entries).", summary.success);
			}
		}
		CURRENT_VERSION => (),
		_ => return Err(UpgradeError::FutureDatabaseVersion(db_version)),
	}
	update_version(db_path)?;
	Ok(())
}

/// Reads current database version from the file at given path.
/// If the file does not exist it gets created with version 1.
pub(crate) fn current_version(path: &Path) -> UpgradeResult<u32> {
	match fs::File::open(version_file_path(path)) {
		Err(ref err) if err.kind() == ErrorKind::NotFound => {
			fs::create_dir_all(path)?;
			let mut file = fs::File::create(version_file_path(path))?;
			file.write_all(format!("{CURRENT_VERSION}").as_bytes())?;
			Ok(CURRENT_VERSION)
		}
		Err(_) => Err(UpgradeError::UnknownDatabaseVersion),
		Ok(mut file) => {
			let mut s = String::new();
			file.read_to_string(&mut s)
				.map_err(|_| UpgradeError::UnknownDatabaseVersion)?;
			s.parse::<u32>()
				.map_err(|_| UpgradeError::UnknownDatabaseVersion)
		}
	}
}

/// Writes current database version to the file.
/// Creates a new file if the version file does not exist yet.
pub(crate) fn update_version(path: &Path) -> io::Result<()> {
	fs::create_dir_all(path)?;
	let mut file = fs::File::create(version_file_path(path))?;
	file.write_all(format!("{CURRENT_VERSION}").as_bytes())?;
	Ok(())
}

/// Returns the version file path.
fn version_file_path(path: &Path) -> PathBuf {
	let mut file_path = path.to_owned();
	file_path.push(VERSION_FILE_NAME);
	file_path
}

/// Migration from version1 to version2:
/// - The format of the Ethereum<>Substrate block mapping changed to support equivocation.
/// - Migrating schema from One-to-one to One-to-many (EthHash: Vec<SubstrateHash>) relationship.
#[cfg(feature = "rocksdb")]
pub(crate) fn migrate_1_to_2_rocks_db<Block: BlockT, C: HeaderBackend<Block>>(
	client: Arc<C>,
	db_path: &Path,
) -> UpgradeResult<UpgradeVersion1To2Summary> {
	log::info!("🔨 Running Frontier DB migration from version 1 to version 2. Please wait.");
	let mut res = UpgradeVersion1To2Summary {
		success: 0,
		error: vec![],
	};
	// Process a batch of hashes in a single db transaction
	#[rustfmt::skip]
	let mut process_chunk = |
		db: &kvdb_rocksdb::Database,
		ethereum_hashes: &[smallvec::SmallVec<[u8; 32]>]
	| -> UpgradeResult<()> {
		let mut transaction = db.transaction();
		for ethereum_hash in ethereum_hashes {
			let mut maybe_error = true;
			if let Some(substrate_hash) = db.get(super::columns::BLOCK_MAPPING, ethereum_hash)? {
				// Only update version1 data
				let decoded = Vec::<Block::Hash>::decode(&mut &substrate_hash[..]);
				if decoded.is_err() || decoded.unwrap().is_empty() {
					// Verify the substrate hash is part of the canonical chain.
					if let Ok(Some(number)) = client.number(Block::Hash::decode(&mut &substrate_hash[..]).unwrap()) {
						if let Ok(Some(hash)) = client.hash(number) {
							transaction.put_vec(
								super::columns::BLOCK_MAPPING,
								ethereum_hash,
								vec![hash].encode(),
							);
							res.success += 1;
							maybe_error = false;
						}
					}
				} else {
					// If version 2 data, we just consider this hash a success.
					// This can happen if the process was closed in the middle of the migration.
					res.success += 1;
					maybe_error = false;
				}
			}
			if maybe_error {
				res.error.push(H256::from_slice(ethereum_hash));
			}
		}
		db.write(transaction)
			.map_err(|_| io::Error::other("Failed to commit on migrate_1_to_2"))?;
		log::debug!(
			target: "fc-db-upgrade",
			"🔨 Success {}, error {}.",
			res.success,
			res.error.len()
		);
		Ok(())
	};

	let db_cfg = kvdb_rocksdb::DatabaseConfig::with_columns(V2_NUM_COLUMNS);
	let db = kvdb_rocksdb::Database::open(&db_cfg, db_path)?;

	// Get all the block hashes we need to update
	let ethereum_hashes: Vec<_> = db
		.iter(super::columns::BLOCK_MAPPING)
		.filter_map(|entry| entry.map_or(None, |r| Some(r.0)))
		.collect();

	// Read and update each entry in db transaction batches
	const CHUNK_SIZE: usize = 10_000;
	let chunks = ethereum_hashes.chunks(CHUNK_SIZE);
	let all_len = ethereum_hashes.len();
	for (i, chunk) in chunks.enumerate() {
		process_chunk(&db, chunk)?;
		log::debug!(
			target: "fc-db-upgrade",
			"🔨 Processed {} of {} entries.",
			(CHUNK_SIZE * (i + 1)),
			all_len
		);
	}
	Ok(res)
}

pub(crate) fn migrate_1_to_2_parity_db<Block: BlockT, C: HeaderBackend<Block>>(
	client: Arc<C>,
	db_path: &Path,
) -> UpgradeResult<UpgradeVersion1To2Summary> {
	log::info!("🔨 Running Frontier DB migration from version 1 to version 2. Please wait.");
	let mut res = UpgradeVersion1To2Summary {
		success: 0,
		error: vec![],
	};
	// Process a batch of hashes in a single db transaction
	#[rustfmt::skip]
	let mut process_chunk = |
		db: &parity_db::Db,
		ethereum_hashes: &[Vec<u8>]
	| -> UpgradeResult<()> {
		let mut transaction = vec![];
		for ethereum_hash in ethereum_hashes {
			let mut maybe_error = true;
			if let Some(substrate_hash) = db.get(super::columns::BLOCK_MAPPING as u8, ethereum_hash).map_err(|_|
				io::Error::other("Key does not exist")
			)? {
				// Only update version1 data
				let decoded = Vec::<Block::Hash>::decode(&mut &substrate_hash[..]);
				if decoded.is_err() || decoded.unwrap().is_empty() {
					// Verify the substrate hash is part of the canonical chain.
					if let Ok(Some(number)) = client.number(Block::Hash::decode(&mut &substrate_hash[..]).unwrap()) {
						if let Ok(Some(hash)) = client.hash(number) {
							transaction.push((
								super::columns::BLOCK_MAPPING as u8,
								ethereum_hash,
								Some(vec![hash].encode()),
							));
							res.success += 1;
							maybe_error = false;
						}
					}
				}
			}
			if maybe_error {
				res.error.push(H256::from_slice(ethereum_hash));
			}
		}
		db.commit(transaction)
			.map_err(|_| io::Error::other("Failed to commit on migrate_1_to_2"))?;
		Ok(())
	};

	let mut db_cfg = parity_db::Options::with_columns(db_path, V2_NUM_COLUMNS as u8);
	db_cfg.columns[super::columns::BLOCK_MAPPING as usize].btree_index = true;

	let db = parity_db::Db::open_or_create(&db_cfg)
		.map_err(|_| io::Error::other("Failed to open db"))?;

	// Get all the block hashes we need to update
	let ethereum_hashes: Vec<_> = match db.iter(super::columns::BLOCK_MAPPING as u8) {
		Ok(mut iter) => {
			let mut hashes = vec![];
			while let Ok(Some((k, _))) = iter.next() {
				hashes.push(k);
			}
			hashes
		}
		Err(_) => vec![],
	};
	// Read and update each entry in db transaction batches
	const CHUNK_SIZE: usize = 10_000;
	let chunks = ethereum_hashes.chunks(CHUNK_SIZE);
	for chunk in chunks {
		process_chunk(&db, chunk)?;
	}
	Ok(res)
}
