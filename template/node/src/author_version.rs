//! The node version this binary declares in the blocks it authors.
//!
//! - [`inherent_data_provider`] hands the version to every block the node builds;
//! - [`warn_if_below_minimum`] tells a validator's operator at startup that the
//!   chain's minimum author version is above this binary's.
//!
//! The runtime enforces the minimum; this module only declares and reports. A
//! validator below the minimum still starts, imports and votes on finality: it
//! just cannot author until it upgrades.

use pallet_validator_set::{author_version::InherentDataProvider, MinAuthorVersion, NodeVersion};
use sc_client_api::{StorageKey, StorageProvider};
use scale_codec::Decode;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::Block as BlockT;

use crate::client::FullBackend;

/// This binary's version. Parsed at compile time: a crate version that does not
/// fit `major.minor.patch` in u16 fails the build.
pub const AUTHOR_VERSION: NodeVersion = match NodeVersion::parse(env!("CARGO_PKG_VERSION")) {
	Some(version) => version,
	None => panic!("crate version must be major.minor.patch, each part up to 65535"),
};

/// Declares [`AUTHOR_VERSION`] in every block this node builds.
pub fn inherent_data_provider() -> InherentDataProvider {
	InherentDataProvider(AUTHOR_VERSION)
}

/// Logs an error if the chain's minimum author version, as of the best block,
/// is above this binary's. A node still syncing reads an older state, so this
/// can miss a recent minimum; the runtime rejects its blocks regardless.
pub fn warn_if_below_minimum<B, C>(client: &C)
where
	B: BlockT,
	C: StorageProvider<B, FullBackend<B>> + HeaderBackend<B>,
{
	let key = StorageKey(MinAuthorVersion::<orbinum_runtime::Runtime>::hashed_key().to_vec());
	let min = match client.storage(client.info().best_hash, &key) {
		Ok(Some(data)) => match NodeVersion::decode(&mut &data.0[..]) {
			Ok(min) => min,
			Err(e) => return log::warn!("cannot decode the minimum author version: {e}"),
		},
		Ok(None) => return,
		Err(e) => return log::warn!("cannot read the minimum author version: {e}"),
	};
	if AUTHOR_VERSION < min {
		log::error!(
			"this node is {AUTHOR_VERSION}, the chain requires at least {min} to author blocks: \
			 it will import and vote but not author until it is upgraded"
		);
	}
}
