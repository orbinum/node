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

use crate::client::Client;

#[cfg(test)]
mod tests;

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
pub fn warn_if_below_minimum(client: &Client) {
	let key = StorageKey(MinAuthorVersion::<orbinum_runtime::Runtime>::hashed_key().to_vec());
	let stored = match client.storage(client.info().best_hash, &key) {
		Ok(stored) => stored,
		Err(e) => return log::warn!("cannot read the minimum author version: {e}"),
	};
	match minimum_above_ours(stored.as_ref().map(|data| &data.0[..])) {
		Ok(Some(min)) => log::error!(
			"this node is {AUTHOR_VERSION}, the chain requires at least {min} to author blocks: \
			 it will import and vote but not author until it is upgraded"
		),
		Ok(None) => {}
		Err(e) => log::warn!("cannot decode the minimum author version: {e}"),
	}
}

/// The stored minimum (`MinAuthorVersion`'s raw value), if it is above [`AUTHOR_VERSION`].
fn minimum_above_ours(stored: Option<&[u8]>) -> Result<Option<NodeVersion>, scale_codec::Error> {
	let Some(mut data) = stored else {
		return Ok(None);
	};
	let min = NodeVersion::decode(&mut data)?;
	Ok((AUTHOR_VERSION < min).then_some(min))
}
