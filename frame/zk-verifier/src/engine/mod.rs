//! The pallet's logic, one concern per module: registering and activating keys
//! under the rule every stored key is held to ([`registry`]), storing them with
//! their hash and prepared form ([`keys`]), encoding statements into public
//! inputs ([`encoding`]), verifying proofs ([`verifier`]), serving other pallets
//! ([`port`]), the runtime API ([`runtime_api`]) and the storage migrations
//! ([`migrations`]). This module holds the bounds they share.

pub mod encoding;
mod keys;
pub mod migrations;
pub(crate) mod port;
mod registry;
mod runtime_api;
pub(crate) mod verifier;

use crate::{Config, Pallet};

impl<T: Config> Pallet<T> {
	/// Upper bound on stored versions per circuit — keeps the versions DoubleMap
	/// and the runtime-API iteration provably bounded. Registration is `AdminOrigin`-only,
	/// so this is operator-discipline, not an attacker limit.
	pub(crate) const MAX_VERSIONS_PER_CIRCUIT: u32 = 64;

	/// The version genesis registers.
	pub(crate) const FIRST_VERSION: u32 = 1;
}
