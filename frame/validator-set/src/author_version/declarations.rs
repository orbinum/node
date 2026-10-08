//! The on-chain rules for declared author versions: which declarations a block
//! accepts, what is recorded, when a block is invalid, and the quorum a new
//! minimum needs.

use super::NodeVersion;
use crate::{
	ApprovedValidators, AuthorVersionNoted, Call, Config, Error, LastAuthorVersion,
	MinAuthorVersion, Pallet,
};
use frame_support::{
	dispatch::DispatchResult,
	ensure,
	traits::{FindAuthor, Get},
};
use sp_runtime::traits::Saturating;

impl<T: Config> Pallet<T> {
	/// The inherent call declaring `version`, or none if the chain would refuse
	/// it. A refused node then authors a block without a declaration, which
	/// `settle_author_declaration` rejects; the node logs why here instead of the
	/// proposer's generic "inherent returned unexpected error".
	pub(crate) fn declaration_call(version: NodeVersion) -> Option<Call<T>> {
		if let Some(min) = MinAuthorVersion::<T>::get().filter(|min| version < *min) {
			log::warn!(
				target: "runtime::validator-set",
				"this node's version {version} is below the minimum {min}: it cannot author until it upgrades",
			);
			return None;
		}
		Some(Call::note_author_version { version })
	}

	/// Accepts the block author's declaration: at most one per block, never
	/// below the minimum.
	pub(crate) fn note_declaration(version: NodeVersion) -> DispatchResult {
		ensure!(
			!AuthorVersionNoted::<T>::get(),
			Error::<T>::AuthorVersionAlreadyNoted
		);
		if let Some(min) = MinAuthorVersion::<T>::get() {
			ensure!(version >= min, Error::<T>::AuthorVersionTooOld);
		}
		AuthorVersionNoted::<T>::put(true);
		Self::record_author_version(version);
		Ok(())
	}

	/// Closes the block's declaration. Without one, the author stops counting
	/// toward a quorum (it may have rolled back to an older binary), and while
	/// a minimum is set the block is invalid: panicking in `on_finalize` is how
	/// FRAME rejects a block, so the author's node fails to build it and any
	/// other node fails to import it.
	pub(crate) fn settle_author_declaration() {
		if AuthorVersionNoted::<T>::take() {
			return;
		}
		Self::forget_author_version();
		if let Some(min) = MinAuthorVersion::<T>::get() {
			panic!("block author declared no node version; minimum is {min}");
		}
	}

	/// Whether at least 2/3 of the approved set declared `min` or newer within
	/// `QuorumWindow`. An empty set proves nothing: the session may still run
	/// validators that never declared.
	pub(crate) fn has_version_quorum(min: &NodeVersion) -> bool {
		let validators = ApprovedValidators::<T>::get();
		if validators.is_empty() {
			return false;
		}
		let now = frame_system::Pallet::<T>::block_number();
		let window = T::QuorumWindow::get();
		let ready = validators
			.iter()
			.filter(|v| {
				LastAuthorVersion::<T>::get(v).is_some_and(|(version, at)| {
					version >= *min && now.saturating_sub(at) <= window
				})
			})
			.count();
		ready.saturating_mul(3) >= validators.len().saturating_mul(2)
	}

	/// Records `version` against the block's author if it is approved. Only
	/// approved validators count toward the quorum, and keeping the map to them
	/// bounds it by `MaxValidators`.
	fn record_author_version(version: NodeVersion) {
		let Some(author) = Self::block_author() else {
			return;
		};
		if ApprovedValidators::<T>::get().contains(&author) {
			let now = frame_system::Pallet::<T>::block_number();
			LastAuthorVersion::<T>::insert(author, (version, now));
		}
	}

	/// Drops the block's author's last declaration.
	fn forget_author_version() {
		if let Some(author) = Self::block_author() {
			LastAuthorVersion::<T>::remove(author);
		}
	}

	/// The current block's author, from its pre-runtime digests.
	fn block_author() -> Option<T::AccountId> {
		let digest = frame_system::Pallet::<T>::digest();
		T::FindAuthor::find_author(digest.logs.iter().filter_map(|d| d.as_pre_runtime()))
	}
}
