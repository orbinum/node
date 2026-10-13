//! Runtime-level storage migrations, run by `Executive` on upgrade (`Migrations`).

use crate::{AccountId, Runtime};
use frame_support::{traits::OnRuntimeUpgrade, weights::Weight};
use sp_core::crypto::key_types::AURA;

#[cfg(feature = "try-runtime")]
use alloc::vec::Vec;

/// Moves relay fees credited to a validator's Aura key, read as an account, to
/// the validator's own account (spec 19).
///
/// Until spec 19 the block author was the Aura key taken as an `AccountId`, so a
/// validator whose account is not its Aura key earned its fallback relay fees on
/// an account nobody claims from. The Aura key's owner is the validator that
/// registered it (`pallet_session::KeyOwner`); a key no current validator owns is
/// left where it is. Idempotent: once moved, no balance sits on an owned key.
pub struct MoveAuraKeyRelayFees;

impl MoveAuraKeyRelayFees {
	/// `(aura_key_account, asset_id, amount, validator)` for every balance to move.
	fn moves() -> alloc::vec::Vec<(AccountId, u32, u128, AccountId)> {
		pallet_relayer::PendingRelayerFees::<Runtime>::iter()
			.filter_map(|(holder, asset_id, amount)| {
				let key: &[u8] = holder.as_ref();
				let owner = pallet_session::Pallet::<Runtime>::key_owner(AURA, key)?;
				(owner != holder).then_some((holder, asset_id, amount, owner))
			})
			.collect()
	}
}

impl OnRuntimeUpgrade for MoveAuraKeyRelayFees {
	fn on_runtime_upgrade() -> Weight {
		let entries = pallet_relayer::PendingRelayerFees::<Runtime>::iter().count() as u64;
		let moves = Self::moves();
		for (holder, asset_id, amount, validator) in &moves {
			pallet_relayer::PendingRelayerFees::<Runtime>::remove(holder, asset_id);
			pallet_relayer::PendingRelayerFees::<Runtime>::mutate(validator, asset_id, |b| {
				*b = b.saturating_add(*amount);
			});
		}
		log::info!(
			target: "runtime::migrations",
			"moved {} relay fee balance(s) from Aura keys to their validators",
			moves.len(),
		);
		let moved = moves.len() as u64;
		// Two passes over the map, a key-owner read per entry, and per move a
		// read and two writes.
		<Runtime as frame_system::Config>::DbWeight::get().reads_writes(
			entries.saturating_mul(3).saturating_add(moved),
			moved.saturating_mul(2),
		)
	}

	#[cfg(feature = "try-runtime")]
	fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
		use scale_codec::Encode;
		let total: u128 = pallet_relayer::PendingRelayerFees::<Runtime>::iter_values().sum();
		Ok((total, Self::moves().len() as u32).encode())
	}

	#[cfg(feature = "try-runtime")]
	fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
		use scale_codec::Decode;
		let (before, to_move) = <(u128, u32)>::decode(&mut &state[..])
			.map_err(|_| sp_runtime::TryRuntimeError::Other("undecodable pre-upgrade state"))?;
		let after: u128 = pallet_relayer::PendingRelayerFees::<Runtime>::iter_values().sum();
		frame_support::ensure!(before == after, "relay fee total changed");
		frame_support::ensure!(
			Self::moves().is_empty(),
			"a fee balance is still on an Aura key"
		);
		log::info!(target: "runtime::migrations", "{to_move} balance(s) moved, total unchanged");
		Ok(())
	}
}
