//! Runtime-level storage migrations, run by `Executive` on upgrade (`Migrations`).
//!
//! Spec 19 removes `pallet_relayer` (index 16): its fee ledger moves into the
//! shielded pool, the rest of its storage is cleared, and EVM tips stranded on
//! accounts derived from Aura keys move to their validators.

use crate::{AccountId, Balances, Runtime};
use frame_support::{
	parameter_types,
	traits::{
		fungible::{Inspect, Mutate},
		tokens::{Fortitude, Preservation},
		OnRuntimeUpgrade,
	},
	weights::Weight,
};
use sp_core::{crypto::key_types::AURA, H160};

#[cfg(feature = "try-runtime")]
use alloc::vec::Vec;

/// `pallet_relayer` storage, read once more before its prefix is cleared.
pub(crate) mod relayer {
	use crate::AccountId;
	use frame_support::{storage_alias, Blake2_128Concat};

	#[storage_alias]
	pub type PendingRelayerFees = StorageDoubleMap<
		Relayer,
		Blake2_128Concat,
		AccountId,
		Blake2_128Concat,
		u32,
		u128,
		frame_support::pallet_prelude::ValueQuery,
	>;

	#[cfg(feature = "try-runtime")]
	#[storage_alias]
	pub type MinRelayFee = StorageValue<Relayer, u128, frame_support::pallet_prelude::OptionQuery>;
}

/// The validator that owns `key` as its Aura session key, if any.
fn aura_key_owner(key: &[u8]) -> Option<AccountId> {
	pallet_session::Pallet::<Runtime>::key_owner(AURA, key)
}

fn db_weight(reads: u64, writes: u64) -> Weight {
	<Runtime as frame_system::Config>::DbWeight::get().reads_writes(reads, writes)
}

/// Moves every unclaimed fee from `pallet_relayer::PendingRelayerFees` to
/// `pallet_shielded_pool::PendingFees`.
///
/// Until spec 19 the block author was the Aura key read as an account, so a
/// validator whose account is not its Aura key earned fees on that key. Such a
/// balance is credited to the validator owning the key
/// (`pallet_session::KeyOwner`); any other holder keeps its own. Idempotent: the
/// old map is drained.
pub struct RelayerFeesToPool;

impl OnRuntimeUpgrade for RelayerFeesToPool {
	fn on_runtime_upgrade() -> Weight {
		let mut moved = 0u64;
		let mut rekeyed = 0u64;
		for (holder, asset_id, amount) in relayer::PendingRelayerFees::drain() {
			let key: &[u8] = holder.as_ref();
			let validator = aura_key_owner(key).unwrap_or(holder.clone());
			if validator != holder {
				rekeyed += 1;
			}
			pallet_shielded_pool::PendingFees::<Runtime>::mutate(&validator, asset_id, |b| {
				*b = b.saturating_add(amount);
			});
			moved += 1;
		}
		log::info!(
			target: "runtime::migrations",
			"moved {moved} fee balance(s) to the shielded pool, {rekeyed} from Aura keys to their validators",
		);
		// Per entry: the drained read and write, a key-owner read, and the new
		// balance's read and write.
		db_weight(
			moved.saturating_mul(3).saturating_add(1),
			moved.saturating_mul(2),
		)
	}

	#[cfg(feature = "try-runtime")]
	fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
		use frame_support::traits::Get;
		use scale_codec::Encode;
		let floor = <Runtime as pallet_shielded_pool::Config>::MinSpendFee::get();
		if let Some(set) = relayer::MinRelayFee::get() {
			frame_support::ensure!(
				set == floor,
				"MinRelayFee was changed on chain; MinSpendFee would revert it"
			);
		}
		let old: u128 = relayer::PendingRelayerFees::iter_values().sum();
		let new: u128 = pallet_shielded_pool::PendingFees::<Runtime>::iter_values().sum();
		Ok(old.saturating_add(new).encode())
	}

	#[cfg(feature = "try-runtime")]
	fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
		use scale_codec::Decode;
		let before = u128::decode(&mut &state[..])
			.map_err(|_| sp_runtime::TryRuntimeError::Other("undecodable pre-upgrade state"))?;
		let after: u128 = pallet_shielded_pool::PendingFees::<Runtime>::iter_values().sum();
		frame_support::ensure!(before == after, "fee total changed");
		frame_support::ensure!(
			relayer::PendingRelayerFees::iter().next().is_none(),
			"pallet_relayer still holds fees"
		);
		frame_support::ensure!(
			pallet_shielded_pool::PendingFees::<Runtime>::iter_keys().all(|(who, _)| {
				let key: &[u8] = who.as_ref();
				aura_key_owner(key).is_none_or(|owner| owner == who)
			}),
			"a fee balance is still on an Aura key"
		);
		Ok(())
	}
}

parameter_types! {
	pub const RelayerPalletName: &'static str = "Relayer";
}

/// Clears what is left of `pallet_relayer`: the relay registry, commits,
/// allowed selectors and fee floor. Runs after [`RelayerFeesToPool`].
pub type RemoveRelayerPallet = frame_support::migrations::RemovePallet<
	RelayerPalletName,
	<Runtime as frame_system::Config>::DbWeight,
>;

/// The account that collected EVM priority tips for an Aura key before spec 19:
/// the H160 taken from bytes 4..24 of the key, under the runtime's address mapping.
fn stranded_tip_account(aura_key: &[u8]) -> Option<AccountId> {
	let bytes = aura_key.get(4..24)?;
	Some(crate::evm_account::evm_h160_to_account_id(
		H160::from_slice(bytes),
	))
}

/// Moves EVM priority tips paid to Aura-derived coinbase accounts to the
/// validators owning those keys.
///
/// Until spec 19 `block.coinbase` was 20 bytes of the author's Aura key, and the
/// tip went to the account that address maps to, which no key controls. Only keys
/// a current validator owns are moved; a rotated key's account is left. Idempotent:
/// a moved account holds nothing.
pub struct MoveStrandedEvmTips;

impl MoveStrandedEvmTips {
	/// `(stranded_account, validator, amount)` for every balance to move.
	fn moves() -> alloc::vec::Vec<(AccountId, AccountId, u128)> {
		pallet_session::KeyOwner::<Runtime>::iter()
			.filter(|((key_type, _), _)| *key_type == AURA)
			.filter_map(|((_, key), validator)| {
				let source = stranded_tip_account(&key)?;
				let amount = <Balances as Inspect<AccountId>>::reducible_balance(
					&source,
					Preservation::Expendable,
					Fortitude::Polite,
				);
				(amount > 0 && source != validator).then_some((source, validator, amount))
			})
			.collect()
	}
}

impl OnRuntimeUpgrade for MoveStrandedEvmTips {
	fn on_runtime_upgrade() -> Weight {
		let owners = pallet_session::KeyOwner::<Runtime>::iter().count() as u64;
		let moves = Self::moves();
		let mut moved = 0u64;
		for (source, validator, amount) in &moves {
			match <Balances as Mutate<AccountId>>::transfer(
				source,
				validator,
				*amount,
				Preservation::Expendable,
			) {
				Ok(_) => moved += 1,
				Err(e) => log::warn!(
					target: "runtime::migrations",
					"could not move a stranded EVM tip balance: {e:?}",
				),
			}
		}
		log::info!(
			target: "runtime::migrations",
			"moved {moved} stranded EVM tip balance(s) to their validators",
		);
		// A key-owner read and a balance read per owned key; a transfer reads and
		// writes both accounts.
		db_weight(
			owners
				.saturating_mul(2)
				.saturating_add(moved.saturating_mul(2)),
			moved.saturating_mul(2),
		)
	}

	#[cfg(feature = "try-runtime")]
	fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
		use scale_codec::Encode;
		let issuance = <Balances as Inspect<AccountId>>::total_issuance();
		Ok((Self::moves(), issuance).encode())
	}

	#[cfg(feature = "try-runtime")]
	fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
		use scale_codec::Decode;
		let (moves, issuance) =
			<(alloc::vec::Vec<(AccountId, AccountId, u128)>, u128)>::decode(&mut &state[..])
				.map_err(|_| sp_runtime::TryRuntimeError::Other("undecodable pre-upgrade state"))?;
		frame_support::ensure!(
			<Balances as Inspect<AccountId>>::total_issuance() == issuance,
			"total issuance changed"
		);
		frame_support::ensure!(Self::moves().is_empty(), "a stranded tip balance is left");
		let total: u128 = moves.iter().map(|(_, _, amount)| amount).sum();
		log::info!(
			target: "runtime::migrations",
			"{} stranded tip balance(s) moved, {total} planck",
			moves.len(),
		);
		Ok(())
	}
}
