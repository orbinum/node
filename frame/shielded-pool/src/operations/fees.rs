//! Relay fees: which relayer a spend credits, and paying fees out.
//!
//! A spend's fee goes to the relayer that recorded a relay commit for it in an
//! earlier block (see `pallet_relayer::relay_commit_hash`), whoever submits the
//! spend; without one it goes to the block author.

use crate::{
	operations::{SpendRequest, assets::AssetOperation},
	origin::RelayCaller,
	pallet::{BalanceOf, Call, Config, Error, Event, Pallet},
	storage::PoolBalanceRepository,
};
use frame_support::{
	ensure,
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use pallet_relayer::RelayerInterface as _;
use pallet_zk_verifier::{TransferStatement, UnshieldStatement};
use parity_scale_codec::Encode;
use sp_runtime::{
	SaturatedConversion,
	traits::{Convert, Zero},
};

const UNSHIELD_OP_DOMAIN: &[u8] = b"orbinum/relay-op/unshield";
const TRANSFER_OP_DOMAIN: &[u8] = b"orbinum/relay-op/transfer";

/// Identify an unshield for relay commits.
///
/// Hashes the statement's public values plus `circuit_version`, and nothing
/// else: not the proof bytes, which anyone can re-randomise without the
/// witness, and not the memo, which a v1 proof does not bind. Any copy that
/// verifies hashes the same under a memo-bound version, which binds the memo
/// and the full recipient, so a copier cannot dodge the original's commit. A v1
/// copy can still alias the recipient (see `pallet_zk_verifier::encoding`).
pub fn unshield_op_hash(s: &UnshieldStatement, circuit_version: u32) -> [u8; 32] {
	sp_io::hashing::blake2_256(
		&(
			UNSHIELD_OP_DOMAIN,
			s.merkle_root,
			s.nullifier,
			s.asset_id,
			s.amount,
			s.recipient,
			s.fee,
			s.change_commitment,
			circuit_version,
		)
			.encode(),
	)
}

/// Identify a private transfer for relay commits. Same scope as
/// [`unshield_op_hash`]: public values and circuit version only.
pub fn transfer_op_hash(s: &TransferStatement, circuit_version: u32) -> [u8; 32] {
	sp_io::hashing::blake2_256(
		&(
			TRANSFER_OP_DOMAIN,
			s.merkle_roots,
			&s.nullifiers,
			&s.commitments,
			s.asset_id,
			s.fee,
			circuit_version,
		)
			.encode(),
	)
}

/// The operation hash of a relayable call, `None` for any other call.
///
/// What a relayer commits to before submitting. It builds the same request the
/// extrinsic executes, so the two cannot disagree on what identifies a spend.
pub fn relay_op_hash<T: Config>(call: &Call<T>) -> Option<[u8; 32]> {
	match SpendRequest::from_call(call)?.1 {
		SpendRequest::Transfer(req) => Some(req.op_hash()),
		SpendRequest::Unshield(req) => req.op_hash().ok(),
	}
}

/// Credit `fee` to the relayer that committed to `op_hash`, else the block
/// author. Both spends route through here so they cannot drift apart.
pub fn credit_relay_fee<T: Config>(
	op_hash: &[u8; 32],
	asset_id: u32,
	fee: u128,
) -> Result<(), Error<T>> {
	let recipient = match T::Relayer::take_committed_relayer(op_hash) {
		Some(relayer) => relayer,
		None => T::Relayer::block_author().ok_or(Error::<T>::FeeRecipientUnavailable)?,
	};
	T::Relayer::accumulate_relay_fee(&recipient, asset_id, fee);
	Ok(())
}

pub struct FeeOperation;

impl FeeOperation {
	/// Record `commits` for the caller's registered relay address.
	pub fn commit<T: Config>(
		caller: RelayCaller<T::AccountId>,
		commits: &[sp_core::H256],
	) -> DispatchResult {
		ensure!(!commits.is_empty(), Error::<T>::EmptyBatch);
		let relayer = match caller {
			RelayCaller::Evm(address) => address,
			RelayCaller::Signed(who) => {
				T::Relayer::registered_evm_address(&who).ok_or(Error::<T>::RelayerNotRegistered)?
			}
		};
		T::Relayer::record_relay_commits(&relayer, commits)
	}

	/// Whose pending fees a claim spends, and where it pays them.
	///
	/// | Caller | Fees spent | Paid to |
	/// |---|---|---|
	/// | `Signed(who)` | `who`'s | the account of `who`'s registered address, else `who` |
	/// | `Evm(addr)` | those of the account registered to `addr` | the account of `addr` |
	pub fn claimant_and_payee<T: Config>(
		caller: RelayCaller<T::AccountId>,
	) -> Result<(T::AccountId, T::AccountId), Error<T>> {
		Ok(match caller {
			RelayCaller::Evm(address) => (
				T::Relayer::resolve_relayer(&address).ok_or(Error::<T>::RelayerNotRegistered)?,
				T::EvmAccount::convert(address),
			),
			RelayCaller::Signed(who) => {
				let to = T::Relayer::registered_evm_address(&who)
					.map_or_else(|| who.clone(), T::EvmAccount::convert);
				(who, to)
			}
		})
	}

	/// Pay `amount` of `claimant`'s pending relay fees out of the pool to `to`.
	///
	/// No proof: the transfer is public and bounded by the claimant's own
	/// pending balance, which `consume_relay_fee` enforces. The fee tokens stayed
	/// in the pool when they were credited, so the ledger drops by `amount` now.
	pub fn claim<T: Config>(
		claimant: T::AccountId,
		to: T::AccountId,
		asset_id: u32,
		amount: BalanceOf<T>,
	) -> DispatchResult {
		// An unverified asset is frozen: no outflow at all, relay fees included.
		AssetOperation::ensure_movable::<T>(asset_id)?;
		ensure!(!amount.is_zero(), Error::<T>::InvalidAmount);
		ensure!(
			PoolBalanceRepository::get_asset_balance::<T>(asset_id) >= amount,
			Error::<T>::InsufficientPoolBalance
		);

		let amount_u128: u128 = amount.saturated_into();
		T::Relayer::consume_relay_fee(&claimant, asset_id, amount_u128)?;
		T::Currency::transfer(
			&Pallet::<T>::pool_account_id(),
			&to,
			amount,
			ExistenceRequirement::AllowDeath,
		)?;
		PoolBalanceRepository::decrease_balance::<T>(asset_id, amount);

		Pallet::<T>::deposit_event(Event::RelayFeesClaimed {
			who: claimant,
			to,
			asset_id,
			amount,
		});
		Ok(())
	}
}
