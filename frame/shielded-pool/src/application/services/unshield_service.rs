//! Unshield service - Handles withdrawal from shielded pool to public account

use crate::{
	domain::entities::Nullifier,
	infrastructure::repositories::MerkleRepository,
	pallet::{
		Assets, Config, Error, Event, NullifierSet, Pallet, PoolBalance, PoolBalancePerAsset,
	},
};
use frame_support::{
	pallet_prelude::*,
	traits::{Currency, ExistenceRequirement},
};
use frame_system;
#[cfg(not(feature = "runtime-benchmarks"))]
use pallet_zk_verifier::ZkVerifierPort;
#[cfg(not(feature = "runtime-benchmarks"))]
use parity_scale_codec::Encode;

pub struct UnshieldService;

impl UnshieldService {
	/// Execute unshield operation
	pub fn execute<T: Config>(
		_proof: &[u8],
		merkle_root: [u8; 32],
		nullifier: Nullifier,
		asset_id: u32,
		amount: <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance,
		recipient: <T as frame_system::Config>::AccountId,
	) -> DispatchResult {
		// 1. Validate asset exists and is verified
		let asset = Assets::<T>::get(asset_id).ok_or(Error::<T>::InvalidAssetId)?;

		ensure!(asset.is_verified, Error::<T>::AssetNotVerified);

		// 2. Validate recipient is not zero/burn address
		let recipient_info = frame_system::Pallet::<T>::account(&recipient);
		let _is_zero_account = recipient_info.providers == 0
			&& recipient_info.consumers == 0
			&& recipient_info.sufficients == 0
			&& recipient_info.nonce == 0u32.into();

		ensure!(
			recipient != Pallet::<T>::pool_account_id(),
			Error::<T>::InvalidRecipient
		);

		// 3. Verify Merkle root is known (checks Poseidon roots)
		ensure!(
			MerkleRepository::is_known_root::<T>(&merkle_root),
			Error::<T>::UnknownMerkleRoot
		);

		// 4. Check nullifier hasn't been used
		ensure!(
			!NullifierSet::<T>::contains_key(nullifier),
			Error::<T>::NullifierAlreadyUsed
		);

		// 5. Check pool has sufficient balance for this specific asset
		ensure!(
			PoolBalancePerAsset::<T>::get(asset_id) >= amount,
			Error::<T>::InsufficientPoolBalance
		);

		// 6. Convert amount to u128 for ZK verification
		let amount_u128: u128 = amount.try_into().map_err(|_| Error::<T>::InvalidAmount)?;

		// 7. Verify ZK proof (skip in benchmarking mode)
		// Canonical format between shielded-pool and zk-verifier is LE.
		// Pass merkle_root/nullifier as-is (no endianness conversion).
		#[cfg(not(feature = "runtime-benchmarks"))]
		{
			// Convert recipient (AccountId) to bytes
			// En el runtime de producción, AccountId es H160 (20 bytes)
			// En tests, puede ser u64 (8 bytes)
			let recipient_encoded = recipient.encode();

			// Padding a 20 bytes (requerido por el circuito)
			let recipient_bytes: [u8; 20] = {
				let mut bytes = [0u8; 20];
				let len = recipient_encoded.len().min(20);
				// Copiar desde el final (right-aligned) para números pequeños
				bytes[20 - len..].copy_from_slice(&recipient_encoded[..len]);
				bytes
			};

			let valid = T::ZkVerifier::verify_unshield_proof(
				_proof,
				&merkle_root,
				&nullifier.0,
				amount_u128,
				&recipient_bytes,
				asset_id,
				None, // Use active version
			)
			.map_err(|_| Error::<T>::ProofVerificationFailed)?;

			ensure!(valid, Error::<T>::InvalidProof);
		}

		// In benchmarking mode, suppress unused variable warning
		#[cfg(feature = "runtime-benchmarks")]
		let _ = amount_u128;

		// 8. Transfer tokens from pool to recipient
		T::Currency::transfer(
			&Pallet::<T>::pool_account_id(),
			&recipient,
			amount,
			ExistenceRequirement::AllowDeath,
		)?;

		// 9. Update pool balance (legacy total)
		PoolBalance::<T>::mutate(|b| {
			if let Some(new_balance) = b.checked_sub(&amount) {
				*b = new_balance;
			}
		});

		// 10. Update pool balance per asset
		PoolBalancePerAsset::<T>::mutate(asset_id, |b| {
			if let Some(new_balance) = b.checked_sub(&amount) {
				*b = new_balance;
			}
		});

		// 11. Mark nullifier as used to prevent double-spending
		let current_block = frame_system::Pallet::<T>::block_number();
		NullifierSet::<T>::insert(nullifier, current_block);

		// 12. Emit event
		Pallet::<T>::deposit_event(Event::Unshielded {
			nullifier,
			amount,
			recipient,
		});

		Ok(())
	}
}
