//! `eth_call` / `eth_estimateGas` state-override support for Orbinum's account model.
//!
//! Frontier ships two overrides, one per address model it supports: an
//! `AccountId20` runtime (`IdentityAddressMapping`) and an `AccountId32` runtime
//! using `HashedAddressMapping`. Orbinum is neither — it keeps `AccountId32` but
//! maps addresses with `EeSuffixAddressMapping` (`[H160 | 0x00 × 12]`), so both
//! stock overrides build a `System::Account` key that does not exist and the
//! caller's `state_overrides` are silently dropped.
//!
//! This override derives the key the way the runtime does. It must stay in step
//! with `EeSuffixAddressMapping`: a mismatch here does not fail loudly, it just
//! makes simulated balances and nonces disappear.

use std::marker::PhantomData;

use sc_client_api::{backend::Backend, StorageProvider};
use scale_codec::Encode;
use sp_core::{H160, U256};
use sp_io::hashing::{blake2_128, twox_128};
use sp_runtime::traits::{Block as BlockT, HashingFor};
use sp_state_machine::OverlayedChanges;
use sp_storage::StorageKey;

/// `[H160 | 0x00 × 12]` — the layout `EeSuffixAddressMapping` gives an EVM
/// address in the runtime.
fn account_id_bytes(address: H160) -> Vec<u8> {
	let mut bytes = [0u8; 32];
	bytes[..20].copy_from_slice(address.as_bytes());
	bytes.to_vec()
}

/// Writes `System::Account` overrides for an `AccountId32` runtime that maps EVM
/// addresses as `[H160 | 0x00 × 12]`.
///
/// Assumes the account layout `pallet_balances` gives `System::Account`:
/// `nonce: u32` at bytes 0..4 and `free: u128` at bytes 16..32.
pub struct EeSuffixStorageOverride<B, C, BE>(PhantomData<(B, C, BE)>);

impl<B, C, BE> fp_rpc::RuntimeStorageOverride<B, C> for EeSuffixStorageOverride<B, C, BE>
where
	B: BlockT,
	C: StorageProvider<B, BE> + Send + Sync,
	BE: Backend<B>,
{
	fn is_enabled() -> bool {
		true
	}

	fn set_overlayed_changes(
		client: &C,
		overlayed_changes: &mut OverlayedChanges<HashingFor<B>>,
		block: B::Hash,
		_version: u32,
		address: H160,
		balance: Option<U256>,
		nonce: Option<U256>,
	) {
		let mut key = [twox_128(b"System"), twox_128(b"Account")]
			.concat()
			.to_vec();
		let account_id = Self::into_account_id_bytes(address);
		key.extend(blake2_128(&account_id));
		key.extend(&account_id);

		// No entry means the account has never been touched on chain; there is
		// nothing to splice the override into.
		if let Ok(Some(item)) = client.storage(block, &StorageKey(key.clone())) {
			let mut new_item = item.0;

			if let Some(nonce) = nonce {
				new_item.splice(0..4, nonce.low_u32().encode());
			}

			if let Some(balance) = balance {
				new_item.splice(16..32, balance.low_u128().encode());
			}

			overlayed_changes.set_storage(key, Some(new_item));
		}
	}

	fn into_account_id_bytes(address: H160) -> Vec<u8> {
		account_id_bytes(address)
	}
}

#[cfg(test)]
mod tests {
	use orbinum_runtime::evm_h160_to_account_id;

	use super::*;

	/// The whole point of this file: the RPC-side derivation and the runtime's
	/// `EeSuffixAddressMapping` must agree, or state overrides build a
	/// `System::Account` key that does not exist and are dropped without an error.
	#[test]
	fn matches_the_runtime_address_mapping() {
		for byte in [0x00u8, 0x01, 0x42, 0xAB, 0xFF] {
			let address = H160::repeat_byte(byte);
			let expected = evm_h160_to_account_id(address);
			assert_eq!(
				account_id_bytes(address),
				AsRef::<[u8]>::as_ref(&expected).to_vec(),
				"RPC override and runtime mapping disagree for {address:?}"
			);
		}
	}

	#[test]
	fn layout_is_address_then_twelve_zeros() {
		let address = H160::repeat_byte(0xAB);
		let bytes = account_id_bytes(address);

		assert_eq!(bytes.len(), 32);
		assert_eq!(&bytes[..20], address.as_bytes());
		assert_eq!(&bytes[20..], &[0u8; 12]);
	}
}
