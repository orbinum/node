//! Derives the EVM relay address from the node's Aura keystore and logs it.
//!
//! When a validator starts with an Aura key in the keystore, this module
//! derives the corresponding EVM address and logs it prominently so that
//! sudo/governance can call `relayer.register_relayer(who, evm_address)`
//! on-chain.
//!
//! The on-chain extrinsic is **not** submitted automatically — it requires
//! `ManageOrigin` (sudo / governance).

use std::sync::Arc;

use sc_client_api::StorageProvider;
use sp_blockchain::HeaderBackend;
use sp_core::{crypto::KeyTypeId, storage::StorageKey, H256};
use sp_keystore::Keystore;
use sp_runtime::{
	codec::Encode,
	traits::{Block as BlockT, Zero},
};

use orbinum_runtime::AccountId;

use crate::client::FullBackend;

/// Aura key type identifier: `KeyTypeId(*b"aura")`.
const AURA_KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

// ---------------------------------------------------------------------------
// Storage check
// ---------------------------------------------------------------------------

/// Builds the full storage key for `pallet-relayer::RelayerByAccount[account_id]`.
///
/// Key layout (Blake2_128Concat map):
///   `Twox128("Relayer") ++ Twox128("RelayerByAccount") ++ Blake2_128(account_id) ++ encode(account_id)`
///
/// Total: 16 + 16 + 16 + 32 = 80 bytes.
pub(crate) fn build_relayer_by_account_key(account_id: &AccountId) -> Vec<u8> {
	let pallet_prefix = sp_io::hashing::twox_128(b"Relayer");
	let item_prefix = sp_io::hashing::twox_128(b"RelayerByAccount");
	let encoded_id = account_id.encode();
	let key_hash = sp_io::hashing::blake2_128(&encoded_id);

	let mut full_key = Vec::with_capacity(32 + encoded_id.len() + 16);
	full_key.extend_from_slice(&pallet_prefix);
	full_key.extend_from_slice(&item_prefix);
	full_key.extend_from_slice(&key_hash);
	full_key.extend_from_slice(&encoded_id);
	full_key
}

/// Returns `true` if `account_id` already has an entry in
/// `pallet-relayer::RelayerByAccount` storage.
fn is_registered<B, C>(client: &C, best_hash: B::Hash, account_id: &AccountId) -> bool
where
	B: BlockT<Hash = H256>,
	C: StorageProvider<B, FullBackend<B>>,
{
	let full_key = build_relayer_by_account_key(account_id);
	client
		.storage(best_hash, &StorageKey(full_key))
		.ok()
		.flatten()
		.is_some()
}

// ---------------------------------------------------------------------------
// Detection task
// ---------------------------------------------------------------------------

/// Waits for at least block #1, then derives the EVM relay address from the
/// node's Aura key and logs it with instructions for sudo registration.
///
/// Idempotent: if the account is already registered on-chain, logs a
/// confirmation and exits without further action.
pub async fn auto_register<B, C>(
	client: Arc<C>,
	keystore: Arc<dyn Keystore>,
	evm_address: sp_core::H160,
) where
	B: BlockT<Hash = H256>,
	C: HeaderBackend<B> + StorageProvider<B, FullBackend<B>> + Send + Sync + 'static,
{
	// Wait until block #1 is imported so state is ready (up to 30 s).
	for _ in 0u32..60 {
		if !client.info().best_number.is_zero() {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(500)).await;
	}

	// Resolve the node identity from the Aura keystore.
	let aura_keys = keystore.sr25519_public_keys(AURA_KEY_TYPE);
	let pub_key = match aura_keys.first() {
		Some(k) => *k,
		None => {
			log::warn!(
				target: "orbinum-relay",
				"auto-register: no Aura key in keystore — cannot derive EVM relay address"
			);
			return;
		}
	};

	let account_id: AccountId = pub_key.0.into();
	let best_hash = client.info().best_hash;

	// If already registered, just confirm and exit.
	if is_registered::<B, C>(&client, best_hash, &account_id) {
		log::info!(
			target: "orbinum-relay",
			"🔑 EVM relay already registered on-chain: EVM={evm_address:?} ↔ substrate={account_id:?}"
		);
		return;
	}

	// Log the address with clear instructions for the operator.
	log::info!(target: "orbinum-relay", "╔══════════════════════════════════════════════════╗");
	log::info!(target: "orbinum-relay", "║   EVM relay key detected — register via sudo     ║");
	log::info!(target: "orbinum-relay", "╠══════════════════════════════════════════════════╣");
	log::info!(target: "orbinum-relay", "║  Substrate : {account_id:?}");
	log::info!(target: "orbinum-relay", "║  EVM addr  : {evm_address:?}");
	log::info!(target: "orbinum-relay", "╠══════════════════════════════════════════════════╣");
	log::info!(target: "orbinum-relay", "║  relayer.registerRelayer(who, evmAddress)        ║");
	log::info!(target: "orbinum-relay", "╚══════════════════════════════════════════════════╝");
}

// ---------------------------------------------------------------------------
// Unit tests — pure key-derivation logic, no runtime required
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use sp_runtime::codec::Encode;

	use super::*;

	/// Build a deterministic test AccountId from a single seed byte.
	fn account(seed: u8) -> AccountId {
		AccountId::from([seed; 32])
	}

	// ── Key length ────────────────────────────────────────────────────────

	/// Blake2_128Concat layout: 16 (pallet) + 16 (item) + 16 (hash) + 32 (encoded) = 80 bytes.
	#[test]
	fn storage_key_has_correct_length() {
		let key = build_relayer_by_account_key(&account(1));
		assert_eq!(key.len(), 80);
	}

	// ── Key structure ─────────────────────────────────────────────────────

	/// Bytes [0..16] must be Twox128("Relayer").
	#[test]
	fn storage_key_pallet_prefix_is_twox128_relayer() {
		let key = build_relayer_by_account_key(&account(1));
		let expected = sp_io::hashing::twox_128(b"Relayer");
		assert_eq!(&key[0..16], &expected);
	}

	/// Bytes [16..32] must be Twox128("RelayerByAccount").
	#[test]
	fn storage_key_item_prefix_is_twox128_relayer_by_account() {
		let key = build_relayer_by_account_key(&account(1));
		let expected = sp_io::hashing::twox_128(b"RelayerByAccount");
		assert_eq!(&key[16..32], &expected);
	}

	/// Bytes [32..48] must be Blake2_128(encoded_account_id).
	#[test]
	fn storage_key_blake2_128_at_offset_32() {
		let acc = account(7);
		let key = build_relayer_by_account_key(&acc);
		let expected_hash = sp_io::hashing::blake2_128(&acc.encode());
		assert_eq!(&key[32..48], &expected_hash);
	}

	/// Bytes [48..80] must be the raw SCALE-encoded AccountId32 (32 bytes).
	#[test]
	fn storage_key_ends_with_raw_encoded_account_id() {
		let acc = account(42);
		let key = build_relayer_by_account_key(&acc);
		assert_eq!(&key[48..80], acc.encode().as_slice());
	}

	// ── Cross-account uniqueness ──────────────────────────────────────────

	/// Two different accounts must produce different storage keys.
	#[test]
	fn different_accounts_produce_different_keys() {
		let k1 = build_relayer_by_account_key(&account(1));
		let k2 = build_relayer_by_account_key(&account(2));
		assert_ne!(k1, k2);
	}

	/// The same account must always produce the same key (determinism).
	#[test]
	fn same_account_is_deterministic() {
		let k1 = build_relayer_by_account_key(&account(99));
		let k2 = build_relayer_by_account_key(&account(99));
		assert_eq!(k1, k2);
	}

	/// Zero-seed and max-seed accounts must both be handled without collision.
	#[test]
	fn zero_and_max_seed_produce_different_keys() {
		let k_zero = build_relayer_by_account_key(&account(0x00));
		let k_max = build_relayer_by_account_key(&account(0xff));
		assert_ne!(k_zero, k_max);
	}
}
