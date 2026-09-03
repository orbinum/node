//! Chain RPC — general chain state queries.
//!
//! Endpoints:
//! - `chain_isValidator` — returns `true` if the given SS58 account is an active Aura validator.

use jsonrpsee::{
	core::RpcResult,
	proc_macros::rpc,
	types::error::{ErrorCode, ErrorObject},
};
use sc_client_api::StorageProvider as ScStorageProvider;
use scale_codec::Decode;
use sp_blockchain::HeaderBackend;
use sp_core::{crypto::Ss58Codec, storage::StorageKey};
use sp_crypto_hashing::twox_128;
use sp_runtime::{traits::Block as BlockT, AccountId32};
use std::{marker::PhantomData, sync::Arc};

// ============================================================================
// Storage key helpers
// ============================================================================

/// `twox_128("Aura") ++ twox_128("Authorities")` — `StorageValue` key for `pallet_aura`.
fn aura_authorities_key() -> Vec<u8> {
	[twox_128(b"Aura"), twox_128(b"Authorities")].concat()
}

fn read_storage<B: BlockT, C: ScStorageProvider<B, BE>, BE: sc_client_api::Backend<B>>(
	client: &C,
	hash: B::Hash,
	key: Vec<u8>,
) -> RpcResult<Option<Vec<u8>>> {
	ScStorageProvider::storage(client, hash, &StorageKey(key))
		.map_err(internal_error)
		.map(|opt| opt.map(|data| data.0))
}

// ============================================================================
// RPC trait
// ============================================================================

#[rpc(server)]
pub trait ChainApi {
	/// Returns `true` if the given SS58-encoded account is an active Aura validator.
	///
	/// Reads `pallet_aura::Authorities` directly from storage at the best known block.
	/// No runtime API call is performed.
	#[method(name = "chain_isValidator")]
	fn is_validator(&self, account: String) -> RpcResult<bool>;
}

// ============================================================================
// RPC server struct
// ============================================================================

/// Chain RPC server for general Orbinum chain state queries.
pub struct ChainRpc<C, B, BE> {
	client: Arc<C>,
	_ph: PhantomData<(B, BE)>,
}

impl<C, B, BE> ChainRpc<C, B, BE> {
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			_ph: PhantomData,
		}
	}
}

// ============================================================================
// Error helpers
// ============================================================================

fn internal_error(msg: impl std::fmt::Display) -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InternalError.code(),
		format!("Internal error: {msg}"),
		None::<()>,
	)
}

fn invalid_params(msg: impl std::fmt::Display) -> ErrorObject<'static> {
	ErrorObject::owned(
		ErrorCode::InvalidParams.code(),
		format!("Invalid params: {msg}"),
		None::<()>,
	)
}

// ============================================================================
// Implementation
// ============================================================================

impl<C, B, BE> ChainApiServer for ChainRpc<C, B, BE>
where
	C: HeaderBackend<B> + ScStorageProvider<B, BE> + Send + Sync + 'static,
	B: BlockT,
	BE: sc_client_api::Backend<B> + Send + Sync + 'static,
{
	fn is_validator(&self, account: String) -> RpcResult<bool> {
		// Parse SS58 address → 32-byte AccountId32.
		let account_id = AccountId32::from_ss58check(&account)
			.map_err(|e| invalid_params(format!("invalid SS58 address: {e:?}")))?;
		let target: [u8; 32] = *account_id.as_ref();

		// Read `Aura::Authorities` from storage at the best known block.
		let best = self.client.info().best_hash;
		let raw = read_storage(&*self.client, best, aura_authorities_key())?;

		let Some(bytes) = raw else {
			// Storage item absent → chain has no configured validators.
			return Ok(false);
		};

		// SCALE-decode as `Vec<[u8; 32]>`.
		// `AuraId = sr25519::Public`, which serialises as a plain 32-byte array.
		let authorities = Vec::<[u8; 32]>::decode(&mut bytes.as_slice())
			.map_err(|e| internal_error(format!("failed to decode Aura::Authorities: {e}")))?;

		Ok(authorities.iter().any(|auth| auth == &target))
	}
}

#[cfg(test)]
mod tests {
	use super::aura_authorities_key;
	use sp_crypto_hashing::twox_128;

	#[test]
	fn aura_authorities_key_is_32_bytes() {
		assert_eq!(aura_authorities_key().len(), 32);
	}

	#[test]
	fn aura_authorities_key_uses_correct_hashes() {
		let key = aura_authorities_key();
		assert_eq!(&key[..16], &twox_128(b"Aura"));
		assert_eq!(&key[16..], &twox_128(b"Authorities"));
	}
}
