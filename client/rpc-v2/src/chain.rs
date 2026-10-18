//! Chain RPC — general chain state queries.
//!
//! Endpoints:
//! - `chain_isValidator` — returns `true` if the given SS58 account is an active session validator.

use jsonrpsee::{
	core::RpcResult,
	proc_macros::rpc,
	types::error::{ErrorCode, ErrorObject},
};
use sc_client_api::StorageProvider as ScStorageProvider;
use scale_codec::DecodeAll;
use sp_blockchain::HeaderBackend;
use sp_core::{crypto::Ss58Codec, storage::StorageKey};
use sp_crypto_hashing::twox_128;
use sp_runtime::{traits::Block as BlockT, AccountId32};
use std::{marker::PhantomData, sync::Arc};

// ============================================================================
// Storage key helpers
// ============================================================================

/// `twox_128("Session") ++ twox_128("Validators")` — `StorageValue` key for the
/// current session's validator accounts in `pallet_session`.
fn session_validators_key() -> Vec<u8> {
	[twox_128(b"Session"), twox_128(b"Validators")].concat()
}

/// Whether `account` is in the SCALE-encoded `Session::Validators` value `raw`
/// (`Vec<AccountId32>`, each account its 32 bytes). An absent value means no
/// validators. A value that does not decode exactly is an error, not a miss.
fn contains_validator(raw: Option<&[u8]>, account: &[u8; 32]) -> Result<bool, scale_codec::Error> {
	let Some(mut bytes) = raw else {
		return Ok(false);
	};
	let validators = Vec::<[u8; 32]>::decode_all(&mut bytes)?;
	Ok(validators.contains(account))
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
	/// Returns `true` if the given SS58-encoded account validates the current session.
	///
	/// A validator is its account, not its Aura key: an operator may register its
	/// session keys from that account, so the key need not equal the account.
	/// Reads `pallet_session::Validators` from storage at the best known block.
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

		// Read `Session::Validators` from storage at the best known block.
		let best = self.client.info().best_hash;
		let raw = read_storage(&*self.client, best, session_validators_key())?;

		contains_validator(raw.as_deref(), &target)
			.map_err(|e| internal_error(format!("failed to decode Session::Validators: {e}")))
	}
}

#[cfg(test)]
mod tests {
	use super::{contains_validator, session_validators_key};
	use scale_codec::Encode;
	use sp_crypto_hashing::twox_128;

	const ALICE: [u8; 32] = [1; 32];
	const BOB: [u8; 32] = [2; 32];

	#[test]
	fn session_validators_key_is_32_bytes() {
		assert_eq!(session_validators_key().len(), 32);
	}

	#[test]
	fn session_validators_key_uses_correct_hashes() {
		let key = session_validators_key();
		assert_eq!(&key[..16], &twox_128(b"Session"));
		assert_eq!(&key[16..], &twox_128(b"Validators"));
	}

	#[test]
	fn absent_value_has_no_validators() {
		assert_eq!(contains_validator(None, &ALICE), Ok(false));
	}

	#[test]
	fn empty_set_has_no_validators() {
		let raw = Vec::<[u8; 32]>::new().encode();
		assert_eq!(contains_validator(Some(&raw), &ALICE), Ok(false));
	}

	#[test]
	fn member_is_found() {
		let raw = vec![BOB, ALICE].encode();
		assert_eq!(contains_validator(Some(&raw), &ALICE), Ok(true));
		assert_eq!(contains_validator(Some(&raw), &BOB), Ok(true));
	}

	#[test]
	fn non_member_is_not_found() {
		let raw = vec![BOB].encode();
		assert_eq!(contains_validator(Some(&raw), &ALICE), Ok(false));
	}

	#[test]
	fn truncated_value_is_an_error() {
		let raw = vec![ALICE].encode();
		assert!(contains_validator(Some(&raw[..raw.len() - 1]), &ALICE).is_err());
	}

	#[test]
	fn trailing_bytes_are_an_error() {
		let mut raw = vec![ALICE].encode();
		raw.push(0);
		assert!(contains_validator(Some(&raw), &ALICE).is_err());
	}
}
