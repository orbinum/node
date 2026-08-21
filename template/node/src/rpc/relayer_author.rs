//! `relayer_getRelayInfo` RPC — onboarding helper for the validator operator.
//!
//! Returns the node's Substrate `AccountId`, its EVM relay address, and a
//! signature proving the node holds that address's private key — the three
//! things `relayer.registerRelayer(evmAddress, signature)` needs.
//!
//! The signature is what stops one approved validator from claiming another's
//! public relay address, so it cannot be produced by hand: only the holder of
//! the `evmr` key can sign the binding digest. This RPC exists so the operator
//! does not have to.
//!
//! No extrinsic is submitted; this is a pure read-only query. The signature it
//! returns is only usable to register this node's own address, and becomes
//! public the moment that extrinsic lands, so the method is not gated.

use std::sync::Arc;

use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::{crypto::KeyTypeId, H160, H256};
use sp_keystore::Keystore;
use sp_runtime::traits::Block as BlockT;

use orbinum_runtime::AccountId;

const AURA_KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

/// Imported rather than redeclared: two copies of the key type could drift and
/// the node would sign with a key the RPC never reports.
use crate::evm_relay_key::EVM_RELAY_KEY_TYPE;

// ── RPC trait ────────────────────────────────────────────────────────────────

#[rpc(client, server)]
pub trait RelayerAuthorApi {
	/// Returns everything needed to call `relayer.registerRelayer`.
	///
	/// Requires an Aura session key (for the account) and an `evmr` key (for the
	/// address and the proof) in the local keystore.
	#[method(name = "relayer_getRelayInfo")]
	async fn get_relay_info(&self) -> RpcResult<serde_json::Value>;
}

// ── Handler struct ───────────────────────────────────────────────────────────

pub struct RelayerAuthor<C, B> {
	client: Arc<C>,
	keystore: Arc<dyn Keystore>,
	_block: std::marker::PhantomData<B>,
}

impl<C, B> RelayerAuthor<C, B> {
	pub fn new(client: Arc<C>, keystore: Arc<dyn Keystore>) -> Self {
		Self {
			client,
			keystore,
			_block: std::marker::PhantomData,
		}
	}
}

// ── Implementation ───────────────────────────────────────────────────────────

#[async_trait]
impl<C, B> RelayerAuthorApiServer for RelayerAuthor<C, B>
where
	B: BlockT<Hash = H256>,
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
{
	async fn get_relay_info(&self) -> RpcResult<serde_json::Value> {
		let aura_keys = self.keystore.sr25519_public_keys(AURA_KEY_TYPE);
		let pub_key = aura_keys.first().copied().ok_or_else(|| {
			rpc_err("No Aura key in keystore — is this node configured as a validator?")
		})?;
		let account_id: AccountId = pub_key.0.into();

		let evm_keys = self.keystore.ecdsa_public_keys(EVM_RELAY_KEY_TYPE);
		let evm_pub = evm_keys.first().copied().ok_or_else(|| {
			rpc_err(
				"No \"evmr\" key in keystore — insert one with \
				 author_insertKey(\"evmr\", <phrase>, <pubkey>) and restart",
			)
		})?;
		let evm_addr = evm_address_of(&evm_pub)?;

		let genesis = self
			.client
			.hash(0u32.into())
			.map_err(|e| rpc_err(format!("cannot read genesis hash: {e}")))?
			.ok_or_else(|| rpc_err("genesis block missing"))?;

		let digest = pallet_relayer::evm_proof::binding_digest(
			scale_codec::Encode::encode(&account_id).as_slice(),
			&evm_addr,
			&genesis,
		);
		let signature = self
			.keystore
			.ecdsa_sign_prehashed(EVM_RELAY_KEY_TYPE, &evm_pub, &digest)
			.map_err(|e| rpc_err(format!("signing failed: {e}")))?
			.ok_or_else(|| rpc_err("keystore refused to sign with the \"evmr\" key"))?;

		Ok(serde_json::json!({
			"substrate_account": to_hex(<AccountId as AsRef<[u8; 32]>>::as_ref(&account_id)),
			"evm_address": format!("{evm_addr:#x}"),
			"signature": to_hex(&signature.0),
			"call": "relayer.registerRelayer(evm_address, signature)",
		}))
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Ethereum address for a compressed secp256k1 public key.
///
/// Delegates the actual derivation to `pallet_relayer::evm_proof` so the node and
/// the runtime can never disagree about which address a key owns.
fn evm_address_of(pubkey: &sp_core::ecdsa::Public) -> Result<H160, ErrorObjectOwned> {
	let tagged = libsecp256k1::PublicKey::parse_compressed(&pubkey.0)
		.map_err(|e| rpc_err(format!("malformed evmr public key: {e:?}")))?
		.serialize();
	// serialize() is 65 bytes with a 0x04 tag; the derivation wants the 64 after it.
	let untagged: [u8; 64] = tagged[1..].try_into().expect("65 - 1 == 64; qed");
	Ok(pallet_relayer::evm_proof::evm_address_from_uncompressed(
		&untagged,
	))
}

fn to_hex(bytes: &[u8]) -> String {
	format!("0x{}", hex::encode(bytes))
}

fn rpc_err(msg: impl Into<String>) -> ErrorObjectOwned {
	ErrorObjectOwned::owned(-32000, msg.into(), None::<()>)
}
