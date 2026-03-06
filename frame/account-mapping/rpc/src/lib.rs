use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use pallet_account_mapping_runtime_api::{AccountMappingRuntimeApi, AliasInfo, ListingInfo};
use serde::{Deserialize, Serialize};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::{crypto::AccountId32, H160};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

pub mod error;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountAddresses {
	pub mapped: Option<String>,
	pub fallback: Option<String>,
}

/// Alias resolution response returned to the frontend.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AliasResponse {
	/// Alias string (without @).
	pub alias: String,
	/// Substrate AccountId32 (hex).
	pub substrate_account: String,
	/// EVM H160 address (hex).
	pub evm_address: Option<String>,
	/// How many external chain links are registered.
	pub chain_links_count: u32,
}

/// Marketplace listing info returned to the frontend.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListingResponse {
	/// Alias string (without @).
	pub alias: String,
	/// Asking price as a string (u128 as string to avoid JS overflow).
	pub price: String,
	/// True if a whitelist is set (private/OTC sale).
	pub private: bool,
	/// Number of accounts in the whitelist (0 if public).
	pub whitelist_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainLinkResponse {
	pub chain_id: u32,
	pub address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountMetadataResponse {
	pub display_name: Option<String>,
	pub bio: Option<String>,
	pub avatar: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FullIdentityResponse {
	pub owner: String,
	pub evm_address: Option<String>,
	pub chain_links: Vec<ChainLinkResponse>,
	pub metadata: Option<AccountMetadataResponse>,
}

/// A private chain link commitment returned to the frontend.
/// Real address is never included.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrivateLinkResponse {
	/// Chain ID this private link belongs to.
	pub chain_id: u32,
	/// Keccak256 commitment (hex-encoded, 0x-prefixed).
	pub commitment: String,
}

#[rpc(client, server)]
pub trait AccountMappingApi<BlockHash> {
	#[method(name = "accountMapping_getMappedAccount")]
	fn get_mapped_account(&self, address: String) -> RpcResult<Option<String>>;

	#[method(name = "accountMapping_getAccountAddresses")]
	fn get_account_addresses(&self, account_id: String) -> RpcResult<AccountAddresses>;

	/// Resolve "@alias" → identity info.
	/// Accepts the alias with or without the "@" prefix.
	#[method(name = "accountMapping_resolveAlias")]
	fn resolve_alias(&self, alias: String) -> RpcResult<Option<AliasResponse>>;

	/// Return the alias registered for a given SS58 / hex AccountId.
	#[method(name = "accountMapping_getAliasOf")]
	fn get_alias_of(&self, account_id: String) -> RpcResult<Option<String>>;

	// ── Marketplace queries ────────────────────────────────────────────────

	/// Get listing info for a given alias.
	/// Returns null if the alias is not listed for sale.
	#[method(name = "accountMapping_getListingInfo")]
	fn get_listing_info(&self, alias: String) -> RpcResult<Option<ListingResponse>>;

	/// Get the active listing for the account that owns the alias, if any.
	/// Useful to show "Alias for sale" on the address detail page.
	#[method(name = "accountMapping_getAccountListing")]
	fn get_account_listing(&self, account_id: String) -> RpcResult<Option<ListingResponse>>;

	/// Check whether a specific buyer can purchase the given alias right now.
	/// Returns false if not for sale, buyer already has alias, or buyer not in whitelist.
	#[method(name = "accountMapping_canBuy")]
	fn can_buy(&self, alias: String, buyer_account_id: String) -> RpcResult<bool>;

	/// Resolve "@alias" → Full identity (links, metadata, addresses).
	#[method(name = "accountMapping_resolveFullIdentity")]
	fn resolve_full_identity(&self, alias: String) -> RpcResult<Option<FullIdentityResponse>>;

	/// Get metadata (profile) for a specific account.
	#[method(name = "accountMapping_getAccountMetadata")]
	fn get_account_metadata(
		&self,
		account_id: String,
	) -> RpcResult<Option<AccountMetadataResponse>>;

	/// Get the owner AccountId of a verified multichain link.
	#[method(name = "accountMapping_getLinkOwner")]
	fn get_link_owner(&self, chain_id: u32, address: String) -> RpcResult<Option<String>>;

	/// Get all supported blockchains and their signature schemes.
	#[method(name = "accountMapping_getSupportedChains")]
	fn get_supported_chains(
		&self,
	) -> RpcResult<Vec<(u32, pallet_account_mapping_runtime_api::SignatureScheme)>>;

	// ── Private link queries ────────────────────────────────────────────────

	/// Return the private link commitments registered for an alias.
	/// Real addresses are never exposed. Returns null if alias does not exist.
	#[method(name = "accountMapping_getPrivateLinks")]
	fn get_private_links(&self, alias: String) -> RpcResult<Option<Vec<PrivateLinkResponse>>>;

	/// Check whether a specific commitment exists as a private link for the alias.
	#[method(name = "accountMapping_hasPrivateLink")]
	fn has_private_link(&self, alias: String, commitment: String) -> RpcResult<bool>;
}

pub struct AccountMapping<C, B> {
	client: Arc<C>,
	_marker: std::marker::PhantomData<B>,
}

impl<C, B> AccountMapping<C, B> {
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			_marker: Default::default(),
		}
	}
}

fn parse_h160(hex_address: &str) -> Result<H160, ErrorObjectOwned> {
	let bytes = hex::decode(hex_address.trim_start_matches("0x")).map_err(error::invalid_h160)?;
	if bytes.len() != 20 {
		return Err(error::invalid_h160("address must be exactly 20 bytes"));
	}
	Ok(H160::from_slice(&bytes))
}

fn parse_account_id32(hex_account: &str) -> Result<AccountId32, ErrorObjectOwned> {
	let bytes =
		hex::decode(hex_account.trim_start_matches("0x")).map_err(error::invalid_account_id)?;
	if bytes.len() != 32 {
		return Err(error::invalid_account_id(
			"AccountId must be exactly 32 bytes",
		));
	}
	AccountId32::try_from(bytes.as_slice())
		.map_err(|_| error::invalid_account_id("failed to parse AccountId32"))
}

fn alias_info_to_response(alias: String, info: AliasInfo<AccountId32>) -> AliasResponse {
	let owner_bytes: &[u8; 32] = info.owner.as_ref();
	let owner_hex = format!("0x{}", hex::encode(owner_bytes));
	let evm_hex = info
		.evm_address
		.map(|a| format!("0x{}", hex::encode(a.as_bytes())));
	AliasResponse {
		alias,
		substrate_account: owner_hex,
		evm_address: evm_hex,
		chain_links_count: info.chain_links_count,
	}
}

fn listing_info_to_response<Balance: ToString>(
	alias: String,
	info: ListingInfo<Balance>,
) -> ListingResponse {
	ListingResponse {
		alias,
		price: info.price.to_string(),
		private: info.private,
		whitelist_count: info.whitelist_count,
	}
}

impl<C, B> AccountMappingApiServer<B::Hash> for AccountMapping<C, B>
where
	B: BlockT,
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + 'static,
	C::Api: AccountMappingRuntimeApi<B, AccountId32, u128>,
{
	fn get_mapped_account(&self, address: String) -> RpcResult<Option<String>> {
		let parsed = parse_h160(&address)?;

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let account = api
			.get_mapped_account(best_block, parsed)
			.map_err(|e| error::runtime_error(e))?;

		Ok(account.map(|a| {
			let bytes: &[u8; 32] = a.as_ref();
			format!("0x{}", hex::encode(bytes))
		}))
	}

	fn get_account_addresses(&self, account_id: String) -> RpcResult<AccountAddresses> {
		let account = parse_account_id32(&account_id)?;

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let mapped = api
			.get_mapped_address(best_block, account.clone())
			.map_err(|e| error::runtime_error(e))?
			.map(|h| format!("0x{}", hex::encode(h.as_bytes())));

		let fallback = api
			.get_fallback_address(best_block, account)
			.map_err(|e| error::runtime_error(e))?
			.map(|h| format!("0x{}", hex::encode(h.as_bytes())));

		Ok(AccountAddresses { mapped, fallback })
	}

	fn resolve_alias(&self, alias: String) -> RpcResult<Option<AliasResponse>> {
		// Strip leading "@" if present.
		let clean = alias.trim_start_matches('@');
		let alias_bytes = clean.as_bytes().to_vec();

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let info = api
			.resolve_alias(best_block, alias_bytes)
			.map_err(|e| error::runtime_error(e))?;

		Ok(info.map(|i| alias_info_to_response(clean.to_string(), i)))
	}

	fn get_alias_of(&self, account_id: String) -> RpcResult<Option<String>> {
		let account = parse_account_id32(&account_id)?;

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let alias_bytes = api
			.get_alias_of(best_block, account)
			.map_err(|e| error::runtime_error(e))?;

		Ok(alias_bytes.and_then(|b| String::from_utf8(b).ok()))
	}

	fn get_listing_info(&self, alias: String) -> RpcResult<Option<ListingResponse>> {
		let clean = alias.trim_start_matches('@');
		let alias_bytes = clean.as_bytes().to_vec();

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let info = api
			.get_listing_info(best_block, alias_bytes)
			.map_err(|e| error::runtime_error(e))?;

		Ok(info.map(|i| listing_info_to_response(clean.to_string(), i)))
	}

	fn get_account_listing(&self, account_id: String) -> RpcResult<Option<ListingResponse>> {
		let account = parse_account_id32(&account_id)?;

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let result = api
			.get_account_listing(best_block, account)
			.map_err(|e| error::runtime_error(e))?;

		Ok(result.and_then(|(alias_bytes, info)| {
			let alias = String::from_utf8(alias_bytes).ok()?;
			Some(listing_info_to_response(alias, info))
		}))
	}

	fn can_buy(&self, alias: String, buyer_account_id: String) -> RpcResult<bool> {
		let clean = alias.trim_start_matches('@');
		let alias_bytes = clean.as_bytes().to_vec();
		let buyer = parse_account_id32(&buyer_account_id)?;

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let ok = api
			.can_buy(best_block, alias_bytes, buyer)
			.map_err(|e| error::runtime_error(e))?;

		Ok(ok)
	}

	fn resolve_full_identity(&self, alias: String) -> RpcResult<Option<FullIdentityResponse>> {
		let clean = alias.trim_start_matches('@');
		let alias_bytes = clean.as_bytes().to_vec();

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let info = api
			.get_full_identity(best_block, alias_bytes)
			.map_err(|e| error::runtime_error(e))?;

		Ok(info.map(|i| {
			let owner_bytes: &[u8; 32] = i.owner.as_ref();
			FullIdentityResponse {
				owner: format!("0x{}", hex::encode(owner_bytes)),
				evm_address: i
					.evm_address
					.map(|a| format!("0x{}", hex::encode(a.as_bytes()))),
				chain_links: i
					.chain_links
					.into_iter()
					.map(|l| ChainLinkResponse {
						chain_id: l.chain_id,
						address: format!("0x{}", hex::encode(&l.address)),
					})
					.collect(),
				metadata: i.metadata.map(|m| AccountMetadataResponse {
					display_name: m.display_name.and_then(|v| String::from_utf8(v).ok()),
					bio: m.bio.and_then(|v| String::from_utf8(v).ok()),
					avatar: m.avatar.and_then(|v| String::from_utf8(v).ok()),
				}),
			}
		}))
	}

	fn get_account_metadata(
		&self,
		account_id: String,
	) -> RpcResult<Option<AccountMetadataResponse>> {
		let account = parse_account_id32(&account_id)?;

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let metadata = api
			.get_account_metadata(best_block, account)
			.map_err(|e| error::runtime_error(e))?;

		Ok(metadata.map(|m| AccountMetadataResponse {
			display_name: m.display_name.and_then(|v| String::from_utf8(v).ok()),
			bio: m.bio.and_then(|v| String::from_utf8(v).ok()),
			avatar: m.avatar.and_then(|v| String::from_utf8(v).ok()),
		}))
	}

	fn get_link_owner(&self, chain_id: u32, address: String) -> RpcResult<Option<String>> {
		let parsed_address = if let Some(stripped) = address.strip_prefix("0x") {
			hex::decode(stripped).map_err(error::invalid_chain_address)?
		} else {
			address.as_bytes().to_vec()
		};

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let owner = api
			.get_link_owner(best_block, chain_id, parsed_address)
			.map_err(|e| error::runtime_error(e))?;

		Ok(owner.map(|a| {
			let bytes: &[u8; 32] = a.as_ref();
			format!("0x{}", hex::encode(bytes))
		}))
	}

	fn get_supported_chains(
		&self,
	) -> RpcResult<Vec<(u32, pallet_account_mapping_runtime_api::SignatureScheme)>> {
		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		api.get_supported_chains(best_block)
			.map_err(|e| error::runtime_error(e))
	}

	fn get_private_links(&self, alias: String) -> RpcResult<Option<Vec<PrivateLinkResponse>>> {
		let clean = alias.trim_start_matches('@');
		let alias_bytes = clean.as_bytes().to_vec();

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		let links = api
			.get_private_links(best_block, alias_bytes)
			.map_err(|e| error::runtime_error(e))?;

		Ok(links.map(|list| {
			list.into_iter()
				.map(|l| PrivateLinkResponse {
					chain_id: l.chain_id,
					commitment: format!("0x{}", hex::encode(l.commitment)),
				})
				.collect()
		}))
	}

	fn has_private_link(&self, alias: String, commitment: String) -> RpcResult<bool> {
		let clean = alias.trim_start_matches('@');
		let alias_bytes = clean.as_bytes().to_vec();

		// Parsear el commitment hex a [u8; 32].
		let bytes = hex::decode(commitment.trim_start_matches("0x"))
			.map_err(|e| error::invalid_chain_address(format!("invalid commitment hex: {e}")))?;
		if bytes.len() != 32 {
			return Err(error::invalid_chain_address(
				"commitment must be exactly 32 bytes",
			));
		}
		let mut commitment_arr = [0u8; 32];
		commitment_arr.copy_from_slice(&bytes);

		let api = self.client.runtime_api();
		let best_block = self.client.info().best_hash;

		api.has_private_link(best_block, alias_bytes, commitment_arr)
			.map_err(|e| error::runtime_error(e))
	}
}

#[cfg(test)]
mod tests {
	use super::{parse_account_id32, parse_h160};

	#[test]
	fn parse_h160_accepts_valid_hex() {
		let parsed = parse_h160("0x1111111111111111111111111111111111111111").unwrap();
		assert_eq!(
			format!("0x{}", hex::encode(parsed.as_bytes())),
			"0x1111111111111111111111111111111111111111"
		);
	}

	#[test]
	fn parse_h160_rejects_wrong_length() {
		let result = parse_h160("0x1111");
		assert!(result.is_err());
	}

	#[test]
	fn parse_account_id32_accepts_valid_hex() {
		let parsed = parse_account_id32(
			"0x0101010101010101010101010101010101010101010101010101010101010101",
		)
		.unwrap();
		let bytes: &[u8; 32] = parsed.as_ref();
		assert_eq!(bytes[0], 0x01);
		assert_eq!(bytes[31], 0x01);
	}

	#[test]
	fn parse_account_id32_rejects_wrong_length() {
		let result = parse_account_id32("0x0101");
		assert!(result.is_err());
	}

	#[test]
	fn resolve_alias_strips_at_prefix() {
		let alias = "@nolasco";
		let clean = alias.trim_start_matches('@');
		assert_eq!(clean, "nolasco");
	}
}
