use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use pallet_relayer_runtime_api::RelayerRuntimeApi;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::crypto::Ss58Codec;
use sp_runtime::{AccountId32, traits::Block as BlockT};
use std::sync::Arc;

#[rpc(client, server)]
pub trait RelayerApi<BlockHash> {
	/// Returns true if the given SS58 address is a registered relayer.
	#[method(name = "relayer_isRelayer")]
	fn is_relayer(&self, account: String) -> RpcResult<bool>;

	/// Returns the pending fees (as decimal string) for the given account and asset.
	#[method(name = "relayer_pendingFees")]
	fn pending_fees(&self, account: String, asset_id: u32) -> RpcResult<String>;

	/// Returns the registered EVM address (0x-prefixed hex) for the relayer, if any.
	#[method(name = "relayer_registeredEvmAddress")]
	fn registered_evm_address(&self, account: String) -> RpcResult<Option<String>>;
}

pub struct Relayer<C, B> {
	client: Arc<C>,
	_marker: std::marker::PhantomData<B>,
}

impl<C, B> Relayer<C, B> {
	pub fn new(client: Arc<C>) -> Self {
		Self {
			client,
			_marker: Default::default(),
		}
	}
}

fn parse_account(s: &str) -> Result<AccountId32, ErrorObjectOwned> {
	AccountId32::from_ss58check(s)
		.map_err(|e| ErrorObjectOwned::owned(1, format!("Invalid SS58 address: {e}"), None::<()>))
}

impl<C, B> RelayerApiServer<B::Hash> for Relayer<C, B>
where
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + 'static,
	C::Api: RelayerRuntimeApi<B>,
	B: BlockT,
{
	fn is_relayer(&self, account: String) -> RpcResult<bool> {
		let account_id = parse_account(&account)?;
		let api = self.client.runtime_api();
		let best = self.client.info().best_hash;
		api.is_relayer(best, account_id)
			.map_err(|e| ErrorObjectOwned::owned(1, format!("Runtime error: {e}"), None::<()>))
	}

	fn pending_fees(&self, account: String, asset_id: u32) -> RpcResult<String> {
		let account_id = parse_account(&account)?;
		let api = self.client.runtime_api();
		let best = self.client.info().best_hash;
		let amount = api
			.pending_fees(best, account_id, asset_id)
			.map_err(|e| ErrorObjectOwned::owned(1, format!("Runtime error: {e}"), None::<()>))?;
		Ok(amount.to_string())
	}

	fn registered_evm_address(&self, account: String) -> RpcResult<Option<String>> {
		let account_id = parse_account(&account)?;
		let api = self.client.runtime_api();
		let best = self.client.info().best_hash;
		let maybe_addr = api
			.registered_evm_address(best, account_id)
			.map_err(|e| ErrorObjectOwned::owned(1, format!("Runtime error: {e}"), None::<()>))?;
		Ok(maybe_addr.map(|bytes| format!("0x{}", hex::encode(bytes))))
	}
}

#[cfg(test)]
mod tests {
	use super::parse_account;

	// Alice's well-known SS58 address on network 42 (Substrate default).
	const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

	// ── parse_account ────────────────────────────────────────────────────────

	#[test]
	fn parse_account_accepts_valid_ss58() {
		assert!(parse_account(ALICE_SS58).is_ok());
	}

	#[test]
	fn parse_account_rejects_invalid_string() {
		assert!(parse_account("not-a-valid-ss58").is_err());
	}

	#[test]
	fn parse_account_rejects_empty_string() {
		assert!(parse_account("").is_err());
	}

	#[test]
	fn parse_account_error_code_is_1() {
		let err = parse_account("bad-input").unwrap_err();
		assert_eq!(err.code(), 1);
	}

	#[test]
	fn parse_account_roundtrip_matches_known_bytes() {
		use sp_core::crypto::Ss58Codec;
		use sp_runtime::AccountId32;

		// Parse Alice's address and re-encode to verify round-trip consistency.
		let account = parse_account(ALICE_SS58).unwrap();
		let re_encoded = AccountId32::to_ss58check(&account);
		assert_eq!(re_encoded, ALICE_SS58);
	}

	// ── registered_evm_address formatting ───────────────────────────────────

	#[test]
	fn evm_address_formats_as_0x_lowercase_hex() {
		let bytes: [u8; 20] = [
			0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9,
			0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58,
		];
		let formatted = format!("0x{}", hex::encode(bytes));
		assert_eq!(formatted, "0xd43593c715fdd31c61141abd04a99fd6822c8558");
	}

	#[test]
	fn evm_address_all_zeros_formats_correctly() {
		let bytes = [0u8; 20];
		let formatted = format!("0x{}", hex::encode(bytes));
		assert_eq!(formatted, "0x0000000000000000000000000000000000000000");
	}

	#[test]
	fn evm_address_all_ff_formats_correctly() {
		let bytes = [0xffu8; 20];
		let formatted = format!("0x{}", hex::encode(bytes));
		assert_eq!(formatted, "0xffffffffffffffffffffffffffffffffffffffff");
	}

	// ── pending_fees serialization ───────────────────────────────────────────

	#[test]
	fn pending_fees_zero_formats_as_string() {
		assert_eq!((0u128).to_string(), "0");
	}

	#[test]
	fn pending_fees_one_orb_formats_correctly() {
		// 1 ORB = 10^18 planck.
		let one_orb: u128 = 1_000_000_000_000_000_000;
		assert_eq!(one_orb.to_string(), "1000000000000000000");
	}

	#[test]
	fn pending_fees_u128_max_does_not_overflow() {
		let s = u128::MAX.to_string();
		assert_eq!(s, "340282366920938463463374607431768211455");
	}
}
