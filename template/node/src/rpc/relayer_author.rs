//! `relayer_getRelayInfo` RPC — informational query for the validator operator.
//!
//! Returns the node's Substrate `AccountId` and derived EVM address so that
//! a **sudo/governance** account knows what arguments to pass to
//! `relayer.register_relayer(who, evm_address)` on-chain.
//!
//! No extrinsic is submitted; this is a pure read-only query.

use std::sync::Arc;

use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use sp_core::{crypto::KeyTypeId, H160};
use sp_keystore::Keystore;

use orbinum_runtime::AccountId;

/// Aura key-type: `KeyTypeId(*b"aura")`.
const AURA_KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

// ── RPC trait ────────────────────────────────────────────────────────────────

#[rpc(client, server)]
pub trait RelayerAuthorApi {
	/// Returns the node's Substrate account and derived EVM address.
	///
	/// Use these values to construct the sudo call:
	/// `relayer.registerRelayer(who, evmAddress)` via Polkadot-JS or the CLI.
	///
	/// Requires an Aura session key to be present in the local keystore.
	#[method(name = "relayer_getRelayInfo")]
	async fn get_relay_info(&self, evm_address: String) -> RpcResult<serde_json::Value>;
}

// ── Handler struct ───────────────────────────────────────────────────────────

pub struct RelayerAuthor {
	keystore: Arc<dyn Keystore>,
}

impl RelayerAuthor {
	pub fn new(keystore: Arc<dyn Keystore>) -> Self {
		Self { keystore }
	}
}

// ── Implementation ───────────────────────────────────────────────────────────

#[async_trait]
impl RelayerAuthorApiServer for RelayerAuthor {
	async fn get_relay_info(&self, evm_address: String) -> RpcResult<serde_json::Value> {
		let evm_addr = parse_h160(&evm_address)?;

		let aura_keys = self.keystore.sr25519_public_keys(AURA_KEY_TYPE);
		let pub_key = aura_keys.first().copied().ok_or_else(|| {
			rpc_err("No Aura key in keystore — is this node configured as a validator?")
		})?;

		let account_id: AccountId = pub_key.0.into();
		let substrate_hex = format!(
			"0x{}",
			<AccountId as AsRef<[u8; 32]>>::as_ref(&account_id)
				.iter()
				.map(|b| format!("{b:02x}"))
				.collect::<String>()
		);
		let evm_hex = format!("{evm_addr:#x}");

		Ok(serde_json::json!({
			"substrate_account": substrate_hex,
			"evm_address": evm_hex,
		}))
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn rpc_err(msg: impl Into<String>) -> ErrorObjectOwned {
	ErrorObjectOwned::owned(-32000, msg.into(), None::<()>)
}

fn parse_h160(s: &str) -> Result<H160, ErrorObjectOwned> {
	let hex = s.trim_start_matches("0x");
	if hex.len() != 40 {
		return Err(rpc_err(format!(
			"EVM address must be 40 hex chars (20 bytes), got {} in {:?}",
			hex.len(),
			s
		)));
	}
	let mut arr = [0u8; 20];
	for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
		let hi = hex_nibble(chunk[0])
			.ok_or_else(|| rpc_err(format!("Invalid hex char in EVM address: {s:?}")))?;
		let lo = hex_nibble(chunk[1])
			.ok_or_else(|| rpc_err(format!("Invalid hex char in EVM address: {s:?}")))?;
		arr[i] = (hi << 4) | lo;
	}
	Ok(H160(arr))
}

fn hex_nibble(c: u8) -> Option<u8> {
	match c {
		b'0'..=b'9' => Some(c - b'0'),
		b'a'..=b'f' => Some(c - b'a' + 10),
		b'A'..=b'F' => Some(c - b'A' + 10),
		_ => None,
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::{hex_nibble, parse_h160};

	// ── hex_nibble ────────────────────────────────────────────────────────────

	#[test]
	fn hex_nibble_digits() {
		for (c, expected) in (b'0'..=b'9').zip(0u8..=9u8) {
			assert_eq!(hex_nibble(c), Some(expected));
		}
	}

	#[test]
	fn hex_nibble_lowercase() {
		for (c, expected) in (b'a'..=b'f').zip(10u8..=15u8) {
			assert_eq!(hex_nibble(c), Some(expected));
		}
	}

	#[test]
	fn hex_nibble_uppercase() {
		for (c, expected) in (b'A'..=b'F').zip(10u8..=15u8) {
			assert_eq!(hex_nibble(c), Some(expected));
		}
	}

	#[test]
	fn hex_nibble_invalid_returns_none() {
		for c in [b'g', b'G', b'z', b' ', b'!', b'\n'] {
			assert_eq!(hex_nibble(c), None, "expected None for {:?}", c as char);
		}
	}

	// ── parse_h160 ────────────────────────────────────────────────────────────

	#[test]
	fn parse_h160_valid_with_prefix() {
		let addr = "0xd43593c715fdd31c61141abd04a99fd6822c8558";
		let result = parse_h160(addr);
		assert!(result.is_ok(), "expected Ok for valid 0x-prefixed address");
		let h160 = result.unwrap();
		assert_eq!(h160.0[0], 0xd4);
		assert_eq!(h160.0[19], 0x58);
	}

	#[test]
	fn parse_h160_valid_without_prefix() {
		let addr = "d43593c715fdd31c61141abd04a99fd6822c8558";
		assert!(parse_h160(addr).is_ok());
	}

	#[test]
	fn parse_h160_uppercase_accepted() {
		let addr = "0xD43593C715FDD31C61141ABD04A99FD6822C8558";
		assert!(parse_h160(addr).is_ok());
	}

	#[test]
	fn parse_h160_all_zeros() {
		let addr = "0x0000000000000000000000000000000000000000";
		let result = parse_h160(addr).unwrap();
		assert_eq!(result.0, [0u8; 20]);
	}

	#[test]
	fn parse_h160_all_ff() {
		let addr = "0xffffffffffffffffffffffffffffffffffffffff";
		let result = parse_h160(addr).unwrap();
		assert_eq!(result.0, [0xffu8; 20]);
	}

	#[test]
	fn parse_h160_too_short_rejected() {
		let addr = "0xd435";
		assert!(
			parse_h160(addr).is_err(),
			"address shorter than 20 bytes must be rejected"
		);
	}

	#[test]
	fn parse_h160_too_long_rejected() {
		// 21 bytes = 42 hex chars
		let addr = "0xd43593c715fdd31c61141abd04a99fd6822c8558AA";
		assert!(
			parse_h160(addr).is_err(),
			"address longer than 20 bytes must be rejected"
		);
	}

	#[test]
	fn parse_h160_invalid_char_rejected() {
		let addr = "0xd43593c715fdd31c61141abd04a99fd6822c85GG";
		assert!(
			parse_h160(addr).is_err(),
			"address with invalid hex chars must be rejected"
		);
	}

	#[test]
	fn parse_h160_empty_string_rejected() {
		assert!(parse_h160("").is_err());
		assert!(parse_h160("0x").is_err());
	}

	#[test]
	fn parse_h160_error_code_is_minus_32000() {
		let err = parse_h160("bad").unwrap_err();
		assert_eq!(err.code(), -32000);
	}

	#[test]
	fn parse_h160_roundtrip_bytes() {
		// Build a known 20-byte array, hex-encode, parse back, compare.
		let expected: [u8; 20] = [
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		];
		let hex_str = format!(
			"0x{}",
			expected
				.iter()
				.map(|b| format!("{b:02x}"))
				.collect::<String>()
		);
		let result = parse_h160(&hex_str).unwrap();
		assert_eq!(result.0, expected);
	}
}
