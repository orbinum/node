#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

sp_api::decl_runtime_apis! {
	/// Runtime API for querying relayer status and pending fees.
	pub trait RelayerRuntimeApi {
		/// Returns true if the given account is a registered relayer.
		fn is_relayer(account: sp_runtime::AccountId32) -> bool;

		/// Returns the pending fees (in planck) for the given account and asset.
		fn pending_fees(account: sp_runtime::AccountId32, asset_id: u32) -> u128;

		/// Returns the registered EVM address for the relayer, if any.
		fn registered_evm_address(account: sp_runtime::AccountId32) -> Option<[u8; 20]>;

		/// Returns all (evm_address, substrate_account) pairs in the relay registry.
		///
		/// Used by clients to discover which validator nodes have relay active.
		/// Capa 2 of the relay architecture.
		fn get_active_relayers() -> alloc::vec::Vec<([u8; 20], sp_runtime::AccountId32)>;

		/// Returns true if the given EVM address is registered as a relayer on-chain.
		///
		/// Used by `orbinum_relayerStatus` to surface registration state to operators.
		/// Capa 2 of the relay architecture.
		fn is_relayer_evm(evm_address: [u8; 20]) -> bool;
	}
}

#[cfg(test)]
mod tests {
	use scale_codec::{Decode, Encode};
	use sp_runtime::AccountId32;

	// ── AccountId32 SCALE codec ───────────────────────────────────────────────

	#[test]
	fn account_id32_encode_decode_roundtrip() {
		let bytes = [0x42u8; 32];
		let original = AccountId32::from(bytes);
		let encoded = original.encode();
		let decoded = AccountId32::decode(&mut &encoded[..]).expect("decode must succeed");
		assert_eq!(original, decoded);
	}

	#[test]
	fn account_id32_encodes_to_32_bytes() {
		let account = AccountId32::from([0u8; 32]);
		assert_eq!(account.encode().len(), 32);
	}

	#[test]
	fn account_id32_all_zeros_roundtrip() {
		let account = AccountId32::from([0u8; 32]);
		let decoded = AccountId32::decode(&mut &account.encode()[..]).expect("decode must succeed");
		assert_eq!(account, decoded);
	}

	#[test]
	fn account_id32_all_ff_roundtrip() {
		let account = AccountId32::from([0xffu8; 32]);
		let decoded = AccountId32::decode(&mut &account.encode()[..]).expect("decode must succeed");
		assert_eq!(account, decoded);
	}

	#[test]
	fn account_id32_preserves_byte_order() {
		let mut bytes = [0u8; 32];
		bytes[0] = 0xaa;
		bytes[31] = 0xbb;
		let account = AccountId32::from(bytes);
		let raw: &[u8; 32] = account.as_ref();
		assert_eq!(raw[0], 0xaa);
		assert_eq!(raw[31], 0xbb);
	}

	// ── Option<[u8; 20]> SCALE codec (registered_evm_address return type) ───

	#[test]
	fn option_evm_address_some_roundtrip() {
		let addr: Option<[u8; 20]> = Some([0xd4u8; 20]);
		let decoded =
			Option::<[u8; 20]>::decode(&mut &addr.encode()[..]).expect("decode must succeed");
		assert_eq!(addr, decoded);
	}

	#[test]
	fn option_evm_address_none_roundtrip() {
		let addr: Option<[u8; 20]> = None;
		let decoded =
			Option::<[u8; 20]>::decode(&mut &addr.encode()[..]).expect("decode must succeed");
		assert_eq!(addr, decoded);
	}

	#[test]
	fn option_evm_address_some_encodes_with_prefix_byte() {
		// SCALE: None = 0x00, Some(x) = 0x01 ++ encode(x)
		let addr: Option<[u8; 20]> = Some([0u8; 20]);
		let encoded = addr.encode();
		assert_eq!(encoded[0], 0x01);
		assert_eq!(encoded.len(), 21);
	}

	#[test]
	fn option_evm_address_none_encodes_to_single_zero_byte() {
		let addr: Option<[u8; 20]> = None;
		assert_eq!(addr.encode(), vec![0x00]);
	}

	// ── u128 SCALE codec (pending_fees return type) ──────────────────────────

	#[test]
	fn u128_zero_roundtrip() {
		let val: u128 = 0;
		let decoded = u128::decode(&mut &val.encode()[..]).expect("decode must succeed");
		assert_eq!(val, decoded);
	}

	#[test]
	fn u128_one_orb_roundtrip() {
		let val: u128 = 1_000_000_000_000_000_000;
		let decoded = u128::decode(&mut &val.encode()[..]).expect("decode must succeed");
		assert_eq!(val, decoded);
	}

	#[test]
	fn u128_max_roundtrip() {
		let val = u128::MAX;
		let decoded = u128::decode(&mut &val.encode()[..]).expect("decode must succeed");
		assert_eq!(val, decoded);
	}

	#[test]
	fn u128_encodes_to_16_bytes_little_endian() {
		// SCALE uses little-endian fixed-width encoding for primitives.
		let val: u128 = 1u128;
		let encoded = val.encode();
		assert_eq!(encoded.len(), 16);
		assert_eq!(encoded[0], 0x01);
		assert!(encoded[1..].iter().all(|&b| b == 0x00));
	}
}
