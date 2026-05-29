//! Unit tests for `pallet-evm-precompile-account-mapping`.
//!
//! Each test exercises the precompile through `MockHandle` so that no EVM runner
//! is involved.  Storage interactions use the in-memory `TestExternalities` built
//! by `mock::new_test_ext()`.

use fp_evm::{ExitError, ExitSucceed, Precompile, PrecompileFailure};
use sp_core::H160;

use crate::{
	mock::{new_test_ext, MockHandle},
	AccountMappingPrecompile,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds ABI-encoded `string` / `bytes` argument (offset pointer + length + data).
/// The encoded slice is suitable for appending after a function selector.
///
/// Layout (relative to the start of params, i.e. after the 4-byte selector):
///   [0..32]   offset = 0x20  (string data starts at byte 32 of params)
///   [32..64]  length
///   [64..]    UTF-8 bytes zero-padded to the next 32-byte boundary
fn abi_encode_string(s: &[u8]) -> Vec<u8> {
	let padded_len = (s.len() + 31) & !31;
	let mut out = vec![0u8; 64 + padded_len];
	// offset = 0x20 = 32
	out[31] = 0x20;
	// length
	let len_bytes = (s.len() as u64).to_be_bytes();
	out[56..64].copy_from_slice(&len_bytes);
	// data
	out[64..64 + s.len()].copy_from_slice(s);
	out
}

/// Builds params for `hasPrivateLink(string alias, bytes32 commitment)`.
///
/// ABI layout (after selector):
///   [0..32]   offset to string = 0x40 (64)
///   [32..64]  bytes32 commitment  (static)
///   [64..96]  string length
///   [96..]    string bytes zero-padded to 32-byte boundary
fn abi_encode_has_private_link(alias: &[u8], commitment: &[u8; 32]) -> Vec<u8> {
	let padded_len = (alias.len() + 31) & !31;
	let mut params = vec![0u8; 96 + padded_len];
	// offset to string = 64 (0x40)
	params[31] = 0x40;
	// commitment at [32..64]
	params[32..64].copy_from_slice(commitment);
	// string length at [64..96]
	let len_bytes = (alias.len() as u64).to_be_bytes();
	params[88..96].copy_from_slice(&len_bytes);
	// string data
	params[96..96 + alias.len()].copy_from_slice(alias);
	params
}

// ─────────────────────────────────────────────────────────────────────────────
// Selector routing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn selector_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		// Only 3 bytes ─ selector requires at least 4
		let mut handle = MockHandle::new(vec![0xd0, 0x31, 0x49]);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(
			matches!(
				result,
				Err(PrecompileFailure::Error {
					exit_status: ExitError::Other(_)
				})
			),
			"expected error for short input"
		);
	});
}

#[test]
fn unknown_selector_returns_error() {
	new_test_ext().execute_with(|| {
		let mut handle = MockHandle::new(vec![0xff, 0xff, 0xff, 0xff]);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(
			matches!(
				result,
				Err(PrecompileFailure::Error {
					exit_status: ExitError::Other(_)
				})
			),
			"expected error for unknown selector"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Read-only: resolveAlias
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn resolve_alias_not_found_returns_zero_addresses() {
	new_test_ext().execute_with(|| {
		// resolveAlias("noexist")
		let mut input = vec![0xd0, 0x31, 0x49, 0xab];
		input.extend_from_slice(&abi_encode_string(b"noexist"));

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		let out = result.expect("resolveAlias must succeed");
		assert_eq!(out.exit_status, ExitSucceed::Returned);
		// Two H160 zero addresses → 64 zero bytes
		assert_eq!(out.output.len(), 64);
		assert_eq!(out.output, vec![0u8; 64]);
	});
}

#[test]
fn resolve_alias_abi_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		// Selector only — no ABI params at all
		let mut handle = MockHandle::new(vec![0xd0, 0x31, 0x49, 0xab]);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(result.is_err(), "resolveAlias with no params must fail");
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Read-only: getAliasOf
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn get_alias_of_no_alias_returns_empty_bytes() {
	new_test_ext().execute_with(|| {
		// getAliasOf(H160::zero()) ─ address not registered
		let mut input = vec![0x7a, 0x0e, 0xd6, 0x2c];
		input.extend_from_slice(&[0u8; 32]); // zero-padded H160

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		let out = result.expect("getAliasOf must succeed");
		assert_eq!(out.exit_status, ExitSucceed::Returned);
		assert_eq!(out.output.len(), 64, "empty ABI bytes encoding is 64 bytes");
		// Offset slot = 0x20
		assert_eq!(out.output[31], 0x20);
		// Length = 0
		let length = u64::from_be_bytes(out.output[56..64].try_into().unwrap());
		assert_eq!(length, 0);
	});
}

#[test]
fn get_alias_of_abi_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		// Only 20 bytes of params instead of 32
		let mut input = vec![0x7a, 0x0e, 0xd6, 0x2c];
		input.extend_from_slice(&[0u8; 20]);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(result.is_err(), "getAliasOf with short params must fail");
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Read-only: hasPrivateLink
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn has_private_link_returns_false_when_not_registered() {
	new_test_ext().execute_with(|| {
		// hasPrivateLink("alice", [0;32])
		let commitment = [0u8; 32];
		let mut input = vec![0x47, 0xe0, 0x5c, 0x6c];
		input.extend_from_slice(&abi_encode_has_private_link(b"alice", &commitment));

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		let out = result.expect("hasPrivateLink must succeed");
		assert_eq!(out.exit_status, ExitSucceed::Returned);
		assert_eq!(out.output.len(), 32);
		assert_eq!(out.output[31], 0, "expected false");
	});
}

#[test]
fn has_private_link_abi_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		// Only 30 bytes after selector → fails "hasPrivateLink: input too short"
		let mut input = vec![0x47, 0xe0, 0x5c, 0x6c];
		input.extend_from_slice(&[0u8; 30]);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(
			result.is_err(),
			"hasPrivateLink with short params must fail"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// State-changing: mapAccount
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn map_account_dispatches_call() {
	new_test_ext().execute_with(|| {
		// mapAccount() — no ABI params, just the 4-byte selector
		let mut handle = MockHandle::new(vec![0xdc, 0xa4, 0x9d, 0x0e]);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		// The precompile must reach the dispatch stage; it must NOT fail with an
		// ABI decode or routing error.
		let failed_abi = match &result {
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(msg),
			}) => {
				msg.starts_with("input too short")
					|| msg.starts_with("ABI:")
					|| msg.starts_with("unknown selector")
			}
			_ => false,
		};
		assert!(
			!failed_abi,
			"map_account should not fail with ABI/selector error"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// State-changing: registerAlias
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn register_alias_ok() {
	new_test_ext().execute_with(|| {
		// registerAlias("alice") — caller has 1_000_000 ≥ AliasDeposit (100)
		let mut input = vec![0x2f, 0x88, 0x39, 0xc3];
		input.extend_from_slice(&abi_encode_string(b"alice"));

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		assert!(
			result.is_ok(),
			"registerAlias with funded account must succeed: {result:?}"
		);
		assert_eq!(result.unwrap().exit_status, ExitSucceed::Stopped);
	});
}

#[test]
fn register_alias_abi_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		// Only 10 bytes after selector — ABI slot occupies 32 bytes minimum
		let mut input = vec![0x2f, 0x88, 0x39, 0xc3];
		input.extend_from_slice(&[0u8; 10]);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		assert!(
			result.is_err(),
			"registerAlias with truncated ABI must fail"
		);
	});
}

#[test]
fn register_alias_then_resolve_returns_correct_address() {
	new_test_ext().execute_with(|| {
		let caller_h160 = crate::mock::caller();

		// 1. Register "bob" for caller()
		let mut input = vec![0x2f, 0x88, 0x39, 0xc3];
		input.extend_from_slice(&abi_encode_string(b"bob"));
		let mut handle = MockHandle::new(input);
		AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("registerAlias must succeed");

		// 2. Resolve "bob"
		let mut input = vec![0xd0, 0x31, 0x49, 0xab];
		input.extend_from_slice(&abi_encode_string(b"bob"));
		let mut handle = MockHandle::new(input);
		let out = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("resolveAlias must succeed");

		// First 32-byte slot encodes the owner H160 (bytes 12..32)
		let resolved = H160::from_slice(&out.output[12..32]);
		assert_eq!(
			resolved, caller_h160,
			"resolved address must match the registrant"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// State-changing: registerPrivateLink / removePrivateLink
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn register_private_link_ok() {
	new_test_ext().execute_with(|| {
		// First register an alias (required by the pallet)
		let mut input = vec![0x2f, 0x88, 0x39, 0xc3];
		input.extend_from_slice(&abi_encode_string(b"link_test"));
		let mut handle = MockHandle::new(input);
		AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("registerAlias must succeed");

		// registerPrivateLink(chainId=1, commitment=[0;32])
		let mut input = vec![0xc0, 0x4e, 0x98, 0xf4];
		let mut params = vec![0u8; 64];
		// chainId = 1 in last 4 bytes of first slot
		params[28..32].copy_from_slice(&1u32.to_be_bytes());
		// commitment = [0;32] (already zero)
		input.extend_from_slice(&params);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		assert!(
			result.is_ok(),
			"registerPrivateLink must succeed: {result:?}"
		);
	});
}

#[test]
fn remove_private_link_ok() {
	new_test_ext().execute_with(|| {
		let commitment = [0u8; 32];

		// 0. Register an alias first (required by the pallet)
		let mut input = vec![0x2f, 0x88, 0x39, 0xc3];
		input.extend_from_slice(&abi_encode_string(b"rm_link_test"));
		let mut handle = MockHandle::new(input);
		AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("registerAlias must succeed");

		// 1. Register the private link
		let mut input = vec![0xc0, 0x4e, 0x98, 0xf4];
		let mut params = vec![0u8; 64];
		params[28..32].copy_from_slice(&1u32.to_be_bytes());
		input.extend_from_slice(&params);
		let mut handle = MockHandle::new(input);
		AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("registerPrivateLink must succeed");

		// 2. Now remove it
		let mut input = vec![0xdf, 0xd8, 0xb5, 0x7e];
		input.extend_from_slice(&commitment);
		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		assert!(result.is_ok(), "removePrivateLink must succeed: {result:?}");
	});
}

#[test]
fn remove_private_link_abi_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		// 20 bytes after selector instead of 32
		let mut input = vec![0xdf, 0xd8, 0xb5, 0x7e];
		input.extend_from_slice(&[0u8; 20]);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(
			result.is_err(),
			"removePrivateLink with short params must fail"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// State-changing: putAliasOnSale — price zero is rejected by pallet
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn put_alias_on_sale_no_alias_returns_dispatch_error() {
	new_test_ext().execute_with(|| {
		// putAliasOnSale(price=1, allowedBuyers=[]) without having an alias first
		let mut input = vec![0x32, 0x09, 0x11, 0x92];
		let mut params = vec![0u8; 96];
		// price = 1
		params[31] = 0x01;
		// offset to address[] = 0x40 = 64
		params[63] = 0x40;
		// array length = 0 (at params[64..96])
		input.extend_from_slice(&params);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		// Must fail with a dispatch error (caller has no alias), NOT an ABI error
		match &result {
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(msg),
			}) => {
				let is_abi_error = msg.starts_with("input too short")
					|| msg.starts_with("ABI:")
					|| msg.starts_with("unknown selector");
				assert!(
					!is_abi_error,
					"expected dispatch error, got ABI error: {msg}"
				);
			}
			Ok(_) => panic!("expected dispatch error, but got Ok"),
			Err(other) => panic!("unexpected failure variant: {other:?}"),
		}
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3: composability helpers — isEvmSuffixAccount
// ─────────────────────────────────────────────────────────────────────────────

/// bytes32 whose last 12 bytes are zero → suffix pattern → true
#[test]
fn is_evm_suffix_account_returns_true_for_suffix_pattern() {
	new_test_ext().execute_with(|| {
		// isEvmSuffixAccount(bytes32) selector: 0x96e69f8a
		let mut input = vec![0x96, 0xe6, 0x9f, 0x8a];
		let mut bytes32 = [0u8; 32];
		// First 20 bytes = some H160; last 12 stay zero (suffix pattern).
		bytes32[..20].copy_from_slice(H160::from_low_u64_be(0xdeadbeef).as_bytes());
		input.extend_from_slice(&bytes32);

		let mut handle = MockHandle::new(input);
		let out = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("isEvmSuffixAccount must succeed");

		assert_eq!(out.exit_status, ExitSucceed::Returned);
		assert_eq!(out.output.len(), 32);
		assert_eq!(
			out.output[31], 1,
			"last 12 bytes are zero → isEvmSuffix = true"
		);
	});
}

/// bytes32 with a non-zero byte in positions 20..32 → not suffix → false
#[test]
fn is_evm_suffix_account_returns_false_for_non_suffix() {
	new_test_ext().execute_with(|| {
		let mut input = vec![0x96, 0xe6, 0x9f, 0x8a];
		let mut bytes32 = [0u8; 32];
		bytes32[20] = 0x01; // Sr25519 account: non-zero suffix byte
		input.extend_from_slice(&bytes32);

		let mut handle = MockHandle::new(input);
		let out = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("isEvmSuffixAccount must succeed");

		assert_eq!(
			out.output[31], 0,
			"non-zero suffix byte → isEvmSuffix = false"
		);
	});
}

/// Input shorter than selector + bytes32 must return an error.
#[test]
fn is_evm_suffix_account_abi_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		let mut input = vec![0x96, 0xe6, 0x9f, 0x8a];
		input.extend_from_slice(&[0u8; 20]); // only 20 bytes instead of 32

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(
			result.is_err(),
			"isEvmSuffixAccount with short input must fail"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3: composability helpers — toEvmAddress
// ─────────────────────────────────────────────────────────────────────────────

/// suffix bytes32 → derives H160 from first 20 bytes (no storage lookup)
#[test]
fn to_evm_address_derives_h160_from_suffix_bytes32() {
	new_test_ext().execute_with(|| {
		// toEvmAddress(bytes32) selector: 0x0f5b3052
		let target = H160::from_low_u64_be(0xcafe);

		let mut input = vec![0x0f, 0x5b, 0x30, 0x52];
		let mut bytes32 = [0u8; 32];
		bytes32[..20].copy_from_slice(target.as_bytes()); // last 12 bytes stay zero
		input.extend_from_slice(&bytes32);

		let mut handle = MockHandle::new(input);
		let out = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("toEvmAddress must succeed");

		assert_eq!(out.exit_status, ExitSucceed::Returned);
		assert_eq!(out.output.len(), 32);
		// ABI address encoding: 12 zero bytes + 20 H160 bytes
		assert_eq!(&out.output[0..12], &[0u8; 12]);
		let derived = H160::from_slice(&out.output[12..32]);
		assert_eq!(
			derived, target,
			"derived H160 must match first 20 bytes of suffix bytes32"
		);
	});
}

/// Non-suffix bytes32 (Sr25519-style) → returns address(0)
#[test]
fn to_evm_address_returns_zero_for_non_suffix() {
	new_test_ext().execute_with(|| {
		let mut input = vec![0x0f, 0x5b, 0x30, 0x52];
		let mut bytes32 = [0u8; 32];
		bytes32[20] = 0x01; // non-zero suffix byte
		input.extend_from_slice(&bytes32);

		let mut handle = MockHandle::new(input);
		let out = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("toEvmAddress must succeed");

		let derived = H160::from_slice(&out.output[12..32]);
		assert_eq!(
			derived,
			H160::zero(),
			"non-suffix bytes32 must return address(0)"
		);
	});
}

/// Input shorter than selector + bytes32 must return an error.
#[test]
fn to_evm_address_abi_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		let mut input = vec![0x0f, 0x5b, 0x30, 0x52];
		input.extend_from_slice(&[0u8; 20]);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(result.is_err(), "toEvmAddress with short input must fail");
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3: composability helpers — resolveAliasFull
// ─────────────────────────────────────────────────────────────────────────────

/// Unknown alias → 96 zero bytes
#[test]
fn resolve_alias_full_returns_zeros_for_unknown_alias() {
	new_test_ext().execute_with(|| {
		// resolveAliasFull(string) selector: 0x2e40772b
		let mut input = vec![0x2e, 0x40, 0x77, 0x2b];
		input.extend_from_slice(&abi_encode_string(b"no_such_alias"));

		let mut handle = MockHandle::new(input);
		let out = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("resolveAliasFull must succeed even for unknown alias");

		assert_eq!(out.exit_status, ExitSucceed::Returned);
		assert_eq!(out.output.len(), 96);
		assert_eq!(
			out.output,
			vec![0u8; 96],
			"unknown alias must return 96 zero bytes"
		);
	});
}

/// Registered alias → correct ABI layout (bytes32 zeros, evmAddress, isEvmSuffix=false)
///
/// In the precompile mock, `is_implicit_evm_account` always returns false (default),
/// so the bytes32 accountId32 slot stays zero and evmAddress comes from storage.
#[test]
fn resolve_alias_full_returns_correct_layout_for_registered_alias() {
	new_test_ext().execute_with(|| {
		let caller_h160 = crate::mock::caller(); // H160::from_low_u64_be(1)

		// Register alias "full_test" for caller()
		let mut input = vec![0x2f, 0x88, 0x39, 0xc3]; // registerAlias selector
		input.extend_from_slice(&abi_encode_string(b"full_test"));
		let mut handle = MockHandle::new(input);
		AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("registerAlias must succeed");

		// resolveAliasFull("full_test")
		let mut input = vec![0x2e, 0x40, 0x77, 0x2b];
		input.extend_from_slice(&abi_encode_string(b"full_test"));
		let mut handle = MockHandle::new(input);
		let out = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle)
			.expect("resolveAliasFull must succeed");

		assert_eq!(out.output.len(), 96);
		// [0..32]: bytes32 accountId32 — zeros (is_suffix = false in mock)
		assert_eq!(
			&out.output[0..32],
			&[0u8; 32],
			"accountId32 slot must be zeros for non-suffix account"
		);
		// [32..64]: address evmAddress — ABI-encoded H160 (12 zero bytes + 20 address bytes)
		let resolved_evm = H160::from_slice(&out.output[44..64]);
		assert_eq!(
			resolved_evm, caller_h160,
			"evmAddress slot must match caller()"
		);
		// [64..96]: bool isEvmSuffix — false
		assert_eq!(
			out.output[95], 0,
			"isEvmSuffix must be false for mock accounts"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: relay via chain link — dispatchAsLinkedAccount
// ─────────────────────────────────────────────────────────────────────────────

/// Builds ABI-encoded params for `dispatchAsLinkedAccount(bytes32,uint32,bytes,bytes,bytes)`.
///
/// Returns the params WITHOUT the 4-byte selector.
///
/// ABI head layout (160 bytes):
///   [0..32]    bytes32 owner    (static)
///   [32..64]   uint32  chainId  (static, value in [60..64])
///   [64..96]   uint256 offset → bytes address  (dynamic)
///   [96..128]  uint256 offset → bytes signature (dynamic)
///   [128..160] uint256 offset → bytes call      (dynamic)
fn abi_encode_dispatch_as_linked(
	owner: &[u8; 32],
	chain_id: u32,
	address: &[u8],
	signature: &[u8],
	call: &[u8],
) -> Vec<u8> {
	let addr_padded_len = (address.len() + 31) & !31;
	let sig_padded_len = (signature.len() + 31) & !31;
	let call_padded_len = (call.len() + 31) & !31;

	// Offsets are from the start of params (after selector).
	let head: u64 = 160;
	let addr_offset: u64 = head;
	let sig_offset: u64 = addr_offset + 32 + addr_padded_len as u64;
	let call_offset: u64 = sig_offset + 32 + sig_padded_len as u64;

	let total = head as usize + 32 + addr_padded_len + 32 + sig_padded_len + 32 + call_padded_len;
	let mut params = vec![0u8; total];

	// bytes32 owner (static)
	params[0..32].copy_from_slice(owner);
	// uint32 chainId (value in last 4 bytes of its 32-byte slot at [32..64])
	params[60..64].copy_from_slice(&chain_id.to_be_bytes());
	// offset to address (slot at [64..96], value in last 8 bytes)
	params[88..96].copy_from_slice(&addr_offset.to_be_bytes());
	// offset to signature (slot at [96..128])
	params[120..128].copy_from_slice(&sig_offset.to_be_bytes());
	// offset to call (slot at [128..160])
	params[152..160].copy_from_slice(&call_offset.to_be_bytes());

	// Dynamic: bytes address
	let p = addr_offset as usize;
	params[p + 24..p + 32].copy_from_slice(&(address.len() as u64).to_be_bytes());
	params[p + 32..p + 32 + address.len()].copy_from_slice(address);

	// Dynamic: bytes signature
	let p = sig_offset as usize;
	params[p + 24..p + 32].copy_from_slice(&(signature.len() as u64).to_be_bytes());
	params[p + 32..p + 32 + signature.len()].copy_from_slice(signature);

	// Dynamic: bytes call
	let p = call_offset as usize;
	params[p + 24..p + 32].copy_from_slice(&(call.len() as u64).to_be_bytes());
	params[p + 32..p + 32 + call.len()].copy_from_slice(call);

	params
}

/// Input shorter than 5 ABI slots (160 bytes) must return an error.
#[test]
fn dispatch_as_linked_account_short_input_returns_error() {
	new_test_ext().execute_with(|| {
		// selector + 32 bytes (only 1 slot, need 5)
		let mut input = vec![0x06, 0x30, 0xce, 0xf9];
		input.extend_from_slice(&[0u8; 32]);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(
			matches!(
				result,
				Err(PrecompileFailure::Error {
					exit_status: ExitError::Other(_)
				})
			),
			"short input must return error"
		);
	});
}

/// Params with correct ABI head but garbage SCALE bytes for `call` must return a decode error.
///
/// Note: `0xFF` is an invalid pallet index in the mock runtime (only 0–4 are valid),
/// so `RuntimeCall::decode` will fail.
#[test]
fn dispatch_as_linked_account_invalid_scale_call_returns_error() {
	new_test_ext().execute_with(|| {
		// bytes32 owner: H160::from_low_u64_be(1) in first 20 bytes
		let mut owner_slot = [0u8; 32];
		owner_slot[19] = 0x01;

		let params = abi_encode_dispatch_as_linked(
			&owner_slot,
			2, // chain_id != NativeEvmChainId(1) in mock
			b"external_addr",
			b"fake_sig",
			&[0xFF, 0xFF, 0xFF], // invalid SCALE: pallet index 0xFF does not exist
		);

		let mut input = vec![0x06, 0x30, 0xce, 0xf9];
		input.extend_from_slice(&params);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);
		assert!(
			matches!(
				result,
				Err(PrecompileFailure::Error {
					exit_status: ExitError::Other(ref msg),
				}) if msg.contains("SCALE")
			),
			"invalid SCALE call must fail with SCALE decode error; got: {result:?}"
		);
	});
}

/// Valid ABI encoding must route to the pallet (not fail with ABI/selector error).
///
/// The pallet will return a chain-link error (no link registered), but the precompile
/// must not fail at the ABI decode stage. The mock NativeEvmChainId is 1, so we pass
/// chain_id = 2 to bypass the `UseNativeSignatureForEvmAccounts` guard.
#[test]
fn dispatch_as_linked_account_routes_to_pallet_with_valid_abi() {
	use scale_codec::Encode;

	new_test_ext().execute_with(|| {
		// bytes32 owner: H160::from_low_u64_be(1) — SCALE H160 = 20 bytes; first 20 of slot
		let mut owner_slot = [0u8; 32];
		owner_slot[19] = 0x01;

		// SCALE-encode System::remark([]) as a valid RuntimeCall
		let inner_call =
			crate::mock::RuntimeCall::System(frame_system::Call::<crate::mock::Test>::remark {
				remark: vec![],
			});
		let call_bytes = inner_call.encode();

		let params = abi_encode_dispatch_as_linked(
			&owner_slot,
			2, // chain_id = 2; mock NativeEvmChainId = 1 (not blocked)
			b"external_addr",
			b"fake_sig",
			&call_bytes,
		);

		let mut input = vec![0x06, 0x30, 0xce, 0xf9];
		input.extend_from_slice(&params);

		let mut handle = MockHandle::new(input);
		let result = AccountMappingPrecompile::<crate::mock::Test>::execute(&mut handle);

		// ABI and routing must succeed — any pallet-level error is acceptable
		// (no chain link is registered, so the pallet will reject the call).
		let is_abi_error = match &result {
			Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(msg),
			}) => {
				msg.starts_with("dispatchAsLinkedAccount: input too short")
					|| msg.starts_with("dispatchAsLinkedAccount: invalid owner")
					|| msg.starts_with("dispatchAsLinkedAccount: invalid SCALE")
					|| msg.starts_with("unknown selector")
			}
			_ => false,
		};
		assert!(
			!is_abi_error,
			"valid ABI must not fail at the ABI decode stage; got: {result:?}"
		);
	});
}
