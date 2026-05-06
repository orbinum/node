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
			"registerAlias with funded account must succeed: {:?}",
			result
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
			"registerPrivateLink must succeed: {:?}",
			result
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

		assert!(
			result.is_ok(),
			"removePrivateLink must succeed: {:?}",
			result
		);
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
