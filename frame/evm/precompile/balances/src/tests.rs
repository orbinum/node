//! Tests for `pallet-evm-precompile-balances`.
//!
//! # Coverage
//!
//! | # | Test                                          | What it verifies                                     |
//! |---|-----------------------------------------------|------------------------------------------------------|
//! | 1 | `selector_too_short_returns_error`            | Input < 4 bytes → selector error                     |
//! | 2 | `unknown_selector_returns_error`              | Unrecognised 4-byte selector → error                 |
//! | 3 | `transfer_input_too_short_returns_error`       | Selector OK but params missing → error               |
//! | 4 | `transfer_allow_death_updates_balances`        | Happy path: balances change correctly                |
//! | 5 | `transfer_keep_alive_updates_balances`         | Happy path with keep-alive flag                      |
//! | 6 | `transfer_keep_alive_fails_if_would_kill_sender` | keep-alive prevents draining below ED              |
//! | 7 | `transfer_allow_death_drains_full_balance`     | allow-death can drain sender to 0 (account reaped)   |
//! | 8 | `transfer_to_evm_suffix_account`              | Dest is `[H160 | 12×0x00]` — EVM-mapped style       |
//! | 9 | `transfer_to_arbitrary_accountid32`           | Dest is pure arbitrary 32-byte account (Sr25519)     |
//! |10 | `transfer_value_overflow_returns_error`        | uint256 > u128::MAX → error                          |
//! |11 | `transfer_insufficient_balance_returns_error`  | Caller has less than requested → error               |

use fp_evm::{ExitSucceed, Precompile};
use pallet_balances::Pallet as Balances;

use crate::{
	mock::{bob_account, caller_account, eve_evm_account, new_test_ext, MockHandle, Test},
	BalancesPrecompile, SEL_TRANSFER, SEL_TRANSFER_KEEP_ALIVE,
};

// ─────────────────────────────────────────────────────────────────────────────
// Encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encode `dest` (32 bytes) + `value` (u128 as uint256 big-endian) after `selector`.
fn encode_transfer(selector: [u8; 4], dest: [u8; 32], value: u128) -> Vec<u8> {
	let mut input = selector.to_vec();
	input.extend_from_slice(&dest);
	// uint256: 16 zero bytes (high) + 16 bytes (u128 big-endian value, low)
	input.extend_from_slice(&[0u8; 16]);
	input.extend_from_slice(&value.to_be_bytes());
	input
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Selector validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn selector_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		for len in 0..4 {
			let mut handle = MockHandle::new(vec![0xAAu8; len]);
			let result = BalancesPrecompile::<Test>::execute(&mut handle);
			assert!(result.is_err(), "expected error for input of length {len}");
		}
	});
}

#[test]
fn unknown_selector_returns_error() {
	new_test_ext().execute_with(|| {
		// 0xDEADBEEF is not a known selector.
		let mut handle = MockHandle::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);
		assert!(result.is_err(), "expected error for unknown selector");
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Parameter decoding
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transfer_input_too_short_returns_error() {
	new_test_ext().execute_with(|| {
		// Selector only — no dest or value.
		let mut handle = MockHandle::new(SEL_TRANSFER.to_vec());
		let result = BalancesPrecompile::<Test>::execute(&mut handle);
		assert!(result.is_err(), "expected error for truncated input");

		// Selector + partial dest (only 20 bytes instead of 32+32).
		let partial: Vec<u8> = SEL_TRANSFER.iter().chain(&[0xFFu8; 20]).copied().collect();
		let mut handle2 = MockHandle::new(partial);
		let result2 = BalancesPrecompile::<Test>::execute(&mut handle2);
		assert!(
			result2.is_err(),
			"expected error for partially present dest"
		);
	});
}

#[test]
fn transfer_value_overflow_returns_error() {
	new_test_ext().execute_with(|| {
		let mut input = SEL_TRANSFER.to_vec();
		input.extend_from_slice(bob_account().as_ref());
		// Encode 2^128 as uint256: first byte of the high half is 0x01, rest 0x00.
		let mut value_bytes = [0u8; 32];
		value_bytes[15] = 0x01; // bit 128 set → overflows u128
		input.extend_from_slice(&value_bytes);

		let mut handle = MockHandle::new(input);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);
		assert!(result.is_err(), "expected overflow error");
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Happy-path transfers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transfer_allow_death_updates_balances() {
	new_test_ext().execute_with(|| {
		let initial = Balances::<Test>::free_balance(caller_account());
		let amount = 1_000u128;

		let input = encode_transfer(SEL_TRANSFER, bob_account().into(), amount);
		let mut handle = MockHandle::new(input);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);

		assert!(
			matches!(result, Ok(ref out) if out.exit_status == ExitSucceed::Returned),
			"expected Ok(Returned), got {result:?}"
		);

		assert_eq!(
			Balances::<Test>::free_balance(caller_account()),
			initial - amount,
			"caller balance not reduced by amount"
		);
		assert_eq!(
			Balances::<Test>::free_balance(bob_account()),
			amount,
			"bob balance not increased by amount"
		);
	});
}

#[test]
fn transfer_keep_alive_updates_balances() {
	new_test_ext().execute_with(|| {
		let initial = Balances::<Test>::free_balance(caller_account());
		// Transfer all-but-one so the account stays alive (ED = 1).
		let amount = initial - 1;

		let input = encode_transfer(SEL_TRANSFER_KEEP_ALIVE, bob_account().into(), amount);
		let mut handle = MockHandle::new(input);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);

		assert!(
			matches!(result, Ok(ref out) if out.exit_status == ExitSucceed::Returned),
			"expected Ok(Returned), got {result:?}"
		);

		assert_eq!(
			Balances::<Test>::free_balance(caller_account()),
			1,
			"caller should retain exactly the existential deposit"
		);
		assert_eq!(
			Balances::<Test>::free_balance(bob_account()),
			amount,
			"bob should receive the transferred amount"
		);
	});
}

#[test]
fn transfer_keep_alive_fails_if_would_kill_sender() {
	new_test_ext().execute_with(|| {
		let initial = Balances::<Test>::free_balance(caller_account());

		// Attempting to transfer the full balance with keep-alive must fail
		// because it would leave the sender at 0, below ED = 1.
		let input = encode_transfer(SEL_TRANSFER_KEEP_ALIVE, bob_account().into(), initial);
		let mut handle = MockHandle::new(input);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);

		assert!(
			result.is_err(),
			"keep-alive transfer of full balance must fail"
		);

		// Balances must be unchanged.
		assert_eq!(
			Balances::<Test>::free_balance(caller_account()),
			initial,
			"caller balance must be unchanged after failed transfer"
		);
		assert_eq!(
			Balances::<Test>::free_balance(bob_account()),
			0,
			"bob balance must be unchanged after failed transfer"
		);
	});
}

#[test]
fn transfer_allow_death_drains_full_balance() {
	new_test_ext().execute_with(|| {
		let initial = Balances::<Test>::free_balance(caller_account());

		// `transfer` (allow-death) of the full balance must succeed and reap the
		// sender's account.
		let input = encode_transfer(SEL_TRANSFER, bob_account().into(), initial);
		let mut handle = MockHandle::new(input);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);

		assert!(
			matches!(result, Ok(ref out) if out.exit_status == ExitSucceed::Returned),
			"expected Ok(Returned), got {result:?}"
		);

		assert_eq!(
			Balances::<Test>::free_balance(caller_account()),
			0,
			"caller balance must be zero after full drain"
		);
		assert_eq!(
			Balances::<Test>::free_balance(bob_account()),
			initial,
			"bob must receive the full initial balance"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Destination type variants
// ─────────────────────────────────────────────────────────────────────────────

/// Destination is an EVM-suffix AccountId32: `[H160 | 0x00 × 12]`.
/// This mirrors how an EVM wallet is represented in the Substrate storage.
#[test]
fn transfer_to_evm_suffix_account() {
	new_test_ext().execute_with(|| {
		let amount = 500u128;
		let dest: [u8; 32] = eve_evm_account().into();

		let input = encode_transfer(SEL_TRANSFER, dest, amount);
		let mut handle = MockHandle::new(input);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);

		assert!(
			matches!(result, Ok(ref out) if out.exit_status == ExitSucceed::Returned),
			"transfer to EVM-suffix account failed: {result:?}"
		);

		assert_eq!(
			Balances::<Test>::free_balance(eve_evm_account()),
			amount,
			"EVM-suffix recipient did not receive the expected balance"
		);
	});
}

/// Destination is an arbitrary 32-byte AccountId32 (e.g. a Sr25519 public key).
#[test]
fn transfer_to_arbitrary_accountid32() {
	new_test_ext().execute_with(|| {
		let amount = 250u128;
		// A deterministic but arbitrary 32-byte account (distinct from bob).
		let dest_bytes = [0xCAu8; 32];
		let dest_account = sp_runtime::AccountId32::from(dest_bytes);

		let input = encode_transfer(SEL_TRANSFER, dest_bytes, amount);
		let mut handle = MockHandle::new(input);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);

		assert!(
			matches!(result, Ok(ref out) if out.exit_status == ExitSucceed::Returned),
			"transfer to arbitrary AccountId32 failed: {result:?}"
		);

		assert_eq!(
			Balances::<Test>::free_balance(&dest_account),
			amount,
			"arbitrary AccountId32 recipient did not receive the expected balance"
		);
	});
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Insufficient balance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn transfer_insufficient_balance_returns_error() {
	new_test_ext().execute_with(|| {
		let initial = Balances::<Test>::free_balance(caller_account());
		// Request more than the caller has.
		let amount = initial + 1;

		let input = encode_transfer(SEL_TRANSFER, bob_account().into(), amount);
		let mut handle = MockHandle::new(input);
		let result = BalancesPrecompile::<Test>::execute(&mut handle);

		assert!(
			result.is_err(),
			"expected error when caller has insufficient balance"
		);

		// Balances must be unchanged.
		assert_eq!(
			Balances::<Test>::free_balance(caller_account()),
			initial,
			"caller balance must be unchanged after failed transfer"
		);
		assert_eq!(
			Balances::<Test>::free_balance(bob_account()),
			0,
			"bob balance must be unchanged after failed transfer"
		);
	});
}
