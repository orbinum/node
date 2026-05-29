//! # EVM Precompile — Balances
//!
//! Exposes native `pallet_balances` transfers to arbitrary `AccountId32`
//! destinations from EVM contracts and wallets.
//!
//! ## ABI Selectors
//!
//! | Function                          | Selector   |
//! |-----------------------------------|------------|
//! | `transfer(bytes32,uint256)`       | `0x6a467394` |
//! | `transferKeepAlive(bytes32,uint256)` | `0xac6ac4c4` |
//!
//! The `bytes32` parameter is the raw 32-byte `AccountId32` of the recipient
//! (e.g. a Sr25519 public key or an EVM-suffix account `[H160 | 12×0x00]`).
//! The `uint256` parameter is the amount to transfer; values exceeding
//! `u128::MAX` are rejected.
//!
//! ## Gas
//!
//! A flat base cost of `5_000` gas is charged per call to cover the storage
//! reads and writes performed by `pallet_balances`.
//!
//! ## Deployment Address
//!
//! `hash(2050)` — precompile address `0x…0802` on Orbinum networks.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use core::marker::PhantomData;

use fp_evm::{
	ExitError, ExitSucceed, Precompile, PrecompileFailure, PrecompileHandle, PrecompileOutput,
	PrecompileResult,
};
use frame_support::traits::{fungible::Mutate, tokens::Preservation};
use pallet_evm::AddressMapping;
use sp_core::H160;

// ─────────────────────────────────────────────────────────────────────────────
// ABI Function Selectors
//
// Verify with:  cast sig "transfer(bytes32,uint256)"
//               cast sig "transferKeepAlive(bytes32,uint256)"
// ─────────────────────────────────────────────────────────────────────────────

/// `transfer(bytes32,uint256)` → 0x6a467394
const SEL_TRANSFER: [u8; 4] = [0x6a, 0x46, 0x73, 0x94];
/// `transferKeepAlive(bytes32,uint256)` → 0xac6ac4c4
const SEL_TRANSFER_KEEP_ALIVE: [u8; 4] = [0xac, 0x6a, 0xc4, 0xc4];

/// Flat base gas cost per call.
const BASE_GAS: u64 = 5_000;

/// Minimum input length: 4 bytes selector + 32 bytes dest + 32 bytes value.
const MIN_INPUT_LEN: usize = 4 + 32 + 32;

// ─────────────────────────────────────────────────────────────────────────────

pub struct BalancesPrecompile<T>(PhantomData<T>);

impl<T> Precompile for BalancesPrecompile<T>
where
	T: pallet_evm::Config + pallet_balances::Config,
	T::AccountId: From<[u8; 32]>,
	<T as pallet_balances::Config>::Balance: TryFrom<u128>,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
	pallet_balances::Pallet<T>:
		Mutate<T::AccountId, Balance = <T as pallet_balances::Config>::Balance>,
{
	fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
		// Charge base gas first so DoS attempts are not free.
		handle
			.record_cost(BASE_GAS)
			.map_err(|e| PrecompileFailure::Error { exit_status: e })?;

		let input = handle.input();

		if input.len() < 4 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("input too short: missing selector".into()),
			});
		}

		let selector: [u8; 4] = input[0..4].try_into().unwrap();

		match selector {
			SEL_TRANSFER => Self::do_transfer(handle, false),
			SEL_TRANSFER_KEEP_ALIVE => Self::do_transfer(handle, true),
			_ => Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("unknown selector".into()),
			}),
		}
	}
}

impl<T> BalancesPrecompile<T>
where
	T: pallet_evm::Config + pallet_balances::Config,
	T::AccountId: From<[u8; 32]>,
	<T as pallet_balances::Config>::Balance: TryFrom<u128>,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
	pallet_balances::Pallet<T>:
		Mutate<T::AccountId, Balance = <T as pallet_balances::Config>::Balance>,
{
	/// Decode input, resolve caller, and perform the balance transfer.
	///
	/// Input layout after the 4-byte selector:
	/// ```text
	/// [  0.. 32] bytes32  dest    — recipient AccountId32
	/// [ 32.. 64] uint256  value   — amount (must fit in u128)
	/// ```
	fn do_transfer(handle: &mut impl PrecompileHandle, keep_alive: bool) -> PrecompileResult {
		let input = handle.input();

		if input.len() < MIN_INPUT_LEN {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("input too short: expected bytes32 + uint256".into()),
			});
		}

		// Decode dest (bytes32 → AccountId32).
		let dest_bytes: [u8; 32] = input[4..36].try_into().unwrap();
		let dest: T::AccountId = dest_bytes.into();

		// Decode value (uint256 big-endian, reject anything > u128::MAX).
		let value_bytes: [u8; 32] = input[36..68].try_into().unwrap();

		// The high 16 bytes must all be zero for the value to fit in u128.
		if value_bytes[..16].iter().any(|&b| b != 0) {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("value overflows u128".into()),
			});
		}
		let value_u128 = u128::from_be_bytes(value_bytes[16..32].try_into().unwrap());

		let value: <T as pallet_balances::Config>::Balance =
			value_u128
				.try_into()
				.map_err(|_| PrecompileFailure::Error {
					exit_status: ExitError::Other("value conversion failed".into()),
				})?;

		// Resolve the EVM caller to a Substrate AccountId.
		let caller_h160: H160 = handle.context().caller;
		let caller: T::AccountId =
			<T as pallet_evm::Config>::AddressMapping::into_account_id(caller_h160).into();

		let preservation = if keep_alive {
			Preservation::Preserve
		} else {
			Preservation::Expendable
		};

		<pallet_balances::Pallet<T> as Mutate<T::AccountId>>::transfer(
			&caller,
			&dest,
			value,
			preservation,
		)
		.map_err(|e| PrecompileFailure::Error {
			exit_status: ExitError::Other(alloc::format!("transfer failed: {e:?}").into()),
		})?;

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output: alloc::vec![],
		})
	}
}
