//! Tests for `pallet-evm-precompile-balances`, one module per concern:
//!
//! | Module     | What it verifies                                                  |
//! |------------|-------------------------------------------------------------------|
//! | `abi`      | Selector and calldata decoding, exact length, u128 bound          |
//! | `guard`    | Static, delegated and value-carrying calls are refused            |
//! | `dispatch` | Transfers move balances; weight, proof size and storage are paid  |
//! |            | up front, failing transfers included; failures revert with reason |

mod abi;
mod dispatch;
mod guard;

use crate::{mock::MockHandle, BalancesPrecompile, SEL_TRANSFER};
use fp_evm::{Precompile, PrecompileFailure, PrecompileResult};

pub(super) type Precompiled = BalancesPrecompile<crate::mock::Test>;

/// `selector ‖ dest ‖ uint256(value)`.
pub(super) fn encode_transfer(selector: [u8; 4], dest: [u8; 32], value: u128) -> Vec<u8> {
	let mut input = selector.to_vec();
	input.extend_from_slice(&dest);
	input.extend_from_slice(&[0u8; 16]);
	input.extend_from_slice(&value.to_be_bytes());
	input
}

pub(super) fn run(handle: &mut MockHandle) -> PrecompileResult {
	Precompiled::execute(handle)
}

pub(super) fn transfer_handle(dest: [u8; 32], value: u128) -> MockHandle {
	MockHandle::new(encode_transfer(SEL_TRANSFER, dest, value))
}

/// The `Error(string)` reason of a revert; panics on any other outcome, so a
/// test also proves the failure is a revert (unused gas returned), not an
/// `Error` exit that burns the caller's whole gas limit.
pub(super) fn revert_reason(result: PrecompileResult) -> String {
	match result {
		Err(PrecompileFailure::Revert { output, .. }) => {
			// Error(string): selector ‖ offset ‖ length ‖ bytes.
			assert_eq!(
				&output[..4],
				&[0x08, 0xc3, 0x79, 0xa0],
				"not an Error(string)"
			);
			let len = u32::from_be_bytes(output[64..68].try_into().unwrap()) as usize;
			String::from_utf8(output[68..68 + len].to_vec()).unwrap()
		}
		other => panic!("expected a revert, got {other:?}"),
	}
}
