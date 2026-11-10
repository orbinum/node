//! The Ethereum RPC API's `call` and `create`, as `eth_call`, `eth_estimateGas` and
//! contract deployment reach them.

use crate::{
	test_utils::{with_dev_chain, ALITH_ADDRESS},
	Block, Runtime,
};
use fp_evm::{ExitReason, ExitSucceed};
use fp_rpc::runtime_decl_for_ethereum_runtime_rpc_api::EthereumRuntimeRPCApiV6;
use sp_core::{H160, U256};

fn call(
	gas_limit: U256,
	estimate: bool,
) -> Result<pallet_evm::CallInfo, sp_runtime::DispatchError> {
	<Runtime as EthereumRuntimeRPCApiV6<Block>>::call(
		H160(ALITH_ADDRESS),
		H160::repeat_byte(0xb0),
		Vec::new(),
		U256::from(1_000u64),
		gas_limit,
		None,
		None,
		None,
		estimate,
		None,
		None,
	)
}

#[test]
fn a_transfer_call_uses_its_intrinsic_gas() {
	with_dev_chain(|| {
		for estimate in [false, true] {
			let info = call(U256::from(21_000u64), estimate).expect("the call runs");
			assert_eq!(info.exit_reason, ExitReason::Succeed(ExitSucceed::Stopped));
			assert_eq!(info.used_gas.standard, U256::from(21_000u64), "{estimate}");
		}
	});
}

/// A gas limit past `u64` is clamped, not truncated: `2^64 + 20_000` runs with
/// the block gas limit, where its low 64 bits would be below a transfer's
/// intrinsic gas.
#[test]
fn a_gas_limit_past_u64_is_clamped_not_truncated() {
	with_dev_chain(|| {
		let succeeds = |gas_limit, estimate| {
			call(gas_limit, estimate)
				.is_ok_and(|info| matches!(info.exit_reason, ExitReason::Succeed(_)))
		};
		assert!(!succeeds(U256::from(20_000u64), false));
		assert!(succeeds((U256::one() << 64) + U256::from(20_000u64), false));
		assert!(succeeds(U256::MAX, true));
	});
}

/// The API caps a call at one block's gas whatever it asks for: `state_call`
/// reaches it without the RPC's own cap. Init code that loops runs out of gas
/// after one block's worth, not twenty.
#[test]
fn a_call_never_runs_past_the_block_gas_limit() {
	with_dev_chain(|| {
		let block = <Runtime as pallet_evm::Config>::BlockGasLimit::get();
		// JUMPDEST PUSH1 0 JUMP: loops until the gas runs out.
		let looping = vec![0x5b, 0x60, 0x00, 0x56];
		let info = <Runtime as EthereumRuntimeRPCApiV6<Block>>::create(
			H160::repeat_byte(0x11),
			looping,
			U256::zero(),
			block * 20,
			None,
			None,
			None,
			false,
			None,
			None,
		)
		.expect("the creation runs");
		assert_eq!(
			info.exit_reason,
			ExitReason::Error(fp_evm::ExitError::OutOfGas)
		);
		assert_eq!(info.used_gas.standard, block);
	});
}

#[test]
fn create_deploys_init_code() {
	with_dev_chain(|| {
		// PUSH1 0 PUSH1 0 RETURN: deploys empty code.
		let init = vec![0x60, 0x00, 0x60, 0x00, 0xf3];
		for estimate in [false, true] {
			let info = <Runtime as EthereumRuntimeRPCApiV6<Block>>::create(
				H160(ALITH_ADDRESS),
				init.clone(),
				U256::zero(),
				U256::from(100_000u64),
				None,
				None,
				None,
				estimate,
				None,
				None,
			)
			.expect("the creation runs");
			assert_eq!(info.exit_reason, ExitReason::Succeed(ExitSucceed::Returned));
			assert_ne!(info.value, H160::zero());
		}
	});
}
