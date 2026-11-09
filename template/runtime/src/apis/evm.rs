//! What the Ethereum RPC API's `call` and `create` share: the encoded length they
//! charge proof size for, the gas limit as `u64`, the weight limit it implies, and
//! the EVM config for estimates.

use crate::Runtime;
use alloc::vec::Vec;
use ethereum::AuthorizationList;
use frame_support::weights::Weight;
use pallet_evm::{EvmConfig, GasWeightMapping};
use scale_codec::Encode;
use sp_core::{H160, H256, U256};

/// A `call`'s encoded transaction without its data, sized as the heaviest type
/// (EIP-7702) so the estimate holds for every type: pallet and call index (2), the
/// transaction variant (1), chain id (8), nonce, both fees, gas limit and value
/// (5 × 32), the action (21: variant and address), empty access and authorization
/// lists (2) and the signature (65).
pub(crate) const CALL_BASE_LEN: usize = 259;

/// A `create`'s encoded transaction without its data, fees and lists: from (20),
/// value, gas limit and nonce (3 × 32), the action variant (1), chain id (8) and the
/// signature (65).
pub(crate) const CREATE_BASE_LEN: usize = 190;

/// The access and authorization lists' share of the length, when given.
fn lists_len(
	access_list: &Option<Vec<(H160, Vec<H256>)>>,
	authorization_list: &Option<AuthorizationList>,
) -> usize {
	let mut len = 0;
	if access_list.is_some() {
		len += access_list.encoded_size();
	}
	if authorization_list.is_some() {
		len += authorization_list.encoded_size();
	}
	len
}

/// The estimated encoded length of a `call` with `data_len` bytes of data.
pub(crate) fn call_len(
	data_len: usize,
	access_list: &Option<Vec<(H160, Vec<H256>)>>,
	authorization_list: &Option<AuthorizationList>,
) -> usize {
	data_len + CALL_BASE_LEN + lists_len(access_list, authorization_list)
}

/// The estimated encoded length of a `create` with `data_len` bytes of init code;
/// each fee given adds 32 bytes.
pub(crate) fn create_len(
	data_len: usize,
	max_fee_per_gas: Option<U256>,
	max_priority_fee_per_gas: Option<U256>,
	access_list: &Option<Vec<(H160, Vec<H256>)>>,
	authorization_list: &Option<AuthorizationList>,
) -> usize {
	let fees = [max_fee_per_gas, max_priority_fee_per_gas]
		.iter()
		.filter(|fee| fee.is_some())
		.count();
	data_len + CREATE_BASE_LEN + 32 * fees + lists_len(access_list, authorization_list)
}

/// What the runner takes besides the transaction.
pub(crate) struct RunnerLimits {
	/// The requested gas limit, clamped to one block's gas.
	pub gas_limit: u64,
	/// The weight the gas limit maps to, when it carries proof size.
	pub weight_limit: Option<Weight>,
	/// The estimated encoded length, charged as proof size with `weight_limit`.
	pub proof_size_base_cost: Option<u64>,
	estimate_config: Option<EvmConfig>,
}

impl RunnerLimits {
	/// `gas_limit` is clamped to the block gas limit: the runtime API runs a call
	/// without the block and transaction checks, and `state_call` reaches it
	/// directly, past any cap an RPC applies.
	pub(crate) fn new(gas_limit: U256, estimated_len: usize, estimate: bool) -> Self {
		let gas_limit = gas_limit
			.min(<Runtime as pallet_evm::Config>::BlockGasLimit::get())
			.low_u64();
		let without_base_extrinsic_weight = true;
		let (weight_limit, proof_size_base_cost) =
			match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
				gas_limit,
				without_base_extrinsic_weight,
			) {
				weight_limit if weight_limit.proof_size() > 0 => {
					(Some(weight_limit), Some(estimated_len as u64))
				}
				_ => (None, None),
			};
		let estimate_config = estimate.then(|| {
			let mut config = <Runtime as pallet_evm::Config>::config().clone();
			config.estimate = true;
			config
		});
		Self {
			gas_limit,
			weight_limit,
			proof_size_base_cost,
			estimate_config,
		}
	}

	/// The runtime's EVM config, with `estimate` set for a gas estimate.
	pub(crate) fn config(&self) -> &EvmConfig {
		self.estimate_config
			.as_ref()
			.unwrap_or(<Runtime as pallet_evm::Config>::config())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn lengths_add_the_data_fees_and_lists_to_the_base() {
		assert_eq!(call_len(10, &None, &None), 10 + CALL_BASE_LEN);
		assert_eq!(
			create_len(10, None, None, &None, &None),
			10 + CREATE_BASE_LEN
		);
		assert_eq!(
			create_len(0, Some(U256::one()), Some(U256::one()), &None, &None),
			CREATE_BASE_LEN + 64
		);
		let access_list = Some(vec![(H160::zero(), vec![H256::zero()])]);
		assert_eq!(
			call_len(0, &access_list, &None),
			CALL_BASE_LEN + access_list.encoded_size()
		);
		assert_eq!(
			create_len(0, None, None, &access_list, &Some(Vec::new())),
			CREATE_BASE_LEN
				+ access_list.encoded_size()
				+ Some(AuthorizationList::new()).encoded_size()
		);
	}

	#[test]
	fn the_gas_limit_is_clamped_and_sets_the_weight_limit() {
		let block = <Runtime as pallet_evm::Config>::BlockGasLimit::get();
		assert!(block <= U256::from(u64::MAX));
		let limits = RunnerLimits::new(U256::MAX, 300, false);
		assert_eq!(U256::from(limits.gas_limit), block);
		let limits = RunnerLimits::new(block + 1, 300, false);
		assert_eq!(U256::from(limits.gas_limit), block);

		let limits = RunnerLimits::new(U256::from(21_000u64), 300, false);
		assert_eq!(limits.gas_limit, 21_000);
		let weight = <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(21_000, true);
		assert_eq!(limits.weight_limit, Some(weight));
		assert_eq!(limits.proof_size_base_cost, Some(300));
	}

	#[test]
	fn only_an_estimate_changes_the_config() {
		assert!(!RunnerLimits::new(U256::one(), 0, false).config().estimate);
		assert!(RunnerLimits::new(U256::one(), 0, true).config().estimate);
		assert!(!<Runtime as pallet_evm::Config>::config().estimate);
	}
}
