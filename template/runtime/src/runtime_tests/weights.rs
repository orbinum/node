use crate::{Runtime, WeightPerGas};

#[test]
fn configured_base_extrinsic_weight_is_evm_compatible() {
	let min_ethereum_transaction_weight = WeightPerGas::get() * 21_000;
	let base_extrinsic = <Runtime as frame_system::Config>::BlockWeights::get()
		.get(frame_support::dispatch::DispatchClass::Normal)
		.base_extrinsic;
	assert!(base_extrinsic.ref_time() <= min_ethereum_transaction_weight.ref_time());
}
