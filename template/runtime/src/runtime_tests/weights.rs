use crate::{Runtime, WeightPerGas};

#[test]
fn configured_base_extrinsic_weight_is_evm_compatible() {
	let min_ethereum_transaction_weight = WeightPerGas::get() * 21_000;
	let base_extrinsic = <Runtime as frame_system::Config>::BlockWeights::get()
		.get(frame_support::dispatch::DispatchClass::Normal)
		.base_extrinsic;
	assert!(base_extrinsic.ref_time() <= min_ethereum_transaction_weight.ref_time());
}

/// Substrate fees price weight and bytes like EVM gas at the default base fee:
/// the weight of 21_000 gas costs what 21_000 gas does.
#[test]
fn substrate_fees_match_evm_gas() {
	use frame_support::weights::WeightToFee as _;

	let base_fee = crate::DefaultBaseFeePerGas::get().low_u128();
	assert_eq!(crate::WeightFee::get(), 50_000);
	assert_eq!(crate::LengthFee::get(), 16 * base_fee);

	let transfer = WeightPerGas::get() * 21_000;
	assert_eq!(
		<Runtime as pallet_transaction_payment::Config>::WeightToFee::weight_to_fee(&transfer),
		21_000 * base_fee
	);
}
