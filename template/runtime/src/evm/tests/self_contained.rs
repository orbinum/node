//! Ethereum transactions as extrinsics: the RPC wraps one into a bare extrinsic
//! (`TransactionConverter`), and only `Ethereum::transact` is self-contained, signed by
//! the address its signature recovers.

use crate::{
	opaque,
	test_utils::{with_dev_chain, ALITH_KEY, CHAIN_ID},
	RuntimeCall, RuntimeOrigin, TransactionConverter, UncheckedExtrinsic,
};
use ethereum::{eip1559::EIP1559Transaction, eip2930::TransactionSignature, TransactionAction};
use fp_self_contained::SelfContainedCall;
use frame_support::{dispatch::GetDispatchInfo, traits::fungible::Inspect};
use pallet_ethereum::Transaction;
use scale_codec::{Decode, Encode};
use sp_core::{ecdsa, Pair, H160, H256, U256};
use sp_runtime::traits::{Dispatchable, ExtrinsicLike};

/// A value transfer of `value` wei to `to`, signed by `key` (EIP-1559).
pub(super) fn signed_transfer(key: &[u8; 32], nonce: u64, to: H160, value: u64) -> Transaction {
	let message = ethereum::EIP1559TransactionMessage {
		chain_id: CHAIN_ID,
		nonce: nonce.into(),
		max_priority_fee_per_gas: U256::zero(),
		max_fee_per_gas: U256::from(2_000_000_000u64),
		gas_limit: U256::from(21_000u64),
		action: TransactionAction::Call(to),
		value: value.into(),
		input: Vec::new(),
		access_list: Vec::new(),
	};
	let signature = ecdsa::Pair::from_seed(key).sign_prehashed(&message.hash().0);
	let raw = signature.0;
	Transaction::EIP1559(EIP1559Transaction {
		chain_id: message.chain_id,
		nonce: message.nonce,
		max_priority_fee_per_gas: message.max_priority_fee_per_gas,
		max_fee_per_gas: message.max_fee_per_gas,
		gas_limit: message.gas_limit,
		action: message.action,
		value: message.value,
		input: message.input,
		access_list: message.access_list,
		signature: TransactionSignature::new(
			raw[64] == 1,
			H256::from_slice(&raw[..32]),
			H256::from_slice(&raw[32..64]),
		)
		.expect("a canonical signature"),
	})
}

fn transact(transaction: Transaction) -> RuntimeCall {
	RuntimeCall::Ethereum(pallet_ethereum::Call::transact { transaction })
}

fn alith() -> H160 {
	H160(crate::test_utils::ALITH_ADDRESS)
}

#[test]
fn the_converter_wraps_a_transaction_into_a_bare_transact() {
	let transaction = signed_transfer(&ALITH_KEY, 0, H160::repeat_byte(0xb0), 1);
	let opaque: opaque::UncheckedExtrinsic =
		<TransactionConverter<opaque::Block> as fp_rpc::ConvertTransaction<_>>::convert_transaction(
			&TransactionConverter::default(),
			transaction.clone(),
		);
	let xt = UncheckedExtrinsic::decode(&mut &opaque.encode()[..]).expect("decodes");
	assert!(xt.is_bare());
	assert_eq!(xt.0.function, transact(transaction));
}

#[test]
fn only_ethereum_transact_is_self_contained() {
	let other = RuntimeCall::System(frame_system::Call::remark { remark: vec![1] });
	let info = other.get_dispatch_info();
	assert!(!other.is_self_contained());
	assert!(other.check_self_contained().is_none());
	assert!(other.validate_self_contained(&alith(), &info, 10).is_none());
	assert!(other
		.pre_dispatch_self_contained(&alith(), &info, 10)
		.is_none());
	assert!(other.apply_self_contained(alith()).is_none());

	let call = transact(signed_transfer(&ALITH_KEY, 0, H160::repeat_byte(0xb0), 1));
	assert!(call.is_self_contained());
}

/// The signer is the address the signature recovers; a tampered transaction recovers
/// another address or none.
#[test]
fn the_signer_is_the_recovered_address() {
	let transaction = signed_transfer(&ALITH_KEY, 0, H160::repeat_byte(0xb0), 1);
	assert_eq!(
		transact(transaction.clone()).check_self_contained(),
		Some(Ok(alith()))
	);
	let Transaction::EIP1559(mut tampered) = transaction else {
		unreachable!()
	};
	tampered.value = U256::from(2);
	match transact(Transaction::EIP1559(tampered)).check_self_contained() {
		Some(Ok(signer)) => assert_ne!(signer, alith()),
		Some(Err(_)) => {}
		None => panic!("a transact call is self-contained"),
	}
}

/// Validated and applied as its signer: the value moves from Alith's account.
#[test]
fn a_signed_transfer_validates_and_applies_as_its_signer() {
	with_dev_chain(|| {
		let to = H160::repeat_byte(0xb0);
		let call = transact(signed_transfer(&ALITH_KEY, 0, to, 1_000));
		let signer = call.check_self_contained().unwrap().unwrap();
		let info = call.get_dispatch_info();
		let len = call.encoded_size();
		assert!(matches!(
			call.validate_self_contained(&signer, &info, len),
			Some(Ok(_))
		));
		assert!(matches!(
			call.pre_dispatch_self_contained(&signer, &info, len),
			Some(Ok(()))
		));
		let result = call.apply_self_contained(signer).expect("self-contained");
		assert!(result.is_ok(), "{result:?}");
		let recipient = crate::evm_h160_to_account_id(to);
		assert_eq!(crate::Balances::balance(&recipient), 1_000);
		// Signed by an account instead, `transact` is refused.
		let as_account = RuntimeOrigin::signed(crate::evm_h160_to_account_id(alith()));
		assert!(transact(signed_transfer(&ALITH_KEY, 1, to, 1))
			.dispatch(as_account)
			.is_err());
	});
}
