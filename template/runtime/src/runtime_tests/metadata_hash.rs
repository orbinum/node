//! `CheckMetadataHash` in disabled mode.

use super::with_ext;
use crate::Runtime;

/// Every signed extension at its default, with `CheckMetadataHash` disabled.
fn signed_extra() -> crate::SignedExtra {
	(
		frame_system::CheckNonZeroSender::new(),
		frame_system::CheckSpecVersion::new(),
		frame_system::CheckTxVersion::new(),
		frame_system::CheckGenesis::new(),
		frame_system::CheckEra::from(sp_runtime::generic::Era::Immortal),
		frame_system::CheckNonce::from(0u32),
		frame_system::CheckWeight::new(),
		pallet_transaction_payment::ChargeTransactionPayment::from(0u128),
		frame_metadata_hash_extension::CheckMetadataHash::new(false),
	)
}

/// Disabled mode (`enable = false`) must encode as the single byte 0x00.
#[test]
fn check_metadata_hash_disabled_mode_encodes_as_zero() {
	use frame_metadata_hash_extension::CheckMetadataHash;
	use scale_codec::Encode;

	let ext = CheckMetadataHash::<Runtime>::new(false);
	assert_eq!(
		ext.encode(),
		vec![0x00u8],
		"CheckMetadataHash disabled mode must encode as 0x00"
	);
}

/// Disabled mode must decode back from its own encoding.
#[test]
fn check_metadata_hash_disabled_mode_round_trips() {
	use frame_metadata_hash_extension::CheckMetadataHash;
	use scale_codec::{Decode, Encode};

	let original = CheckMetadataHash::<Runtime>::new(false);
	let encoded = original.encode();
	let decoded = CheckMetadataHash::<Runtime>::decode(&mut &encoded[..])
		.expect("decoding of a disabled CheckMetadataHash must succeed");
	assert_eq!(
		encoded,
		decoded.encode(),
		"encode(decode(encode(x))) must equal encode(x)"
	);
}

/// `implicit()` in disabled mode must succeed and return `None`.
/// Uses UFCS because `TransactionExtension` is parameterised by `Call`.
#[test]
fn check_metadata_hash_implicit_is_none_when_disabled() {
	use frame_metadata_hash_extension::CheckMetadataHash;
	use sp_runtime::traits::TransactionExtension;

	with_ext(|| {
		let ext = CheckMetadataHash::<Runtime>::new(false);
		let result =
			<CheckMetadataHash<Runtime> as TransactionExtension<crate::RuntimeCall>>::implicit(
				&ext,
			)
			.expect("implicit must not fail in disabled mode");
		assert_eq!(result, None, "disabled mode must produce None");
	});
}

/// The full `SignedExtra` tuple (including `CheckMetadataHash`) must
/// encode and decode correctly.
#[test]
fn signed_extra_with_check_metadata_hash_round_trips() {
	use crate::SignedExtra;
	use scale_codec::{Decode, Encode};

	with_ext(|| {
		let extra = signed_extra();

		let encoded = extra.encode();
		let decoded =
			SignedExtra::decode(&mut &encoded[..]).expect("SignedExtra must round-trip via codec");
		assert_eq!(
			encoded,
			decoded.encode(),
			"SignedExtra including CheckMetadataHash must be codec-stable"
		);
	});
}

/// `SignedExtra` with `CheckMetadataHash` must be constructable and its `implicit()`
/// (via `SignedPayload::new`) must succeed without errors.
/// `CheckEra::implicit()` looks up the genesis block hash from storage, so we must
/// seed it before calling `SignedPayload::new`.
#[test]
fn signed_extra_implicit_succeeds_with_check_metadata_hash() {
	use crate::RuntimeCall;

	with_ext(|| {
		// CheckEra::implicit() for Era::Immortal reads BlockHash[0] from storage.
		// Seed it so the call does not fail with AncientBirthBlock.
		frame_system::BlockHash::<Runtime>::insert(0u32, sp_core::H256::default());

		let extra = signed_extra();

		let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
		crate::SignedPayload::new(call, extra)
			.expect("SignedPayload::new must succeed with disabled CheckMetadataHash");
	});
}
