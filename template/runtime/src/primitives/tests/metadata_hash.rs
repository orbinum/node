//! `CheckMetadataHash` in disabled mode.

use crate::{
	test_utils::{signed_extra, with_ext},
	Runtime,
};

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

/// The full `SignedExtra` tuple, `CheckMetadataHash` included, round-trips.
#[test]
fn signed_extra_with_check_metadata_hash_round_trips() {
	use crate::SignedExtra;
	use scale_codec::{Decode, Encode};

	with_ext(|| {
		let extra = signed_extra(0, 0);

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

/// `SignedPayload::new` computes every extension's implicit data, `CheckMetadataHash`'s
/// included.
#[test]
fn signed_extra_implicit_succeeds_with_check_metadata_hash() {
	use crate::RuntimeCall;

	with_ext(|| {
		// An immortal `CheckEra` reads `BlockHash[0]`; without it the payload fails
		// with `AncientBirthBlock`.
		frame_system::BlockHash::<Runtime>::insert(0u32, sp_core::H256::default());

		let extra = signed_extra(0, 0);

		let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
		crate::SignedPayload::new(call, extra)
			.expect("SignedPayload::new must succeed with disabled CheckMetadataHash");
	});
}
