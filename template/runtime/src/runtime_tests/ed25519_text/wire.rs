//! The signature's wire format and metadata shape, which clients depend on.

use super::*;
use scale_codec::MaxEncodedLen;
use sp_runtime::{traits::Verify, MultiSignature};

#[test]
fn discriminants_and_lengths_are_stable() {
	use sp_core::{ecdsa, sr25519};

	let (pair, _) = keypair();
	let sig = pair.sign(b"wire");

	// 0x00 decodes as `Ed25519`, kept for the metadata; it never verifies.
	let raw = OrbinumSignature::Ed25519(sig).encode();
	assert_eq!(raw, MultiSignature::Ed25519(sig).encode());

	let sr = sr25519::Signature::from_raw([1u8; 64]);
	assert_eq!(
		OrbinumSignature::Sr25519(sr).encode(),
		MultiSignature::Sr25519(sr).encode()
	);
	let ec = ecdsa::Signature::from_raw([2u8; 65]);
	assert_eq!(
		OrbinumSignature::Ecdsa(ec).encode(),
		MultiSignature::Ecdsa(ec).encode()
	);

	for (tag, variant) in [
		(0x03u8, OrbinumSignature::Ed25519Text(sig)),
		(0x04u8, OrbinumSignature::Ed25519WrappedText(sig)),
	] {
		let encoded = variant.encode();
		assert_eq!(encoded[0], tag);
		assert_eq!(&encoded[1..], &sig.0[..]);
		assert_eq!(
			OrbinumSignature::decode(&mut &encoded[..]).unwrap(),
			variant
		);
	}

	let unknown = [&[0x05u8][..], &sig.0[..]].concat();
	assert!(OrbinumSignature::decode(&mut &unknown[..]).is_err());

	assert_eq!(OrbinumSignature::max_encoded_len(), 66);
}

/// polkadot-api builds no extrinsic for a signature enum lacking `Ed25519`, `Sr25519` or
/// `Ecdsa`, and tags them with the fixed indices 0, 1 and 2.
#[test]
fn signature_metadata_keeps_the_shape_polkadot_api_requires() {
	use scale_info::{TypeDef, TypeInfo};

	let TypeDef::Variant(def) = OrbinumSignature::type_info().type_def else {
		panic!("OrbinumSignature is not an enum in the metadata");
	};
	let index_of = |name: &str| {
		def.variants
			.iter()
			.find(|v| v.name == name)
			.map(|v| v.index)
	};
	assert_eq!(index_of("Ed25519"), Some(0));
	assert_eq!(index_of("Sr25519"), Some(1));
	assert_eq!(index_of("Ecdsa"), Some(2));
	assert_eq!(index_of("Ed25519Text"), Some(3));
	assert_eq!(index_of("Ed25519WrappedText"), Some(4));
}

#[test]
fn a_valid_raw_ed25519_signature_never_verifies() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let (pair, account) = keypair();
		let sig = pair.sign(&SHORT_PAYLOAD);
		assert!(sp_io::crypto::ed25519_verify(
			&sig,
			&SHORT_PAYLOAD,
			&pair.public()
		));
		assert!(!OrbinumSignature::Ed25519(sig).verify(&SHORT_PAYLOAD[..], &account));
	});
}
