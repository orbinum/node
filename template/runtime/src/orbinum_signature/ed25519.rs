//! Ed25519 verification, shared by `Ed25519Text` and `Ed25519WrappedText`.

use hex_literal::hex;
use sp_core::ed25519::{Public, Signature};

/// Every encoding (canonical or not) of the small-order points of edwards25519, compared
/// with the sign bit cleared (libsodium's `has_small_order` list). `ed25519_verify`
/// follows ZIP-215, under which such a key accepts a forged signature for any message.
const SMALL_ORDER_KEYS: [[u8; 32]; 7] = [
	hex!("0000000000000000000000000000000000000000000000000000000000000000"),
	hex!("0100000000000000000000000000000000000000000000000000000000000000"),
	hex!("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	hex!("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
];

fn has_small_order(key: &[u8; 32]) -> bool {
	SMALL_ORDER_KEYS
		.iter()
		.any(|k| k[..31] == key[..31] && k[31] == key[31] & 0x7f)
}

pub(super) fn verify(sig: &Signature, msg: &[u8], key: &[u8; 32]) -> bool {
	!has_small_order(key) && sp_io::crypto::ed25519_verify(sig, msg, &Public::from_raw(*key))
}
