//! Sr25519 verification.

use sp_core::sr25519::{Public, Signature};

/// The Ristretto identity, the group's only small-order element: under it `R = 0, s = 0`
/// verifies any message.
const IDENTITY: [u8; 32] = [0; 32];

pub(super) fn verify(sig: &Signature, msg: &[u8], key: &[u8; 32]) -> bool {
	*key != IDENTITY && sp_io::crypto::sr25519_verify(sig, msg, &Public::from_raw(*key))
}
