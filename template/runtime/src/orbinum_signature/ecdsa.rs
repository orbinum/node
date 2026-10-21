//! ECDSA (secp256k1) verification and the EVM-compatible account.

use crate::{evm_account::evm_bytes_to_account_id_bytes, AccountId};
use hex_literal::hex;
use sp_core::ecdsa::Signature;

/// secp256k1 group order `n` halved, big-endian.
const HALF_ORDER: [u8; 32] =
	hex!("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

/// `[keccak256(pubkey)[12..] ‖ 0x00 × 12]` for the 64-byte uncompressed key without its
/// `0x04` prefix: the account `EeSuffixAddressMapping` gives the key's EVM address.
pub(super) fn account_from_pubkey(pub64: &[u8; 64]) -> AccountId {
	let hash = sp_io::hashing::keccak_256(pub64);
	let mut address = [0u8; 20];
	address.copy_from_slice(&hash[12..]);
	AccountId::from(evm_bytes_to_account_id_bytes(address))
}

/// The host also recovers the same key from `(r, n − s)` with the other recovery id, and
/// from `v + 27`; requiring a low `s` and the raw id (0–3) leaves one encoding.
fn is_canonical(sig: &[u8; 65]) -> bool {
	sig[32..64] <= HALF_ORDER[..] && sig[64] < 4
}

pub(super) fn verify(sig: &Signature, msg: &[u8], signer: &AccountId) -> bool {
	let sig: &[u8; 65] = sig.as_ref();
	if !is_canonical(sig) {
		return false;
	}
	sp_io::crypto::secp256k1_ecdsa_recover(sig, &sp_io::hashing::blake2_256(msg))
		.is_ok_and(|pub64| account_from_pubkey(&pub64) == *signer)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sig_with(s: [u8; 32], v: u8) -> [u8; 65] {
		let mut sig = [1u8; 65];
		sig[32..64].copy_from_slice(&s);
		sig[64] = v;
		sig
	}

	#[test]
	fn half_order_is_the_largest_canonical_s() {
		let mut above = HALF_ORDER;
		above[31] += 1;
		assert!(is_canonical(&sig_with(HALF_ORDER, 0)));
		assert!(!is_canonical(&sig_with(above, 0)));
		assert!(!is_canonical(&sig_with([0xff; 32], 0)));
	}

	#[test]
	fn only_raw_recovery_ids_are_canonical() {
		for v in 0..4 {
			assert!(is_canonical(&sig_with([0; 32], v)));
		}
		for v in [4, 26, 27, 28, 29, 30, 255] {
			assert!(!is_canonical(&sig_with([0; 32], v)));
		}
	}
}
