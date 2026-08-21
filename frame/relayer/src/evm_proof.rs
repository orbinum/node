//! Proof that a substrate account controls an EVM address.
//!
//! `register_relayer` is self-service, so the account-set gate alone would let one
//! approved validator claim another's EVM address — the address is public (it is
//! the `caller` of every relay transaction), and the registry is
//! first-come-first-served. Squatting a rival's address would divert its relay
//! fees and, because `AlreadyRegistered` is permanent, lock the rightful owner
//! out entirely.
//!
//! Requiring a signature from the EVM key closes that: only the holder of the
//! private key can produce one.
//!
//! The signed message binds three things:
//!
//! - a domain tag, so a signature cannot be lifted from another protocol;
//! - the genesis hash, so a signature cannot be replayed onto a different chain;
//! - the registering `AccountId`, so a signature observed on-chain cannot be
//!   replayed by a *different* account for the same address.
//!
//! Deliberately absent: a nonce. The `(account, address)` pair can only be
//! registered once — `AccountAlreadyRegistered` and `AlreadyRegistered` reject a
//! second attempt — so a captured signature buys an attacker nothing.
//!
//! ## Contents
//!
//! Everything the scheme needs lives here, so it can be audited in one file:
//!
//! | Item | Role |
//! |------|------|
//! | [`binding_digest`] | the exact bytes a claimant must sign |
//! | [`genesis_hash`] | the chain-binding input to that digest |
//! | [`recover_evm_address`] | who signed it |
//! | [`evm_address_from_uncompressed`] | the one place a key becomes an address |
//! | [`is_usable_relay_address`] | which addresses may be claimed at all |
//!
//! The pallet contributes only the policy wrapper: it turns a `false` from
//! [`is_usable_relay_address`] into `Error::InvalidEvmAddress` and a mismatched
//! recovery into `Error::BadEvmSignature`.

use frame_support::pallet_prelude::*;
use sp_core::{H160, H256};
use sp_io::hashing::keccak_256;

/// Domain separator. Any change invalidates every previously issued signature.
pub const BINDING_DOMAIN: &[u8] = b"orbinum-relayer-bind:v1:";

/// A 65-byte recoverable secp256k1 signature (`r || s || v`), as produced by
/// `personal_sign` / `eth_sign` and by `EthValidatorSigner`.
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, PartialEq, Eq, TypeInfo)]
pub struct EvmSignature(pub [u8; 65]);

impl core::fmt::Debug for EvmSignature {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		// Signatures are public data, but full bytes add nothing to a log line.
		write!(f, "EvmSignature(0x{:02x}{:02x}…)", self.0[0], self.0[1])
	}
}

/// The genesis hash, which binds a signature to one chain.
///
/// Lives here rather than in the pallet because it is an input to the digest,
/// and the whole scheme is easier to audit when every part of it is in one file.
pub fn genesis_hash<T: frame_system::Config>() -> H256 {
	let genesis = frame_system::BlockHash::<T>::get(<frame_system::pallet_prelude::BlockNumberFor<
		T,
	>>::from(0u32));
	H256::from_slice(genesis.as_ref())
}

/// Build the 32-byte digest the EVM key must sign.
///
/// Wrapped in the EIP-191 `personal_sign` envelope so an operator can produce it
/// with any standard wallet, and so the bytes can never be mistaken for a
/// serialized Ethereum transaction.
pub fn binding_digest(account: &[u8], evm_address: &H160, genesis: &H256) -> [u8; 32] {
	let mut payload = sp_std::vec::Vec::with_capacity(
		BINDING_DOMAIN.len() + 1 + account.len() + H160::len_bytes() + H256::len_bytes(),
	);
	payload.extend_from_slice(BINDING_DOMAIN);
	payload.extend_from_slice(genesis.as_bytes());
	// Length-prefix the account: it is the only variable-length field, and
	// without this a runtime whose AccountId is not 32 bytes could produce the
	// same payload from two different (account, address) pairs.
	payload.push(account.len() as u8);
	payload.extend_from_slice(account);
	payload.extend_from_slice(evm_address.as_bytes());

	// EIP-191: "\x19Ethereum Signed Message:\n" || len(payload) || payload
	let mut prefixed = sp_std::vec::Vec::new();
	prefixed.extend_from_slice(b"\x19Ethereum Signed Message:\n");
	prefixed.extend_from_slice(int_to_ascii(payload.len()).as_slice());
	prefixed.extend_from_slice(&payload);
	keccak_256(&prefixed)
}

/// Decimal ASCII for the EIP-191 length field, without `alloc::format!`.
fn int_to_ascii(mut n: usize) -> sp_std::vec::Vec<u8> {
	if n == 0 {
		return sp_std::vec![b'0'];
	}
	let mut out = sp_std::vec::Vec::new();
	while n > 0 {
		out.push(b'0' + (n % 10) as u8);
		n /= 10;
	}
	out.reverse();
	out
}

/// Highest address in the range reserved for runtime-provided contracts.
///
/// Frontier places precompiles at low addresses (`0x1`..`0x5` for the Ethereum
/// standard set, `0x400`+ and `0x800`+ for chain-specific ones). Treating the
/// whole `0x0..=0xffff` block as reserved is deliberately broader than the set
/// actually in use, so adding a precompile later cannot collide with an address
/// somebody already registered.
const RESERVED_ADDRESS_CEILING: u64 = 0xffff;

/// Whether an address can legitimately identify a relayer.
///
/// Rejects the zero address and the reserved precompile range: those are never
/// the `caller` of a real EVM transaction, because their "calls" originate inside
/// the runtime rather than from a key anybody holds. Neither could produce a
/// valid ownership proof either — checking up front turns a puzzling signature
/// failure into a clear one.
pub fn is_usable_relay_address(evm_address: &H160) -> bool {
	let bytes = evm_address.to_fixed_bytes();
	let high_bytes_clear = bytes[..12].iter().all(|b| *b == 0);
	if !high_bytes_clear {
		return true;
	}
	let low = u64::from_be_bytes(
		bytes[12..20]
			.try_into()
			.expect("H160 is 20 bytes; slice [12..20] is 8; qed"),
	);
	low > RESERVED_ADDRESS_CEILING
}

/// Recover the signer of `digest` and return its EVM address.
///
/// Returns `None` when the signature is malformed or recovery fails.
pub fn recover_evm_address(signature: &EvmSignature, digest: &[u8; 32]) -> Option<H160> {
	// secp256k1_ecdsa_recover wants v in {0,1}; wallets emit 27/28.
	let mut sig = signature.0;
	match sig[64] {
		27 | 28 => sig[64] -= 27,
		0 | 1 => {}
		_ => return None,
	}

	let pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig, digest).ok()?;
	Some(evm_address_from_uncompressed(&pubkey))
}

/// The Ethereum address of a secp256k1 public key: the low 20 bytes of the
/// keccak hash of its 64-byte uncompressed form.
///
/// `pubkey` must be those 64 bytes **without** the `0x04` tag that SEC1
/// serialisation prepends — which is exactly what `secp256k1_ecdsa_recover`
/// returns. Callers holding a tagged 65-byte key pass `&tagged[1..]`.
///
/// Every derivation of an EVM address from a key goes through here. Three copies
/// of this five-line expression previously lived in the pallet, the node RPC and
/// the test helper; a divergence between them would only surface as a signature
/// that mysteriously fails to verify.
pub fn evm_address_from_uncompressed(pubkey: &[u8; 64]) -> H160 {
	H160::from_slice(&keccak_256(pubkey)[12..])
}

#[cfg(test)]
mod tests {
	extern crate alloc;

	use super::*;
	/// Reference vector, reproduced independently in JavaScript by the operator
	/// tooling. If this value changes, every previously issued signature stops
	/// verifying — so a change must be deliberate and paired with a new domain
	/// tag in [`BINDING_DOMAIN`].
	const REFERENCE_DIGEST_HEX: &str =
		"188f4aff785e76ccb05f7c733a0fcf92937ab6aa792a7590d301d8fc36dbd469";

	/// The same digest signed by `@noble/curves` with key `0xb0..b0`, pinning
	/// interoperability with non-Rust signers.
	const REFERENCE_SIGNATURE_HEX: &str = "b6715dae2294272a89df32dc7bb42aa76acafa7ac812231bc2d51f7e015476ef\
	                                       0b7ddd1349e42b4929468bfebff107cbf09a164c53a0b6d06eb130b5322b3f2d00";

	/// The EVM address of that key.
	const REFERENCE_ADDRESS_HEX: &str = "af295d3c842bc1145e818d7fef2c929726625620";

	fn from_hex<const N: usize>(s: &str) -> [u8; N] {
		let clean: sp_std::vec::Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
		let mut out = [0u8; N];
		for (i, byte) in out.iter_mut().enumerate() {
			let hi = clean[i * 2].to_digit(16).unwrap() as u8;
			let lo = clean[i * 2 + 1].to_digit(16).unwrap() as u8;
			*byte = (hi << 4) | lo;
		}
		out
	}

	/// Pins the digest against an independent implementation. The operator's
	/// tooling reproduces these bytes in JavaScript; if this value changes, every
	/// previously issued signature stops verifying, so a change must be
	/// deliberate and paired with a new domain tag.
	#[test]
	fn digest_matches_the_reference_vector() {
		let account: [u8; 32] =
			from_hex("8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48");
		let digest = binding_digest(&account, &H160::repeat_byte(0xbb), &H256::zero());
		assert_eq!(digest, from_hex::<32>(REFERENCE_DIGEST_HEX));
	}

	/// An account of a different length must not be able to collide with the
	/// reference, which is what the length prefix buys.
	#[test]
	fn accounts_of_different_lengths_cannot_collide() {
		let short = [0xaau8; 4];
		let long = [0xaau8; 8];
		assert_ne!(
			binding_digest(&short, &H160::zero(), &H256::zero()),
			binding_digest(&long, &H160::zero(), &H256::zero()),
		);
	}

	/// Recovery must interoperate with non-Rust signers: this signature was
	/// produced by @noble/curves over the digest above.
	#[test]
	fn recovers_an_externally_produced_signature() {
		let digest: [u8; 32] = from_hex(REFERENCE_DIGEST_HEX);
		let sig: [u8; 65] = from_hex(REFERENCE_SIGNATURE_HEX);
		assert_eq!(
			recover_evm_address(&EvmSignature(sig), &digest),
			Some(H160(from_hex(REFERENCE_ADDRESS_HEX))),
		);
	}

	#[test]
	fn a_wallet_style_recovery_id_is_normalised() {
		let digest: [u8; 32] = from_hex(REFERENCE_DIGEST_HEX);
		let mut sig: [u8; 65] = from_hex(REFERENCE_SIGNATURE_HEX);
		sig[64] += 27; // 0 -> 27, the form wallets emit
		assert_eq!(
			recover_evm_address(&EvmSignature(sig), &digest),
			Some(H160(from_hex(REFERENCE_ADDRESS_HEX))),
		);
	}

	#[test]
	fn an_invalid_recovery_id_is_rejected_without_panicking() {
		let digest = [0u8; 32];
		let mut sig = [0u8; 65];
		sig[64] = 200;
		assert_eq!(recover_evm_address(&EvmSignature(sig), &digest), None);
	}

	// ── is_usable_relay_address ──────────────────────────────────────────────

	#[test]
	fn the_zero_address_is_not_usable() {
		assert!(!is_usable_relay_address(&H160::zero()));
	}

	#[test]
	fn the_reserved_precompile_range_is_not_usable() {
		// Boundaries and a sample of the addresses actually in use.
		for raw in [1u64, 5, 0x400, 0x801, 0x802, RESERVED_ADDRESS_CEILING] {
			assert!(
				!is_usable_relay_address(&H160::from_low_u64_be(raw)),
				"{raw:#x} must be rejected",
			);
		}
	}

	#[test]
	fn the_first_address_past_the_reserved_range_is_usable() {
		assert!(is_usable_relay_address(&H160::from_low_u64_be(
			RESERVED_ADDRESS_CEILING + 1
		)));
	}

	#[test]
	fn a_high_address_whose_low_bytes_look_reserved_is_usable() {
		// Only the whole 20-byte value is reserved, not its low 8 bytes: a real
		// address ending in 0x…01 must not be mistaken for precompile 0x1.
		let mut bytes = [0u8; 20];
		bytes[0] = 0x01;
		bytes[19] = 0x01;
		assert!(is_usable_relay_address(&H160(bytes)));
	}

	#[test]
	fn a_realistic_address_is_usable() {
		assert!(is_usable_relay_address(&H160(from_hex(
			REFERENCE_ADDRESS_HEX
		))));
	}

	// ── evm_address_from_uncompressed ────────────────────────────────────────

	#[test]
	fn address_derivation_takes_the_low_20_bytes_of_the_keccak_hash() {
		let pubkey = [0x11u8; 64];
		let expected = &sp_io::hashing::keccak_256(&pubkey)[12..];
		assert_eq!(evm_address_from_uncompressed(&pubkey).as_bytes(), expected,);
	}

	#[test]
	fn address_derivation_agrees_with_recovery() {
		// The two paths that produce an address must never disagree, or a proof
		// would verify against an address the signer does not think it owns.
		let digest: [u8; 32] = from_hex(REFERENCE_DIGEST_HEX);
		let sig: [u8; 65] = from_hex(REFERENCE_SIGNATURE_HEX);
		let recovered = recover_evm_address(&EvmSignature(sig), &digest).unwrap();
		assert_eq!(recovered, H160(from_hex(REFERENCE_ADDRESS_HEX)));
	}

	// ── EIP-191 length encoding ──────────────────────────────────────────────

	#[test]
	fn int_to_ascii_matches_decimal_formatting() {
		for n in [0usize, 1, 9, 10, 99, 100, 108, 255, 1000] {
			assert_eq!(
				int_to_ascii(n),
				alloc::format!("{n}").into_bytes(),
				"decimal encoding of {n}",
			);
		}
	}

	// ── binding_digest ───────────────────────────────────────────────────────

	#[test]
	fn the_digest_is_bound_to_account_address_and_chain() {
		let base: [u8; 32] = [1u8; 32];
		let addr = H160::repeat_byte(0xaa);
		let genesis = H256::repeat_byte(0x11);
		let reference = binding_digest(&base, &addr, &genesis);

		// Changing any one input must change the digest, or a signature could be
		// replayed across accounts, addresses or chains.
		assert_ne!(reference, binding_digest(&[2u8; 32], &addr, &genesis));
		assert_ne!(
			reference,
			binding_digest(&base, &H160::repeat_byte(0xab), &genesis)
		);
		assert_ne!(
			reference,
			binding_digest(&base, &addr, &H256::repeat_byte(0x12))
		);
	}
}
