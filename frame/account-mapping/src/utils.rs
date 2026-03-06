extern crate alloc;
use alloc::vec::Vec;

use sp_core::H160;
use sp_io::{crypto::secp256k1_ecdsa_recover, hashing::keccak_256};

#[derive(Debug, PartialEq, Eq)]
pub enum AliasValidationError {
	TooShort,
	InvalidCharacters,
}

pub fn validate_alias(bytes: &[u8]) -> Result<(), AliasValidationError> {
	if bytes.len() < 3 {
		return Err(AliasValidationError::TooShort);
	}
	if !bytes
		.iter()
		.all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
	{
		return Err(AliasValidationError::InvalidCharacters);
	}
	Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
	RecoveryFailed,
	AddressMismatch,
}

pub fn eip191_message_hash(account_id_bytes: &[u8]) -> [u8; 32] {
	let mut message: Vec<u8> = b"\x19Ethereum Signed Message:\n32".to_vec();
	let msg_hash = keccak_256(account_id_bytes);
	message.extend_from_slice(&msg_hash);
	keccak_256(&message)
}

pub fn verify_ethereum_signature(
	expected_address: &[u8],
	account_id_bytes: &[u8],
	signature: &[u8; 65],
) -> Result<H160, SignatureError> {
	let final_hash = eip191_message_hash(account_id_bytes);

	let full_pubkey = secp256k1_ecdsa_recover(signature, &final_hash)
		.map_err(|_| SignatureError::RecoveryFailed)?;

	let addr_hash = keccak_256(&full_pubkey[..]);
	let recovered_addr = &addr_hash[12..];

	if recovered_addr == expected_address {
		let mut addr_bytes = [0u8; 20];
		addr_bytes.copy_from_slice(recovered_addr);
		Ok(H160::from(addr_bytes))
	} else {
		Err(SignatureError::AddressMismatch)
	}
}

pub fn verify_ed25519_signature(
	expected_address: &[u8],
	account_id_bytes: &[u8],
	signature: &[u8; 64],
) -> Result<(), SignatureError> {
	if sp_io::crypto::ed25519_verify(
		&sp_core::ed25519::Signature::from_raw(*signature),
		account_id_bytes,
		&sp_core::ed25519::Public::from_raw(
			expected_address
				.try_into()
				.map_err(|_| SignatureError::AddressMismatch)?,
		),
	) {
		Ok(())
	} else {
		Err(SignatureError::RecoveryFailed)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn validate_alias_rejects_short() {
		assert_eq!(validate_alias(b"ab"), Err(AliasValidationError::TooShort));
		assert_eq!(validate_alias(b""), Err(AliasValidationError::TooShort));
	}

	#[test]
	fn validate_alias_rejects_invalid_chars() {
		assert_eq!(
			validate_alias(b"Bad@Alias"),
			Err(AliasValidationError::InvalidCharacters)
		);
		assert_eq!(
			validate_alias(b"UPPER"),
			Err(AliasValidationError::InvalidCharacters)
		);
		assert_eq!(
			validate_alias(b"with space"),
			Err(AliasValidationError::InvalidCharacters)
		);
	}

	#[test]
	fn validate_alias_accepts_valid() {
		assert!(validate_alias(b"nolasco").is_ok());
		assert!(validate_alias(b"user_123").is_ok());
		assert!(validate_alias(b"abc").is_ok());
		assert!(validate_alias(b"0x0").is_ok());
	}
}
