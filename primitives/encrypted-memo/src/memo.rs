//! Memo data types, errors, and ChaCha20-Poly1305 encryption.
//!
//! # Size layout
//!
//! ```text
//! Plaintext  (MemoData):  value(8) | owner_pk(32) | blinding(32) | asset_id(4) | counterparty_pk(32) = 108 bytes
//! Encrypted wire format:  nonce(12) | ciphertext(108) | MAC(16) | ephPk(32)                         = 168 bytes
//! ```

use alloc::vec::Vec;
use chacha20poly1305::{
	aead::{Aead, KeyInit},
	ChaCha20Poly1305, Nonce,
};

use crate::keys::derive_encryption_key;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Plaintext memo size: `value(8) + owner_pk(32) + blinding(32) + asset_id(4) + counterparty_pk(32)`
pub const MEMO_DATA_SIZE: usize = 108;

/// ChaCha20-Poly1305 nonce size.
pub const NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 MAC (authentication tag) size.
pub const MAC_SIZE: usize = 16;

/// Ephemeral BabyJubJub public key (packed LE) appended to the memo for ECDH recipient decryption.
pub const EPH_PK_SIZE: usize = 32;

/// Maximum encrypted memo size: `nonce(12) + ciphertext(108) + MAC(16) + ephPk(32)`
pub const MAX_ENCRYPTED_MEMO_SIZE: usize = NONCE_SIZE + MEMO_DATA_SIZE + MAC_SIZE + EPH_PK_SIZE;

/// Minimum encrypted memo size: `nonce(12) + MAC(16)` (zero-length plaintext)
pub const MIN_ENCRYPTED_MEMO_SIZE: usize = NONCE_SIZE + MAC_SIZE;

// ─── Error ────────────────────────────────────────────────────────────────────

/// All errors that can occur during encrypted memo operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoError {
	/// Encrypted data is too short (below minimum size).
	DataTooShort,
	/// Encrypted data exceeds maximum allowed size.
	DataTooLong,
	/// Decryption failed — wrong key or tampered data.
	DecryptionFailed,
	/// Encryption operation failed.
	EncryptionFailed,
	/// Invalid note data format during deserialization.
	InvalidNoteData,
	/// Commitment mismatch detected after decryption.
	CommitmentMismatch,
	/// Invalid disclosure mask configuration.
	InvalidDisclosureMask(&'static str),
	/// Invalid disclosed data format.
	InvalidDisclosureData,
	/// Invalid or inconsistent disclosure proof.
	InvalidProof(&'static str),
}

impl core::fmt::Display for MemoError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::DataTooShort => write!(f, "Encrypted data is too short"),
			Self::DataTooLong => write!(f, "Encrypted data exceeds maximum allowed size"),
			Self::DecryptionFailed => write!(f, "Decryption failed — wrong key or tampered data"),
			Self::EncryptionFailed => write!(f, "Encryption operation failed"),
			Self::InvalidNoteData => write!(f, "Invalid note data format"),
			Self::CommitmentMismatch => write!(f, "Commitment mismatch after decryption"),
			Self::InvalidDisclosureMask(msg) => write!(f, "Invalid disclosure mask: {msg}"),
			Self::InvalidDisclosureData => write!(f, "Invalid disclosed data format"),
			Self::InvalidProof(msg) => write!(f, "Invalid disclosure proof: {msg}"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for MemoError {}

// ─── MemoData ────────────────────────────────────────────────────────────────

/// Plaintext content of an encrypted note memo.
///
/// Serialized layout (108 bytes): `value(8) | owner_pk(32) | blinding(32) | asset_id(4) | counterparty_pk(32)`
///
/// `counterparty_pk` is the BabyJubJub Ax coordinate of the other party in the transaction
/// (recipient's key in the change note; sender's key in the output note). Zero for shield/unshield.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
	all(feature = "parity-scale-codec", feature = "scale-info"),
	derive(
		parity_scale_codec::Encode,
		parity_scale_codec::Decode,
		scale_info::TypeInfo
	)
)]
pub struct MemoData {
	/// Token amount in the note.
	pub value: u64,
	/// Owner's public key (32 bytes).
	pub owner_pk: [u8; 32],
	/// Random blinding factor (32 bytes).
	pub blinding: [u8; 32],
	/// Asset identifier (0 = native token).
	pub asset_id: u32,
	/// Counterparty's public key (32 bytes). Zero for shield/unshield notes.
	pub counterparty_pk: [u8; 32],
}

impl MemoData {
	/// Creates new memo data.
	pub fn new(
		value: u64,
		owner_pk: [u8; 32],
		blinding: [u8; 32],
		asset_id: u32,
		counterparty_pk: [u8; 32],
	) -> Self {
		Self {
			value,
			owner_pk,
			blinding,
			asset_id,
			counterparty_pk,
		}
	}

	/// Creates memo data without a counterparty (shield/unshield notes).
	pub fn new_without_counterparty(
		value: u64,
		owner_pk: [u8; 32],
		blinding: [u8; 32],
		asset_id: u32,
	) -> Self {
		Self {
			value,
			owner_pk,
			blinding,
			asset_id,
			counterparty_pk: [0u8; 32],
		}
	}

	/// Serializes to 108 bytes.
	pub fn to_bytes(&self) -> [u8; MEMO_DATA_SIZE] {
		let mut bytes = [0u8; MEMO_DATA_SIZE];
		bytes[0..8].copy_from_slice(&self.value.to_le_bytes());
		bytes[8..40].copy_from_slice(&self.owner_pk);
		bytes[40..72].copy_from_slice(&self.blinding);
		bytes[72..76].copy_from_slice(&self.asset_id.to_le_bytes());
		bytes[76..108].copy_from_slice(&self.counterparty_pk);
		bytes
	}

	/// Deserializes from exactly 108 bytes.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
		if bytes.len() != MEMO_DATA_SIZE {
			return Err(MemoError::InvalidNoteData);
		}
		let value = u64::from_le_bytes(
			bytes[0..8]
				.try_into()
				.map_err(|_| MemoError::InvalidNoteData)?,
		);
		let mut owner_pk = [0u8; 32];
		owner_pk.copy_from_slice(&bytes[8..40]);
		let mut blinding = [0u8; 32];
		blinding.copy_from_slice(&bytes[40..72]);
		let asset_id = u32::from_le_bytes(
			bytes[72..76]
				.try_into()
				.map_err(|_| MemoError::InvalidNoteData)?,
		);
		let mut counterparty_pk = [0u8; 32];
		counterparty_pk.copy_from_slice(&bytes[76..108]);
		Ok(Self {
			value,
			owner_pk,
			blinding,
			asset_id,
			counterparty_pk,
		})
	}
}

/// Returns `true` when `data` has a valid encrypted memo length.
pub fn is_valid_encrypted_memo(data: &[u8]) -> bool {
	(MIN_ENCRYPTED_MEMO_SIZE..=MAX_ENCRYPTED_MEMO_SIZE).contains(&data.len())
}

// ─── Encryption / Decryption ──────────────────────────────────────────────────

/// Encrypts memo data using ChaCha20-Poly1305.
///
/// Returns `nonce(12) || ciphertext(108) || MAC(16) || ephPk(32)` = 168 bytes.
/// The ephemeral public key is set to all-zeros (symmetric / public-note mode).
/// For full ECDH, compute the shared secret externally with BabyJubJub and pass it as
/// `shared_secret`. The caller is responsible for appending the real ephPk after the call
/// if needed for ECDH recipients (replace the trailing 32 zero bytes).
///
/// **WARNING**: `nonce` MUST be unique per (key, message) pair and never reused.
pub fn encrypt_memo(
	memo: &MemoData,
	commitment: &[u8; 32],
	shared_secret: &[u8; 32],
	nonce: &[u8; 12],
) -> Result<Vec<u8>, MemoError> {
	let key = derive_encryption_key(shared_secret, commitment);
	let cipher = ChaCha20Poly1305::new((&key).into());
	let nonce_obj = Nonce::from_slice(nonce);
	let ciphertext = cipher
		.encrypt(nonce_obj, memo.to_bytes().as_ref())
		.map_err(|_| MemoError::EncryptionFailed)?;

	let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + EPH_PK_SIZE);
	result.extend_from_slice(nonce);
	result.extend_from_slice(&ciphertext);
	result.extend_from_slice(&[0u8; EPH_PK_SIZE]); // zero ephPk = symmetric / public-note mode
	Ok(result)
}

/// Encrypts memo with an automatically generated random nonce.
///
/// Preferred method for production use. Requires the `encrypt` feature.
#[cfg(feature = "encrypt")]
pub fn encrypt_memo_random(
	memo: &MemoData,
	commitment: &[u8; 32],
	shared_secret: &[u8; 32],
) -> Result<Vec<u8>, MemoError> {
	use rand::{rngs::OsRng, RngCore};
	let mut nonce = [0u8; 12];
	OsRng.fill_bytes(&mut nonce);
	encrypt_memo(memo, commitment, shared_secret, &nonce)
}

/// Decrypts an encrypted memo.
///
/// Expects `nonce(12) || ciphertext + MAC(124) || ephPk(32)` (168 bytes).
/// The trailing `ephPk` bytes are stripped; the first 136 bytes are fed to ChaCha20-Poly1305.
///
/// **ECDH callers**: extract `ephPk = encrypted[136..168]`, derive the BabyJubJub ECDH
/// shared secret externally (x-coordinate of `BJJ_mul(ephPk_point, ivsk_scalar)`), then
/// pass that 32-byte value as `shared_secret`.
///
/// **Symmetric / public-note callers**: pass the viewing key directly as `shared_secret`.
pub fn decrypt_memo(
	encrypted: &[u8],
	commitment: &[u8; 32],
	shared_secret: &[u8; 32],
) -> Result<MemoData, MemoError> {
	if encrypted.len() < MIN_ENCRYPTED_MEMO_SIZE {
		return Err(MemoError::DataTooShort);
	}
	if encrypted.len() > MAX_ENCRYPTED_MEMO_SIZE {
		return Err(MemoError::DataTooLong);
	}
	// Strip trailing ephemeral public key bytes (v2 ECDH layout).
	let cipher_data = &encrypted[..encrypted.len().min(MAX_ENCRYPTED_MEMO_SIZE - EPH_PK_SIZE)];

	let (nonce_bytes, ciphertext) = cipher_data.split_at(NONCE_SIZE);
	let nonce = Nonce::from_slice(nonce_bytes);
	let key = derive_encryption_key(shared_secret, commitment);
	let cipher = ChaCha20Poly1305::new((&key).into());
	let plaintext = cipher
		.decrypt(nonce, ciphertext)
		.map_err(|_| MemoError::DecryptionFailed)?;

	MemoData::from_bytes(&plaintext)
}

/// Attempts decryption and returns `None` on failure.
///
/// Useful for scanning the chain to find owned notes.
pub fn try_decrypt_memo(
	encrypted: &[u8],
	commitment: &[u8; 32],
	shared_secret: &[u8; 32],
) -> Option<MemoData> {
	decrypt_memo(encrypted, commitment, shared_secret).ok()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;

	fn sample_memo() -> MemoData {
		MemoData::new(1000, [1u8; 32], [2u8; 32], 5, [6u8; 32])
	}

	const COMMITMENT: [u8; 32] = [3u8; 32];
	const VK: [u8; 32] = [4u8; 32];
	const NONCE: [u8; 12] = [5u8; 12];

	// ── Constants ────────────────────────────────────────────────────────────

	#[test]
	fn layout_constants_are_coherent() {
		assert_eq!(MEMO_DATA_SIZE, 108);
		assert_eq!(NONCE_SIZE, 12);
		assert_eq!(MAC_SIZE, 16);
		assert_eq!(EPH_PK_SIZE, 32);
		assert_eq!(
			MAX_ENCRYPTED_MEMO_SIZE,
			NONCE_SIZE + MEMO_DATA_SIZE + MAC_SIZE + EPH_PK_SIZE
		);
		assert_eq!(MIN_ENCRYPTED_MEMO_SIZE, NONCE_SIZE + MAC_SIZE);
		assert_eq!(MAX_ENCRYPTED_MEMO_SIZE, 168);
		assert_eq!(MIN_ENCRYPTED_MEMO_SIZE, 28);
	}

	// ── MemoError ────────────────────────────────────────────────────────────

	#[test]
	fn error_display_contains_expected_words() {
		extern crate alloc;
		use alloc::format;
		assert!(format!("{}", MemoError::DataTooShort).contains("too short"));
		assert!(format!("{}", MemoError::DecryptionFailed)
			.to_lowercase()
			.contains("decryption"));
		assert!(format!("{}", MemoError::InvalidDisclosureMask("x")).contains("x"));
		assert!(format!("{}", MemoError::InvalidProof("y")).contains("y"));
	}

	#[test]
	fn error_eq_and_clone() {
		assert_eq!(MemoError::DataTooShort, MemoError::DataTooShort.clone());
		assert_ne!(MemoError::DataTooShort, MemoError::DataTooLong);
	}

	// ── MemoData ─────────────────────────────────────────────────────────────

	#[test]
	fn memo_data_roundtrip() {
		let m = sample_memo();
		assert_eq!(MemoData::from_bytes(&m.to_bytes()).unwrap(), m);
	}

	#[test]
	fn memo_data_wrong_length() {
		assert!(MemoData::from_bytes(&[0u8; 50]).is_err());
		assert!(MemoData::from_bytes(&[0u8; 76]).is_err());
		assert!(MemoData::from_bytes(&[0u8; 109]).is_err());
		assert!(MemoData::from_bytes(&[]).is_err());
	}

	#[test]
	fn memo_data_field_layout() {
		let m = MemoData::new(u64::MAX, [0xAAu8; 32], [0xBBu8; 32], u32::MAX, [0xCCu8; 32]);
		let b = m.to_bytes();
		assert_eq!(b[0..8], u64::MAX.to_le_bytes());
		assert_eq!(b[8..40], [0xAAu8; 32]);
		assert_eq!(b[40..72], [0xBBu8; 32]);
		assert_eq!(b[72..76], u32::MAX.to_le_bytes());
		assert_eq!(b[76..108], [0xCCu8; 32]);
	}

	#[test]
	fn new_without_counterparty_zeroes_counterparty_pk() {
		let m = MemoData::new_without_counterparty(42, [0x01u8; 32], [0x02u8; 32], 1);
		assert_eq!(m.counterparty_pk, [0u8; 32]);
		let b = m.to_bytes();
		assert_eq!(b[76..108], [0u8; 32]);
	}

	// ── is_valid_encrypted_memo ───────────────────────────────────────────────

	#[test]
	fn valid_encrypted_memo_bounds() {
		assert!(is_valid_encrypted_memo(&[0u8; MIN_ENCRYPTED_MEMO_SIZE]));
		assert!(is_valid_encrypted_memo(&[0u8; MAX_ENCRYPTED_MEMO_SIZE]));
		assert!(!is_valid_encrypted_memo(
			&[0u8; MIN_ENCRYPTED_MEMO_SIZE - 1]
		));
		assert!(!is_valid_encrypted_memo(
			&[0u8; MAX_ENCRYPTED_MEMO_SIZE + 1]
		));
		assert!(!is_valid_encrypted_memo(&[]));
	}

	// ── Encryption / Decryption ───────────────────────────────────────────────

	#[test]
	fn encrypt_produces_correct_length() {
		let enc = encrypt_memo(&sample_memo(), &COMMITMENT, &VK, &NONCE).unwrap();
		assert_eq!(enc.len(), MAX_ENCRYPTED_MEMO_SIZE);
	}

	#[test]
	fn nonce_is_first_12_bytes() {
		let enc = encrypt_memo(&sample_memo(), &COMMITMENT, &VK, &NONCE).unwrap();
		assert_eq!(&enc[..12], &NONCE);
	}

	#[test]
	fn encrypt_decrypt_roundtrip() {
		let memo = sample_memo();
		let enc = encrypt_memo(&memo, &COMMITMENT, &VK, &NONCE).unwrap();
		let dec = decrypt_memo(&enc, &COMMITMENT, &VK).unwrap();
		assert_eq!(dec, memo);
	}

	#[test]
	fn decrypt_fails_wrong_key() {
		let enc = encrypt_memo(&sample_memo(), &COMMITMENT, &VK, &NONCE).unwrap();
		assert_eq!(
			decrypt_memo(&enc, &COMMITMENT, &[99u8; 32]),
			Err(MemoError::DecryptionFailed)
		);
	}

	#[test]
	fn decrypt_fails_tampered_data() {
		let mut enc = encrypt_memo(&sample_memo(), &COMMITMENT, &VK, &NONCE).unwrap();
		enc[20] ^= 0xFF; // flip a byte in the ciphertext
		assert_eq!(
			decrypt_memo(&enc, &COMMITMENT, &VK),
			Err(MemoError::DecryptionFailed)
		);
	}

	#[test]
	fn decrypt_too_short() {
		assert_eq!(
			decrypt_memo(&[0u8; 10], &COMMITMENT, &VK),
			Err(MemoError::DataTooShort)
		);
	}

	#[test]
	fn decrypt_too_long() {
		assert_eq!(
			decrypt_memo(&[0u8; MAX_ENCRYPTED_MEMO_SIZE + 1], &COMMITMENT, &VK),
			Err(MemoError::DataTooLong)
		);
	}

	#[test]
	fn encrypt_deterministic_with_same_nonce() {
		let m = sample_memo();
		let e1 = encrypt_memo(&m, &COMMITMENT, &VK, &NONCE).unwrap();
		let e2 = encrypt_memo(&m, &COMMITMENT, &VK, &NONCE).unwrap();
		assert_eq!(e1, e2);
	}

	#[test]
	fn try_decrypt_returns_none_on_failure() {
		assert!(try_decrypt_memo(&[0u8; 10], &COMMITMENT, &VK).is_none());
	}

	#[test]
	fn try_decrypt_returns_some_on_success() {
		let memo = sample_memo();
		let enc = encrypt_memo(&memo, &COMMITMENT, &VK, &NONCE).unwrap();
		assert_eq!(try_decrypt_memo(&enc, &COMMITMENT, &VK), Some(memo));
	}

	#[test]
	fn counterparty_pk_nonzero_roundtrip() {
		let cpk = [0xABu8; 32];
		let m = MemoData::new(1_000, [0x01u8; 32], [0x02u8; 32], 7, cpk);
		let enc = encrypt_memo(&m, &COMMITMENT, &VK, &NONCE).unwrap();
		let dec = decrypt_memo(&enc, &COMMITMENT, &VK).unwrap();
		assert_eq!(dec.counterparty_pk, cpk);
		assert_eq!(dec, m);
	}
}
