//! Nullifier entity - Represents a spent note identifier
//!
//! Un nullifier es un valor único que se publica cuando se gasta una nota,
//! previniendo el doble gasto sin revelar qué nota fue gastada.

use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::RuntimeDebug;

/// A nullifier that uniquely identifies a spent note
///
/// Computed as: Poseidon(commitment, spending_key)
///
/// # Properties
/// - **Uniqueness**: Cada nota tiene un nullifier único
/// - **Unlinkability**: No revela qué commitment fue gastado
/// - **Non-reusability**: Solo puede ser usado una vez
///
/// Publishing the nullifier prevents double-spending without revealing
/// which note was spent.
#[derive(
	Clone,
	Copy,
	PartialEq,
	Eq,
	Encode,
	Decode,
	DecodeWithMemTracking,
	MaxEncodedLen,
	TypeInfo,
	RuntimeDebug,
	Default
)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
	/// Crea un nuevo nullifier desde bytes
	pub fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Verifica que el nullifier sea válido (no todo ceros)
	///
	/// Un nullifier válido nunca debe ser todo ceros, ya que esto indicaría
	/// un error en el cálculo o un intento de ataque.
	pub fn validate(&self) -> bool {
		self.0 != [0u8; 32]
	}

	/// Retorna los bytes internos del nullifier
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// Consume el nullifier y retorna los bytes internos
	pub fn into_bytes(self) -> [u8; 32] {
		self.0
	}
}

impl From<[u8; 32]> for Nullifier {
	fn from(bytes: [u8; 32]) -> Self {
		Self::new(bytes)
	}
}

impl From<H256> for Nullifier {
	fn from(h: H256) -> Self {
		Self::new(h.0)
	}
}

impl AsRef<[u8]> for Nullifier {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}
