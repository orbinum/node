//! Commitment entity - Represents a commitment to a private note
//!
//! Un commitment es un hash criptográfico que oculta los detalles de una nota
//! (valor, propietario, etc.) mientras permite su inclusión en el árbol Merkle.

use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::RuntimeDebug;

/// A commitment to a private note
///
/// Computed as: Poseidon(value, asset_id, owner_pubkey, blinding)
///
/// # Properties
/// - **Hiding**: No revela información sobre la nota
/// - **Binding**: Compromiso único para cada nota
/// - **Collision-resistant**: Imposible generar dos notas con el mismo commitment
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
pub struct Commitment(pub [u8; 32]);

impl Commitment {
	/// Crea un nuevo commitment desde bytes
	pub fn new(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Verifica que el commitment no sea el valor por defecto (todo ceros)
	///
	/// Un commitment válido nunca debe ser todo ceros, ya que esto indicaría
	/// un error en el cálculo o un intento de ataque.
	pub fn is_valid(&self) -> bool {
		self.0 != [0u8; 32]
	}

	/// Check if commitment is zero (invalid state)
	pub fn is_zero(&self) -> bool {
		self.0 == [0u8; 32]
	}

	/// Retorna los bytes internos del commitment
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// Consume el commitment y retorna los bytes internos
	pub fn into_bytes(self) -> [u8; 32] {
		self.0
	}
}

impl From<[u8; 32]> for Commitment {
	fn from(bytes: [u8; 32]) -> Self {
		Self::new(bytes)
	}
}

impl From<H256> for Commitment {
	fn from(h: H256) -> Self {
		Self::new(h.0)
	}
}

impl AsRef<[u8]> for Commitment {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}
