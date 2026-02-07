//! Note entity - Represents a private note in the shielded pool
//!
//! Una nota es la unidad fundamental de valor en el pool privado.
//! Contiene el valor, propietario y otros metadatos, pero está oculta
//! mediante un commitment.

use sp_std::vec::Vec;

/// Hash type (32 bytes)
pub type Hash = [u8; 32];

/// A private note in the shielded pool
///
/// Una nota representa un UTXO privado que contiene:
/// - Un valor (amount)
/// - Un propietario (owner public key)
/// - Un factor de blinding para ocultar el valor
/// - Opcionalmente, metadatos adicionales
///
/// # Invariantes
/// - El valor debe ser > 0
/// - El owner_pubkey no debe ser todo ceros
/// - El blinding debe ser aleatorio y único
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
	/// Valor de la nota (en unidades mínimas del token)
	value: u128,

	/// Public key del propietario (32 bytes)
	owner_pubkey: Hash,

	/// Factor de blinding para el commitment (32 bytes)
	/// Debe ser aleatorio para cada nota
	blinding: Hash,

	/// Asset ID (para multi-asset pools en el futuro)
	/// Por ahora siempre es 0 (native token)
	asset_id: u64,
}

impl Note {
	/// Crea una nueva nota
	///
	/// # Parámetros
	/// - `value`: Cantidad de tokens en la nota
	/// - `owner_pubkey`: Clave pública del propietario
	/// - `blinding`: Factor aleatorio de blinding
	///
	/// # Errores
	/// - Si value es 0
	/// - Si owner_pubkey es todo ceros
	/// - Si blinding es todo ceros
	pub fn new(value: u128, owner_pubkey: Hash, blinding: Hash) -> Result<Self, &'static str> {
		// Validaciones
		if value == 0 {
			return Err("Note value cannot be zero");
		}

		if owner_pubkey == [0u8; 32] {
			return Err("Owner public key cannot be zero");
		}

		if blinding == [0u8; 32] {
			return Err("Blinding factor cannot be zero");
		}

		Ok(Self {
			value,
			owner_pubkey,
			blinding,
			asset_id: 0, // Native token por defecto
		})
	}

	/// Crea una nota con asset_id específico
	pub fn new_with_asset(
		value: u128,
		owner_pubkey: Hash,
		blinding: Hash,
		asset_id: u64,
	) -> Result<Self, &'static str> {
		let mut note = Self::new(value, owner_pubkey, blinding)?;
		note.asset_id = asset_id;
		Ok(note)
	}

	/// Retorna el valor de la nota
	pub fn value(&self) -> u128 {
		self.value
	}

	/// Retorna la clave pública del propietario
	pub fn owner_pubkey(&self) -> &Hash {
		&self.owner_pubkey
	}

	/// Retorna el factor de blinding
	pub fn blinding(&self) -> &Hash {
		&self.blinding
	}

	/// Retorna el asset ID
	pub fn asset_id(&self) -> u64 {
		self.asset_id
	}

	/// Serializa la nota para hashing
	///
	/// Formato: value || asset_id || owner_pubkey || blinding
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&self.value.to_le_bytes());
		bytes.extend_from_slice(&self.asset_id.to_le_bytes());
		bytes.extend_from_slice(&self.owner_pubkey);
		bytes.extend_from_slice(&self.blinding);
		bytes
	}

	/// Verifica que la nota tenga valores válidos
	pub fn is_valid(&self) -> bool {
		self.value > 0 && self.owner_pubkey != [0u8; 32] && self.blinding != [0u8; 32]
	}
}
