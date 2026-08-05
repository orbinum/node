//! The shielded note — the private-side unit of value.
//!
//! Only ever built and inspected off-chain: the chain sees its commitment, never
//! the note itself. Field widths must match the circuit exactly, since the
//! commitment is computed over this layout on both sides.

use super::Hash;
use sp_std::vec::Vec;

// Note (off-chain type, used by wallets)

/// A private note in the shielded pool (UTXO).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
	value: u128,
	owner_pubkey: Hash,
	blinding: Hash,
	asset_id: u32,
}

impl Note {
	pub fn new(value: u128, owner_pubkey: Hash, blinding: Hash) -> Result<Self, &'static str> {
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
			asset_id: 0,
		})
	}

	pub fn new_with_asset(
		value: u128,
		owner_pubkey: Hash,
		blinding: Hash,
		asset_id: u32,
	) -> Result<Self, &'static str> {
		let mut note = Self::new(value, owner_pubkey, blinding)?;
		note.asset_id = asset_id;
		Ok(note)
	}

	pub fn value(&self) -> u128 {
		self.value
	}
	pub fn owner_pubkey(&self) -> &Hash {
		&self.owner_pubkey
	}
	pub fn blinding(&self) -> &Hash {
		&self.blinding
	}
	pub fn asset_id(&self) -> u32 {
		self.asset_id
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		bytes.extend_from_slice(&self.value.to_le_bytes());
		bytes.extend_from_slice(&self.asset_id.to_le_bytes());
		bytes.extend_from_slice(&self.owner_pubkey);
		bytes.extend_from_slice(&self.blinding);
		bytes
	}

	pub fn is_valid(&self) -> bool {
		self.value > 0 && self.owner_pubkey != [0u8; 32] && self.blinding != [0u8; 32]
	}
}
