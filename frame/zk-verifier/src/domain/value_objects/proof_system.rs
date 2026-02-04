//! Proof system value object

/// Zero-knowledge proof system
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum ProofSystem {
	/// Groth16 - Fast verification, small proofs
	Groth16,
	/// PLONK - Universal trusted setup
	Plonk,
	/// Halo2 - No trusted setup
	Halo2,
}

impl ProofSystem {
	/// Get string representation
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::Groth16 => "Groth16",
			Self::Plonk => "Plonk",
			Self::Halo2 => "Halo2",
		}
	}

	/// Check if proof system is currently supported
	pub fn is_supported(&self) -> bool {
		matches!(self, Self::Groth16)
	}

	/// Get expected VK size range for this proof system
	pub fn expected_vk_size_range(&self) -> (usize, usize) {
		match self {
			Self::Groth16 => (512, 10_000), // Min 512 bytes, max 10KB
			Self::Plonk => (1024, 20_000),
			Self::Halo2 => (1024, 20_000),
		}
	}

	/// Get expected proof size for this proof system
	pub fn expected_proof_size(&self) -> usize {
		match self {
			Self::Groth16 => 256, // ~256 bytes for Groth16
			Self::Plonk => 512,
			Self::Halo2 => 512,
		}
	}
}

impl core::fmt::Display for ProofSystem {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		write!(f, "{}", self.as_str())
	}
}
