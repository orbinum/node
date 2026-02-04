//! Domain errors - Business logic errors

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
	// Verification Key errors
	EmptyVerificationKey,
	VerificationKeyTooLarge,
	InvalidVerificationKeySize,
	InvalidVerificationKeyFormat,
	InvalidVerificationKey, // Added for deserialization errors

	// Proof errors
	EmptyProof,
	ProofTooLarge,
	InvalidProofFormat,
	InvalidProof, // Added for deserialization errors

	// Public inputs errors
	EmptyPublicInputs,
	TooManyPublicInputs,
	InvalidPublicInputFormat,
	InvalidPublicInputs, // Added for conversion errors

	// Verification errors
	VerificationFailed,
	UnsupportedProofSystem,

	// Circuit errors
	CircuitNotFound,
	CircuitAlreadyExists,
}

impl core::fmt::Display for DomainError {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		match self {
			Self::EmptyVerificationKey => write!(f, "Verification key cannot be empty"),
			Self::VerificationKeyTooLarge => write!(f, "Verification key exceeds maximum size"),
			Self::InvalidVerificationKeySize => {
				write!(f, "Verification key has invalid size for proof system")
			}
			Self::InvalidVerificationKeyFormat => write!(f, "Verification key format is invalid"),
			Self::InvalidVerificationKey => write!(f, "Invalid verification key"),
			Self::EmptyProof => write!(f, "Proof cannot be empty"),
			Self::ProofTooLarge => write!(f, "Proof exceeds maximum size"),
			Self::InvalidProofFormat => write!(f, "Proof format is invalid"),
			Self::InvalidProof => write!(f, "Invalid proof"),
			Self::EmptyPublicInputs => write!(f, "Public inputs cannot be empty"),
			Self::TooManyPublicInputs => write!(f, "Too many public inputs provided"),
			Self::InvalidPublicInputFormat => write!(f, "Public input format is invalid"),
			Self::InvalidPublicInputs => write!(f, "Invalid public inputs"),
			Self::VerificationFailed => write!(f, "Proof verification failed"),
			Self::UnsupportedProofSystem => write!(f, "Proof system is not supported"),
			Self::CircuitNotFound => write!(f, "Circuit not found"),
			Self::CircuitAlreadyExists => write!(f, "Circuit already exists"),
		}
	}
}

#[cfg(feature = "std")]
impl std::error::Error for DomainError {}
