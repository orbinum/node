//! Unit tests for pallet runtime types

#[cfg(test)]
mod runtime_types_tests {
	use crate::types::{CircuitId, ProofSystem, VerificationKeyInfo, VerificationStatistics};

	#[test]
	fn circuit_id_constants_are_stable() {
		assert_eq!(CircuitId::TRANSFER.0, 1);
		assert_eq!(CircuitId::UNSHIELD.0, 2);
		assert_eq!(CircuitId::SHIELD.0, 3);
		assert_eq!(CircuitId::DISCLOSURE.0, 4);
		assert_eq!(CircuitId::PRIVATE_LINK.0, 5);
	}

	#[test]
	fn proof_system_default_is_groth16() {
		assert_eq!(ProofSystem::default(), ProofSystem::Groth16);
	}

	#[test]
	fn verification_key_info_default_is_empty() {
		let info: VerificationKeyInfo<u64> = VerificationKeyInfo::default();
		assert!(info.key_data.is_empty());
		assert_eq!(info.system, ProofSystem::Groth16);
		assert_eq!(info.registered_at, 0u64);
	}

	#[test]
	fn verification_statistics_default_is_zeroed() {
		let stats = VerificationStatistics::default();
		assert_eq!(stats.total_verifications, 0);
		assert_eq!(stats.successful_verifications, 0);
		assert_eq!(stats.failed_verifications, 0);
	}
}
