//! Integration tests for infrastructure adapters and repositories

#[cfg(test)]
mod adapter_tests {
	use crate::{
		domain::{
			entities::{Proof, VerificationKey},
			value_objects::{ProofSystem, PublicInputs},
		},
		infrastructure::adapters::{ProofAdapter, PublicInputsAdapter, VerificationKeyAdapter},
	};

	#[test]
	fn public_inputs_adapter_converts_inputs_without_data_loss() {
		let inputs = PublicInputs::new(vec![vec![1u8; 32], vec![2u8; 32]]).unwrap();
		let primitive = PublicInputsAdapter::to_primitive(&inputs);

		assert_eq!(primitive.len(), 2);
		assert_eq!(primitive.inputs[0], [1u8; 32]);
		assert_eq!(primitive.inputs[1], [2u8; 32]);
	}

	#[test]
	fn proof_adapter_preserves_bytes() {
		let proof = Proof::new(vec![9u8; 64]).unwrap();
		let primitive = ProofAdapter::to_primitive(&proof);

		assert_eq!(primitive.as_bytes(), proof.data());
	}

	#[test]
	fn verification_key_adapter_preserves_bytes() {
		let vk = VerificationKey::new(vec![7u8; 512], ProofSystem::Groth16).unwrap();
		let primitive = VerificationKeyAdapter::to_primitive(&vk);

		assert_eq!(primitive.as_bytes(), vk.data());
	}
}

#[cfg(test)]
mod statistics_repository_tests {
	use crate::{
		domain::{repositories::StatisticsRepository, value_objects::CircuitId},
		infrastructure::repositories::FrameStatisticsRepository,
		mock,
	};
	use sp_io::TestExternalities;
	use sp_runtime::BuildStorage;

	#[test]
	fn frame_statistics_repository_updates_and_reads_stats() {
		let storage = frame_system::GenesisConfig::<mock::Test>::default()
			.build_storage()
			.unwrap();
		let mut ext = TestExternalities::new(storage);

		ext.execute_with(|| {
			let repo = FrameStatisticsRepository::<mock::Test>::new();
			let circuit = CircuitId::TRANSFER;
			let version = 1;

			repo.increment_verifications(circuit, version).unwrap();
			repo.increment_verifications(circuit, version).unwrap();
			repo.increment_successes(circuit, version).unwrap();
			repo.increment_failures(circuit, version).unwrap();

			let stats = repo.get_stats(circuit, version).unwrap();
			assert_eq!(stats.total_verifications, 2);
			assert_eq!(stats.successful_verifications, 1);
			assert_eq!(stats.failed_verifications, 1);
		});
	}
}
