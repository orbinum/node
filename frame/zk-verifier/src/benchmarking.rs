//! Benchmarking setup for pallet-zk-verifier
//!
//! Run benchmarks with:
//! ```bash
//! cargo build --release --features runtime-benchmarks
//! ./target/release/orbinum-node benchmark pallet \
//!     --chain dev \
//!     --pallet pallet_zk_verifier \
//!     --extrinsic '*' \
//!     --steps 50 \
//!     --repeat 20 \
//!     --output weights.rs
//! ```

use super::*;
use frame_benchmarking::v2::*;
use frame_system::RawOrigin;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec;

#[benchmarks]
mod benchmarks {
	use super::*;
	use frame_support::{BoundedVec, pallet_prelude::ConstU32};
	use sp_std::vec::Vec;

	// Benchmark configuration constants for FRAME weight generation
	const BENCHMARK_VK_SIZE: usize = 768;
	const BENCHMARK_PROOF_SIZE: usize = 192;
	const BENCHMARK_PUBLIC_INPUTS_COUNT: usize = 1;

	/// Generate synthetic Groth16 verification key bytes for benchmarking
	///
	/// NOTE: Uses mock data because it doesn't affect weight (storage read path only).
	/// Actual weight is measured in storage writes, not format validation.
	fn sample_verification_key() -> Vec<u8> {
		// Typical Groth16 VK: 768 bytes (BN254 curve)
		// Structure: alpha_g1 (48) + beta_g2 (96) + gamma_g2 (96) + delta_g2 (96) + ic (variable)
		// Deterministic pattern for reproducibility
		(0..BENCHMARK_VK_SIZE)
			.map(|i| ((i % 4) + 1) as u8)
			.collect()
	}

	/// Generate mock proof data for benchmarking
	///
	/// WARNING: This data does NOT pass real cryptographic verification.
	/// The benchmark measures FRAME overhead (storage, events, conversions).
	/// Real cryptographic verification timing is intentionally out of scope here.
	fn sample_proof_data() -> (Vec<u8>, Vec<Vec<u8>>) {
		// Groth16 proof: 192 bytes (3 curve points)
		let proof_bytes = vec![0x42; BENCHMARK_PROOF_SIZE];

		// Public inputs with deterministic pattern
		let public_inputs = (0..BENCHMARK_PUBLIC_INPUTS_COUNT)
			.map(|i| {
				let mut input = vec![0u8; 32];
				input[0] = i as u8;
				input
			})
			.collect();

		(proof_bytes, public_inputs)
	}

	/// Benchmark for `verify_proof`
	///
	/// ⚠️ LIMITATION: This benchmark uses mock data that does NOT pass cryptographic verification.
	/// It only measures FRAME overhead (storage reads, mappers, events).
	///
	/// Real Groth16 verification time (~8-10ms) is NOT included here.
	///
	/// TODO: Integrate real proofs when circuits are in production.
	#[benchmark]
	fn verify_proof() {
		let circuit_id = CircuitId::TRANSFER;

		// Get mock VK and proof data (do NOT verify cryptographically)
		let vk_bytes = sample_verification_key();
		let (proof_bytes, public_inputs) = sample_proof_data();

		// Setup: seed storage with verification key + active version (genesis-like state)
		let vk_info = VerificationKeyInfo {
			key_data: vk_bytes.clone().try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at: frame_system::Pallet::<T>::block_number(),
		};
		VerificationKeys::<T>::insert(circuit_id, 1, vk_info);

		// Set active version for verify_proof
		crate::pallet::ActiveCircuitVersion::<T>::insert(circuit_id, 1);

		// Create proof with valid bytes and matching public inputs
		let proof: BoundedVec<u8, T::MaxProofSize> = proof_bytes
			.clone()
			.try_into()
			.expect("benchmark proof bytes must fit MaxProofSize");

		// Use T::MaxPublicInputs for the outer BoundedVec to avoid truncation issues
		let inputs: BoundedVec<BoundedVec<u8, ConstU32<32>>, T::MaxPublicInputs> = public_inputs
			.iter()
			.map(|input| BoundedVec::truncate_from(input.to_vec()))
			.collect::<Vec<_>>()
			.try_into()
			.expect("benchmark public inputs must fit MaxPublicInputs");

		let caller: T::AccountId = whitelisted_caller();

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), circuit_id, proof, inputs);
	}

	#[benchmark]
	fn register_verification_key() {
		let circuit_id = CircuitId::TRANSFER;
		let version = 1u32;
		let vk_bytes = sample_verification_key();
		let bounded_vk: BoundedVec<u8, ConstU32<8192>> = vk_bytes
			.try_into()
			.expect("benchmark vk bytes must fit bounded verification key size");

		#[extrinsic_call]
		_(RawOrigin::Root, circuit_id, version, bounded_vk);

		assert!(VerificationKeys::<T>::contains_key(circuit_id, version));
	}

	#[benchmark]
	fn set_active_version() {
		let circuit_id = CircuitId::TRANSFER;
		let current_version = 1u32;
		let new_version = 2u32;
		let registered_at = frame_system::Pallet::<T>::block_number();

		let vk_v1 = VerificationKeyInfo {
			key_data: sample_verification_key().try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at,
		};
		let vk_v2 = VerificationKeyInfo {
			key_data: sample_verification_key().try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at,
		};

		VerificationKeys::<T>::insert(circuit_id, current_version, vk_v1);
		VerificationKeys::<T>::insert(circuit_id, new_version, vk_v2);
		ActiveCircuitVersion::<T>::insert(circuit_id, current_version);

		#[extrinsic_call]
		_(RawOrigin::Root, circuit_id, new_version);

		assert_eq!(
			ActiveCircuitVersion::<T>::get(circuit_id),
			Some(new_version)
		);
	}

	#[benchmark]
	fn remove_verification_key() {
		let circuit_id = CircuitId::TRANSFER;
		let active_version = 1u32;
		let remove_version = 2u32;
		let registered_at = frame_system::Pallet::<T>::block_number();

		let vk_active = VerificationKeyInfo {
			key_data: sample_verification_key().try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at,
		};
		let vk_remove = VerificationKeyInfo {
			key_data: sample_verification_key().try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at,
		};

		VerificationKeys::<T>::insert(circuit_id, active_version, vk_active);
		VerificationKeys::<T>::insert(circuit_id, remove_version, vk_remove);
		ActiveCircuitVersion::<T>::insert(circuit_id, active_version);

		#[extrinsic_call]
		_(RawOrigin::Root, circuit_id, remove_version);

		assert!(!VerificationKeys::<T>::contains_key(
			circuit_id,
			remove_version
		));
		assert!(VerificationKeys::<T>::contains_key(
			circuit_id,
			active_version
		));
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
