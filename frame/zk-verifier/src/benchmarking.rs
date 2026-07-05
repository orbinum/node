//! Benchmarking setup for pallet-zk-verifier
//!
//! Run benchmarks with (`skip-proof-verification` lets `verify_proof` record
//! weight even though its synthetic VK makes the pairing fail):
//! ```bash
//! cargo build --release --features runtime-benchmarks,skip-proof-verification
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

	/// 128-byte compressed Groth16 proof (A: G1, B: G2, C: G1 on BN254).
	/// Regenerate after any circuit change: `node scripts/generate-bench-fixtures.mjs`
	const BENCH_PROOF: &[u8] = include_bytes!("bench_fixtures/proof_transfer.bin");

	/// Build a BN254 Groth16 VK of the given input arity, serialized as the pallet
	/// consumes it.
	///
	/// `gamma_abc_g1` holds `arity + 1` points, so `verify` runs one G1 scalar-mul
	/// per input before the pairing — the term that scales with `n`. Points are the
	/// generator, so the proof will not satisfy the VK; the `verify_proof` benchmark
	/// relies on `skip-proof-verification` to record weight despite the failed pairing.
	fn synthetic_vk(arity: usize) -> Vec<u8> {
		use ark_bn254::{Bn254, G1Affine, G2Affine};
		use ark_ec::AffineRepr;
		use ark_groth16::VerifyingKey as ArkVk;
		use orbinum_zk_verifier::VerifyingKey;

		let vk = ArkVk::<Bn254> {
			alpha_g1: G1Affine::generator(),
			beta_g2: G2Affine::generator(),
			gamma_g2: G2Affine::generator(),
			delta_g2: G2Affine::generator(),
			gamma_abc_g1: (0..=arity).map(|_| G1Affine::generator()).collect(),
		};
		VerifyingKey::from_ark_vk(&vk)
			.expect("synthetic VK serializes")
			.bytes
	}

	/// VK for the TRANSFER circuit (arity 5) — used by the storage benchmarks,
	/// which validate that a registered VK deserializes and matches circuit arity.
	fn sample_verification_key() -> Vec<u8> {
		synthetic_vk(orbinum_zk_verifier::TRANSFER_PUBLIC_INPUTS)
	}

	/// Benchmark for `verify_proof`, parametrized by the public-input count `n`.
	///
	/// A synthetic VK of arity `n` forces `verify` to run one G1 scalar-mul per input
	/// before the pairing, so the runner can fit `verify_proof(n) = base + n·per_input`.
	/// The proof does not satisfy the VK; the pairing runs and fails, and
	/// `skip-proof-verification` (required for benchmarks) lets the extrinsic return
	/// `Ok`, so the full verification cost is still recorded.
	#[benchmark]
	fn verify_proof(n: Linear<1, 16>) {
		let circuit_id = CircuitId::TRANSFER;

		// Seed storage with an arity-`n` VK so `do_verify` runs `n` scalar-muls + pairing.
		let vk_info = VerificationKeyInfo {
			key_data: synthetic_vk(n as usize).try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at: frame_system::Pallet::<T>::block_number(),
		};
		VerificationKeys::<T>::insert(circuit_id, 1, vk_info);
		crate::pallet::ActiveCircuitVersion::<T>::insert(circuit_id, 1);

		let proof: BoundedVec<u8, T::MaxProofSize> = BENCH_PROOF
			.to_vec()
			.try_into()
			.expect("bench proof must fit MaxProofSize");

		// `n` distinct 32-byte LE field elements, matching the VK arity.
		let inputs: BoundedVec<BoundedVec<u8, ConstU32<32>>, T::MaxPublicInputs> = (0..n)
			.map(|i| {
				let mut bytes = [0u8; 32];
				bytes[0..4].copy_from_slice(&(i + 1).to_le_bytes());
				BoundedVec::truncate_from(bytes.to_vec())
			})
			.collect::<Vec<_>>()
			.try_into()
			.expect("bench public inputs must fit MaxPublicInputs");

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

	#[benchmark]
	fn batch_register_verification_keys(n: Linear<1, 10>) {
		let vk_bytes = sample_verification_key();

		let entries: Vec<crate::types::VkEntry> = (0..n)
			.map(|i| crate::types::VkEntry {
				circuit_id: CircuitId(100 + i),
				version: 1,
				verification_key: vk_bytes
					.clone()
					.try_into()
					.expect("benchmark vk bytes must fit BoundedVec"),
				set_active: true,
			})
			.collect();

		let bounded_entries: frame_support::BoundedVec<
			crate::types::VkEntry,
			frame_support::traits::ConstU32<10>,
		> = entries.try_into().expect("n <= 10, fits the bounded vec");

		#[extrinsic_call]
		_(RawOrigin::Root, bounded_entries);

		for i in 0..n {
			assert!(
				VerificationKeys::<T>::contains_key(CircuitId(100 + i), 1u32),
				"entry {i} must be stored in VerificationKeys"
			);
			assert_eq!(
				crate::pallet::ActiveCircuitVersion::<T>::get(CircuitId(100 + i)),
				Some(1u32),
				"entry {i} must have active version = 1"
			);
		}
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
