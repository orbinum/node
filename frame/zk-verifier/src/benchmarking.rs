//! Benchmarking setup for pallet-zk-verifier
//!
//! IMPORTANTE: Estos benchmarks miden el costo ON-CHAIN de extrinsics.
//! Los pesos generados se usan para calcular fees en producción.
//!
//! ## Generar Pesos de Producción
//!
//! ```bash
//! # 1. Compilar con runtime-benchmarks
//! cargo build --release --features runtime-benchmarks
//!
//! # 2. Ejecutar en HARDWARE DE REFERENCIA (no laptop de desarrollo)
//! ./target/release/orbinum-node benchmark pallet \
//!     --chain dev \
//!     --pallet pallet_zk_verifier \
//!     --extrinsic '*' \
//!     --steps 50 \
//!     --repeat 20 \
//!     --output frame/zk-verifier/src/weights.rs \
//!     --template ./scripts/frame-weight-template.hbs
//! ```
//!
//! ## Verificar Performance Criptográfica
//!
//! Para medir tiempos de verificación Groth16 puros (sin FRAME):
//! ```bash
//! cargo bench --package pallet-zk-verifier
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

	// Importar configuración compartida
	// Nota: Estas constantes deben coincidir con benches/config.rs
	const BENCHMARK_VK_SIZE: usize = 768;
	const BENCHMARK_PROOF_SIZE: usize = 192;
	const BENCHMARK_PUBLIC_INPUTS_COUNT: usize = 1;

	/// Generate a valid Groth16 verification key for benchmarking
	///
	/// NOTA: Usa datos mock porque no afecta el peso (VK se almacena, no se valida).
	/// El peso real se mide en storage writes, no en validación de formato.
	fn sample_verification_key() -> Vec<u8> {
		// VK típica de Groth16: 768 bytes (BN254 curve)
		// Estructura: alpha_g1 (48) + beta_g2 (96) + gamma_g2 (96) + delta_g2 (96) + ic (variable)
		// Pattern determinístico para reproducibilidad
		(0..BENCHMARK_VK_SIZE)
			.map(|i| ((i % 4) + 1) as u8)
			.collect()
	}

	/// Generate mock proof data for benchmarking
	///
	/// ⚠️ ADVERTENCIA: Estos datos NO pasan verificación criptográfica real.
	/// El benchmark mide overhead FRAME (storage, eventos, conversiones).
	/// Para medir verificación Groth16 real, usar: cargo bench
	fn sample_proof_data() -> (Vec<u8>, Vec<Vec<u8>>) {
		// Groth16 proof: 192 bytes (3 puntos curva)
		let proof_bytes = vec![0x42; BENCHMARK_PROOF_SIZE];

		// Public inputs con patrón determinístico
		let public_inputs = (0..BENCHMARK_PUBLIC_INPUTS_COUNT)
			.map(|i| {
				let mut input = vec![0u8; 32];
				input[0] = i as u8;
				input
			})
			.collect();

		(proof_bytes, public_inputs)
	}

	// Benchmark for `register_verification_key`
	#[benchmark]
	fn register_verification_key() {
		let circuit_id = CircuitId(100);
		let version = 1u32;
		let vk_bytes: Vec<u8> = sample_verification_key();

		#[extrinsic_call]
		_(
			RawOrigin::Root,
			circuit_id,
			version,
			vk_bytes,
			ProofSystem::Groth16,
		);

		assert!(VerificationKeys::<T>::contains_key(circuit_id, version));
	}

	/// Benchmark for `remove_verification_key`
	#[benchmark]
	fn remove_verification_key() {
		let circuit_id = CircuitId(100);
		let version = 1u32;
		let vk_bytes: Vec<u8> = vec![1u8; 1024];

		// Setup: register a key first
		let vk_info = VerificationKeyInfo {
			key_data: vk_bytes.try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at: frame_system::Pallet::<T>::block_number(),
		};
		VerificationKeys::<T>::insert(circuit_id, version, vk_info);

		#[extrinsic_call]
		_(RawOrigin::Root, circuit_id, version);

		assert!(!VerificationKeys::<T>::contains_key(circuit_id, version));
	}

	/// Benchmark for `set_active_version`
	#[benchmark]
	fn set_active_version() {
		let circuit_id = CircuitId(100);
		let version = 1u32;
		let vk_bytes = sample_verification_key();

		// Setup: register a key first
		let vk_info = VerificationKeyInfo {
			key_data: vk_bytes.try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at: frame_system::Pallet::<T>::block_number(),
		};
		VerificationKeys::<T>::insert(circuit_id, version, vk_info);

		#[extrinsic_call]
		_(RawOrigin::Root, circuit_id, version);

		assert_eq!(ActiveCircuitVersion::<T>::get(circuit_id), Some(version));
	}

	/// Benchmark for `verify_proof`
	///
	/// ⚠️ LIMITACIÓN: Este benchmark usa datos mock que NO pasan verificación criptográfica.
	/// Mide solo el overhead FRAME (storage reads, mappers, eventos).
	///
	/// El tiempo de verificación Groth16 real (~8-10ms) NO está incluido aquí.
	/// Para medirlo: cargo bench --package pallet-zk-verifier
	///
	/// TODO: Integrar proofs reales cuando circuits estén en producción.
	#[benchmark]
	fn verify_proof() {
		let circuit_id = CircuitId::TRANSFER;

		// Get mock VK and proof data (NO verifican criptográficamente)
		let vk_bytes = sample_verification_key();
		let (proof_bytes, public_inputs) = sample_proof_data();

		// Setup: register the verification key
		let vk_info = VerificationKeyInfo {
			key_data: vk_bytes.clone().try_into().unwrap(),
			system: ProofSystem::Groth16,
			registered_at: frame_system::Pallet::<T>::block_number(),
		};
		VerificationKeys::<T>::insert(circuit_id, 1, vk_info);

		// Set active version for verify_proof
		crate::pallet::ActiveCircuitVersion::<T>::insert(circuit_id, 1);

		// Create proof with valid bytes and matching public inputs
		let proof: BoundedVec<u8, T::MaxProofSize> =
			proof_bytes.clone().try_into().unwrap_or_default();

		// Use T::MaxPublicInputs for the outer BoundedVec to avoid truncation issues
		let inputs: BoundedVec<BoundedVec<u8, ConstU32<32>>, T::MaxPublicInputs> = public_inputs
			.iter()
			.map(|input| BoundedVec::truncate_from(input.to_vec()))
			.collect::<Vec<_>>()
			.try_into()
			.unwrap_or_default();

		let caller: T::AccountId = whitelisted_caller();

		#[extrinsic_call]
		_(RawOrigin::Signed(caller), circuit_id, proof, inputs);
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
