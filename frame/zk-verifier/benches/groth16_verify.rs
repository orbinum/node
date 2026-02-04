//! Criterion benchmarks for pallet-zk-verifier
//!
//! ## Purpose
//!
//! Estos benchmarks miden la performance criptográfica pura del verifier Groth16,
//! sin el overhead de FRAME. Son útiles para:
//! - Optimizar la implementación criptográfica
//! - Comparar diferentes estrategias de verificación
//! - Medir el impacto de cambios en el código
//!
//! ## Ejecutar
//!
//! ```bash
//! # Todos los benchmarks
//! cargo bench --package pallet-zk-verifier
//!
//! # Benchmark específico
//! cargo bench --package pallet-zk-verifier -- single_verification
//!
//! # Con configuración custom
//! CRITERION_CONFIG=production cargo bench --package pallet-zk-verifier
//!
//! # Ver resultados HTML
//! open target/criterion/report/index.html
//! ```
//!
//! ## Estructura
//!
//! 1. **Single Verification**: Tiempo de verificación de un proof
//! 2. **Batch Verification**: Throughput con múltiples proofs
//! 3. **VK Parsing**: Tiempo de parsing/deserialización de VK
//! 4. **Proof Parsing**: Tiempo de parsing de proof
//! 5. **Public Inputs Scaling**: Impacto del número de inputs
//! 6. **Memory Usage**: Footprint en memoria
//!
//! ## Configuración
//!
//! El módulo `config` provee presets de Criterion:
//! - `fast()`: Desarrollo rápido (10 samples, 2s)
//! - `standard()`: Regular (100 samples, 10s)
//! - `production()`: Producción (200 samples, 30s)

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

mod config;
use config::{BenchmarkSizes, CriterionConfig};

// ============================================================================
// Datos de Prueba Reales (usando VKs hardcodeadas del primitivo)
// ============================================================================

use orbinum_zk_verifier::{
	domain::value_objects::{Proof, PublicInputs, VerifyingKey},
	infrastructure::{
		Groth16Verifier,
		storage::verification_keys::{get_transfer_vk_bytes, get_unshield_vk_bytes},
	},
};

/// Genera datos de prueba reales usando VKs hardcodeadas
fn generate_real_test_data() -> (Vec<u8>, Vec<u8>, Vec<[u8; 32]>) {
	// VK real del transfer circuit (hardcoded en primitives)
	let vk_bytes = get_transfer_vk_bytes().to_vec();

	// Para proof y public inputs, usamos datos mock pero con formato válido
	// TODO: Cuando tengamos proofs reales de circuits, usar esos
	let proof_bytes = config::test_data::mock_proof_bytes();
	let public_inputs = vec![
		config::test_data::mock_single_public_input()
			.try_into()
			.unwrap(),
	];

	(vk_bytes, proof_bytes, public_inputs)
}

// ============================================================================
// 1. Single Verification Benchmark
// ============================================================================

fn bench_single_verification(c: &mut Criterion) {
	let mut group = c.benchmark_group("single_verification");
	group.sample_size(100);

	let (vk_bytes, proof_bytes, public_input_bytes) = generate_real_test_data();

	// Pre-parse structures (fuera del benchmark)
	let vk = VerifyingKey::new(vk_bytes.clone());
	let proof = Proof::new(proof_bytes.clone());
	let public_inputs = PublicInputs::new(public_input_bytes.clone());

	group.bench_function("groth16_verify", |b| {
		b.iter(|| {
			// Solo medir el tiempo de verificación
			let _result = Groth16Verifier::verify(
				black_box(&vk),
				black_box(&public_inputs),
				black_box(&proof),
			);
			// Nota: Puede fallar porque son datos mock, pero medimos el tiempo
		});
	});

	// Benchmark con parsing incluido
	group.bench_function("groth16_verify_with_parsing", |b| {
		b.iter(|| {
			let vk = VerifyingKey::new(black_box(vk_bytes.clone()));
			let proof = Proof::new(black_box(proof_bytes.clone()));
			let public_inputs = PublicInputs::new(black_box(public_input_bytes.clone()));
			let _result = Groth16Verifier::verify(&vk, &public_inputs, &proof);
		});
	});

	group.finish();
}

// ============================================================================
// 2. Batch Verification Benchmark
// ============================================================================

fn bench_batch_verification(c: &mut Criterion) {
	let mut group = c.benchmark_group("batch_verification");
	group.sample_size(50);

	let (vk_bytes, proof_bytes, public_input_bytes) = generate_real_test_data();
	let vk = VerifyingKey::new(vk_bytes);

	for &batch_size in BenchmarkSizes::BATCH_SIZES {
		// Pre-generar todos los proofs
		let proofs: Vec<_> = (0..batch_size)
			.map(|_| {
				let proof = Proof::new(proof_bytes.clone());
				let public_inputs = PublicInputs::new(public_input_bytes.clone());
				(proof, public_inputs)
			})
			.collect();

		group.throughput(Throughput::Elements(batch_size as u64));
		group.bench_with_input(
			BenchmarkId::from_parameter(batch_size),
			&batch_size,
			|b, _| {
				b.iter(|| {
					for (proof, public_inputs) in &proofs {
						let _result = Groth16Verifier::verify(
							black_box(&vk),
							black_box(public_inputs),
							black_box(proof),
						);
					}
				});
			},
		);
	}

	group.finish();
}

// ============================================================================
// 3. Verification Key Operations
// ============================================================================

fn bench_vk_operations(c: &mut Criterion) {
	let mut group = c.benchmark_group("vk_operations");
	group.sample_size(200);

	// Test con ambas VKs (transfer y unshield)
	let transfer_vk_bytes = get_transfer_vk_bytes().to_vec();
	let unshield_vk_bytes = get_unshield_vk_bytes().to_vec();

	group.bench_function("parse_transfer_vk", |b| {
		b.iter(|| {
			let _vk = VerifyingKey::new(black_box(transfer_vk_bytes.clone()));
		});
	});

	group.bench_function("parse_unshield_vk", |b| {
		b.iter(|| {
			let _vk = VerifyingKey::new(black_box(unshield_vk_bytes.clone()));
		});
	});

	// Memory footprint
	let vk = VerifyingKey::new(transfer_vk_bytes.clone());
	group.bench_function("vk_memory_footprint", |b| {
		b.iter(|| black_box(std::mem::size_of_val(&vk)));
	});

	group.finish();
}

// ============================================================================
// 4. Proof Operations
// ============================================================================

fn bench_proof_operations(c: &mut Criterion) {
	let mut group = c.benchmark_group("proof_operations");
	group.sample_size(200);

	let (_, proof_bytes, _) = generate_real_test_data();

	group.bench_function("parse_proof", |b| {
		b.iter(|| {
			let _proof = Proof::new(black_box(proof_bytes.clone()));
		});
	});

	let proof = Proof::new(proof_bytes.clone());
	group.bench_function("proof_memory_footprint", |b| {
		b.iter(|| black_box(std::mem::size_of_val(&proof)));
	});

	group.finish();
}

// ============================================================================
// 5. Public Inputs Scaling
// ============================================================================

fn bench_public_inputs_scaling(c: &mut Criterion) {
	let mut group = c.benchmark_group("public_inputs_scaling");
	group.sample_size(100);

	for &num_inputs in BenchmarkSizes::PUBLIC_INPUT_COUNTS {
		let inputs = config::test_data::mock_public_inputs(num_inputs)
			.into_iter()
			.map(|v| v.try_into().unwrap())
			.collect::<Vec<[u8; 32]>>();

		group.throughput(Throughput::Elements(num_inputs as u64));
		group.bench_with_input(
			BenchmarkId::from_parameter(num_inputs),
			&num_inputs,
			|b, _| {
				b.iter(|| {
					let _public_inputs = PublicInputs::new(black_box(inputs.clone()));
				});
			},
		);
	}

	group.finish();
}

// ============================================================================
// 6. End-to-End Workflow
// ============================================================================

fn bench_e2e_workflow(c: &mut Criterion) {
	let mut group = c.benchmark_group("e2e_workflow");
	group.sample_size(50);

	let (vk_bytes, proof_bytes, public_input_bytes) = generate_real_test_data();

	group.bench_function("full_verification_pipeline", |b| {
		b.iter(|| {
			// Simula el flujo completo que haría un usuario
			// 1. Parsear VK (puede estar cached en producción)
			let vk = VerifyingKey::new(black_box(vk_bytes.clone()));

			// 2. Parsear proof (siempre nuevo)
			let proof = Proof::new(black_box(proof_bytes.clone()));

			// 3. Parsear public inputs (siempre nuevos)
			let public_inputs = PublicInputs::new(black_box(public_input_bytes.clone()));

			// 4. Verificar
			let _result = Groth16Verifier::verify(&vk, &public_inputs, &proof);
		});
	});

	group.finish();
}

// ============================================================================
// Criterion Configuration & Main
// ============================================================================

fn get_criterion_config() -> Criterion {
	// Leer configuración desde env var o usar standard
	match std::env::var("CRITERION_CONFIG").as_deref() {
		Ok("fast") => CriterionConfig::fast(),
		Ok("production") => CriterionConfig::production(),
		Ok("batch") => CriterionConfig::batch(),
		Ok("memory") => CriterionConfig::memory(),
		_ => CriterionConfig::standard(),
	}
}

criterion_group! {
	name = benches;
	config = get_criterion_config();
	targets =
		bench_single_verification,
		bench_batch_verification,
		bench_vk_operations,
		bench_proof_operations,
		bench_public_inputs_scaling,
		bench_e2e_workflow
}

criterion_main!(benches);
