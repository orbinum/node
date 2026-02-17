//! Criterion benchmarks for pallet-zk-verifier
//!
//! ## Purpose
//!
//! These benchmarks measure the pure cryptographic performance of the Groth16 verifier,
//! without FRAME overhead. They are useful for:
//! - Optimizing cryptographic implementation
//! - Comparing different verification strategies
//! - Measuring the impact of code changes
//!
//! ## Run
//!
//! ```bash
//! # All benchmarks
//! cargo bench --package pallet-zk-verifier
//!
//! # Specific benchmark
//! cargo bench --package pallet-zk-verifier -- single_verification
//!
//! # With custom configuration
//! CRITERION_CONFIG=production cargo bench --package pallet-zk-verifier
//!
//! # View HTML results
//! open target/criterion/report/index.html
//! ```
//!
//! ## Structure
//!
//! 1. **Single Verification**: Proof verification time
//! 2. **Batch Verification**: Throughput with multiple proofs
//! 3. **VK Parsing**: VK parsing/deserialization time
//! 4. **Proof Parsing**: Proof parsing time
//! 5. **Public Inputs Scaling**: Impact of number of inputs
//! 6. **Memory Usage**: Memory footprint
//!
//! ## Configuration
//!
//! The `config` module provides Criterion presets:
//! - `fast()`: Fast development (10 samples, 2s)
//! - `standard()`: Regular (100 samples, 10s)
//! - `production()`: Production (200 samples, 30s)

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

mod config;
use config::{BenchmarkSizes, CriterionConfig};

// ============================================================================
// Real Test Data (using hardcoded VKs from primitives)
// ============================================================================

use orbinum_zk_verifier::{
	domain::value_objects::{Proof, PublicInputs, VerifyingKey},
	infrastructure::{
		Groth16Verifier,
		storage::verification_keys::{
			get_disclosure_vk_bytes, get_transfer_vk_bytes, get_unshield_vk_bytes,
		},
	},
};

/// Generate real test data using hardcoded VKs
fn generate_real_test_data() -> (Vec<u8>, Vec<u8>, Vec<[u8; 32]>) {
	// Real VK from transfer circuit (hardcoded in primitives)
	let vk_bytes = get_transfer_vk_bytes().to_vec();

	// For proof and public inputs, we use mock data with valid format
	// TODO: When we have real proofs from circuits, use those
	let proof_bytes = config::test_data::mock_proof_bytes();
	let public_inputs = vec![
		config::test_data::mock_single_public_input()
			.try_into()
			.unwrap(),
	];

	(vk_bytes, proof_bytes, public_inputs)
}

/// Generate test data for disclosure circuit (4 public inputs)
fn generate_disclosure_test_data() -> (Vec<u8>, Vec<u8>, Vec<[u8; 32]>) {
	// Real VK from disclosure circuit (hardcoded in primitives)
	let vk_bytes = get_disclosure_vk_bytes().to_vec();

	// For proof, use mock data with valid format
	// TODO: When we have real disclosure proofs, use those
	let proof_bytes = config::test_data::mock_proof_bytes();

	// Disclosure has 4 public inputs:
	// 1. commitment (32 bytes)
	// 2. revealed_value (32 bytes, u64 padded)
	// 3. revealed_asset_id (32 bytes, u32 padded)
	// 4. revealed_owner_hash (32 bytes)
	let mut public_inputs = Vec::with_capacity(4);

	// 1. commitment
	let mut commitment = [0u8; 32];
	commitment[0] = 0x01;
	public_inputs.push(commitment);

	// 2. revealed_value (u64 = 1000 in little-endian, padded to 32 bytes)
	let mut revealed_value = [0u8; 32];
	revealed_value[..8].copy_from_slice(&1000u64.to_le_bytes());
	public_inputs.push(revealed_value);

	// 3. revealed_asset_id (u32 = 1 in little-endian, padded to 32 bytes)
	let mut revealed_asset_id = [0u8; 32];
	revealed_asset_id[..4].copy_from_slice(&1u32.to_le_bytes());
	public_inputs.push(revealed_asset_id);

	// 4. revealed_owner_hash
	let mut owner_hash = [0u8; 32];
	owner_hash[0] = 0x0A;
	public_inputs.push(owner_hash);

	(vk_bytes, proof_bytes, public_inputs)
}

// ============================================================================
// 1. Single Verification Benchmark
// ============================================================================

fn bench_single_verification(c: &mut Criterion) {
	let mut group = c.benchmark_group("single_verification");
	group.sample_size(100);

	let (vk_bytes, proof_bytes, public_input_bytes) = generate_real_test_data();

	// Pre-parse structures (outside benchmark)
	let vk = VerifyingKey::new(vk_bytes.clone());
	let proof = Proof::new(proof_bytes.clone());
	let public_inputs = PublicInputs::new(public_input_bytes.clone());

	group.bench_function("groth16_verify", |b| {
		b.iter(|| {
			// Only measure verification time
			let _result = Groth16Verifier::verify(
				black_box(&vk),
				black_box(&public_inputs),
				black_box(&proof),
			);
			// Note: May fail because they are mock data, but we measure the time
		});
	});

	// Benchmark with parsing included
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
		// Pre-generate all proofs
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

	// Test with both VKs (transfer and unshield)
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
// 7. Disclosure Circuit Benchmarks
// ============================================================================

fn bench_disclosure_single_verification(c: &mut Criterion) {
	let mut group = c.benchmark_group("disclosure_single_verification");
	group.sample_size(100);

	let (vk_bytes, proof_bytes, public_input_bytes) = generate_disclosure_test_data();

	// Pre-parse structures (outside benchmark)
	let vk = VerifyingKey::new(vk_bytes.clone());
	let proof = Proof::new(proof_bytes.clone());
	let public_inputs = PublicInputs::new(public_input_bytes.clone());

	group.bench_function("disclosure_verify", |b| {
		b.iter(|| {
			// Only measure verification time for disclosure circuit
			let _result = Groth16Verifier::verify(
				black_box(&vk),
				black_box(&public_inputs),
				black_box(&proof),
			);
			// Note: May fail because they are mock data, but we measure the time
		});
	});

	// Benchmark with parsing included
	group.bench_function("disclosure_verify_with_parsing", |b| {
		b.iter(|| {
			let vk = VerifyingKey::new(black_box(vk_bytes.clone()));
			let proof = Proof::new(black_box(proof_bytes.clone()));
			let public_inputs = PublicInputs::new(black_box(public_input_bytes.clone()));
			let _result = Groth16Verifier::verify(&vk, &public_inputs, &proof);
		});
	});

	group.finish();
}

fn bench_disclosure_batch_verification(c: &mut Criterion) {
	let mut group = c.benchmark_group("disclosure_batch_verification");
	group.sample_size(50);

	let (vk_bytes, proof_bytes, public_input_bytes) = generate_disclosure_test_data();
	let vk = VerifyingKey::new(vk_bytes);

	for &batch_size in BenchmarkSizes::BATCH_SIZES {
		// Pre-generate all disclosure proofs
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

fn bench_disclosure_public_inputs_construction(c: &mut Criterion) {
	let mut group = c.benchmark_group("disclosure_public_inputs");
	group.sample_size(200);

	// Benchmark constructing public inputs from raw disclosure data
	group.bench_function("construct_from_76_bytes", |b| {
		b.iter(|| {
			// Simulate receiving 76 bytes: commitment(32) + value(8) + asset_id(4) + owner_hash(32)
			let mut signals = Vec::with_capacity(76);
			signals.extend_from_slice(&[1u8; 32]); // commitment
			signals.extend_from_slice(&1000u64.to_le_bytes()); // revealed_value
			signals.extend_from_slice(&1u32.to_le_bytes()); // revealed_asset_id
			signals.extend_from_slice(&[0xAu8; 32]); // revealed_owner_hash

			// Convert to 4 padded inputs (as done in verify_disclosure_proof)
			let mut commitment = [0u8; 32];
			commitment.copy_from_slice(&signals[0..32]);

			let mut revealed_value = [0u8; 32];
			revealed_value[..8].copy_from_slice(&signals[32..40]);

			let mut revealed_asset_id = [0u8; 32];
			revealed_asset_id[..4].copy_from_slice(&signals[40..44]);

			let mut owner_hash = [0u8; 32];
			owner_hash.copy_from_slice(&signals[44..76]);

			let inputs = vec![commitment, revealed_value, revealed_asset_id, owner_hash];
			let _public_inputs = PublicInputs::new(black_box(inputs));
		});
	});

	group.finish();
}

// ============================================================================
// 8. End-to-End Workflow Benchmark
// ============================================================================

fn bench_e2e_workflow(c: &mut Criterion) {
	let mut group = c.benchmark_group("e2e_workflow");
	group.sample_size(50);

	let (vk_bytes, proof_bytes, public_input_bytes) = generate_real_test_data();

	group.bench_function("full_verification_pipeline", |b| {
		b.iter(|| {
			// Simulate the full flow a user would perform
			// 1. Parse VK (may be cached in production)
			let vk = VerifyingKey::new(black_box(vk_bytes.clone()));

			// 2. Parse proof (always new)
			let proof = Proof::new(black_box(proof_bytes.clone()));

			// 3. Parse public inputs (always new)
			let public_inputs = PublicInputs::new(black_box(public_input_bytes.clone()));

			// 4. Verify
			let _result = Groth16Verifier::verify(&vk, &public_inputs, &proof);
		});
	});

	group.finish();
}

// ============================================================================
// Criterion Configuration & Main
// ============================================================================

fn get_criterion_config() -> Criterion {
	// Read configuration from env var or use standard
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
		bench_disclosure_single_verification,
		bench_disclosure_batch_verification,
		bench_disclosure_public_inputs_construction,
		bench_e2e_workflow
}

criterion_main!(benches);
