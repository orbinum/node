//! Benchmark configuration and shared utilities
//!
//! This module provides common configuration for both:
//! - Criterion benchmarks (off-chain, development)
//! - FRAME benchmarks (on-chain, production)

use criterion::Criterion;
use std::time::Duration;

/// Criterion benchmark configuration presets
pub struct CriterionConfig;

impl CriterionConfig {
	/// Fast configuration for quick feedback during development
	pub fn fast() -> Criterion {
		Criterion::default()
			.sample_size(10)
			.measurement_time(Duration::from_secs(2))
			.warm_up_time(Duration::from_secs(1))
	}

	/// Standard configuration for regular benchmarking
	pub fn standard() -> Criterion {
		Criterion::default()
			.sample_size(100)
			.measurement_time(Duration::from_secs(10))
			.warm_up_time(Duration::from_secs(3))
	}

	/// Production configuration for accurate measurements
	pub fn production() -> Criterion {
		Criterion::default()
			.sample_size(200)
			.measurement_time(Duration::from_secs(30))
			.warm_up_time(Duration::from_secs(5))
			.significance_level(0.01)
			.confidence_level(0.99)
	}

	/// Batch verification configuration (longer measurement time)
	pub fn batch() -> Criterion {
		Criterion::default()
			.sample_size(50)
			.measurement_time(Duration::from_secs(15))
			.warm_up_time(Duration::from_secs(3))
	}

	/// Memory/parsing configuration (short, high sample count)
	pub fn memory() -> Criterion {
		Criterion::default()
			.sample_size(200)
			.measurement_time(Duration::from_secs(5))
			.warm_up_time(Duration::from_secs(1))
	}
}

/// Benchmark data sizes for testing scalability
#[allow(dead_code)]
pub struct BenchmarkSizes;

#[allow(dead_code)]
impl BenchmarkSizes {
	/// Batch sizes for testing parallel verification
	pub const BATCH_SIZES: &'static [usize] = &[1, 5, 10, 20, 50];

	/// Public input counts for testing input scaling
	pub const PUBLIC_INPUT_COUNTS: &'static [usize] = &[1, 2, 4, 8, 16];

	/// Verification key sizes (in bytes) for different circuits
	pub const VK_SIZES: &'static [usize] = &[768, 1024, 2048, 4096];
}

/// Test data generation for benchmarks
#[allow(dead_code)]
pub mod test_data {
	/// Generate deterministic verification key mock data
	pub fn mock_vk_bytes(size: usize) -> Vec<u8> {
		// Pattern: alternating 0x01, 0x02, 0x03, 0x04
		(0..size).map(|i| ((i % 4) + 1) as u8).collect()
	}

	/// Generate deterministic proof mock data
	pub fn mock_proof_bytes() -> Vec<u8> {
		// Groth16 proof: 192 bytes (3 curve points)
		vec![0x42; 192]
	}

	/// Generate deterministic public inputs
	pub fn mock_public_inputs(count: usize) -> Vec<Vec<u8>> {
		(0..count)
			.map(|i| {
				let mut input = vec![0u8; 32];
				input[0] = i as u8; // Make each input unique
				input
			})
			.collect()
	}

	/// Generate single public input (32 bytes)
	pub fn mock_single_public_input() -> Vec<u8> {
		vec![0x01; 32]
	}
}

/// FRAME benchmark configuration constants
#[allow(dead_code)]
pub mod frame_config {
	/// Number of steps for FRAME benchmarks
	pub const STEPS: u32 = 50;

	/// Number of repetitions for FRAME benchmarks
	pub const REPEAT: u32 = 20;

	/// Typical VK size for FRAME benchmarks (matches mock data)
	pub const VK_SIZE: usize = 768;

	/// Typical proof size for FRAME benchmarks
	pub const PROOF_SIZE: usize = 192;

	/// Default number of public inputs for FRAME benchmarks
	pub const PUBLIC_INPUTS_COUNT: usize = 1;
}

#[cfg(test)]
mod tests {
	#[allow(unused_imports)]
	use super::test_data;

	#[test]
	fn test_mock_data_sizes() {
		assert_eq!(test_data::mock_vk_bytes(768).len(), 768);
		assert_eq!(test_data::mock_proof_bytes().len(), 192);
		assert_eq!(test_data::mock_single_public_input().len(), 32);
	}

	#[test]
	fn test_mock_public_inputs_unique() {
		let inputs = test_data::mock_public_inputs(5);
		assert_eq!(inputs.len(), 5);
		// Verify each input is unique
		for (i, input) in inputs.iter().enumerate() {
			assert_eq!(input[0], i as u8);
		}
	}
}
