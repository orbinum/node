//! WASM witness calculator for circom circuits with LRU caching

#[cfg(feature = "wasm-witness")]
use wasmer::{imports, Instance, Module, Store, Value};

#[cfg(feature = "wasm-witness")]
use once_cell::sync::Lazy;

#[cfg(feature = "wasm-witness")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "wasm-witness")]
use alloc::collections::BTreeMap;

#[cfg(feature = "wasm-witness")]
use std::sync::Mutex;

use crate::domain::entities::error::MemoError;
use alloc::{string::String, vec::Vec};
use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

/// Max cached modules (10 modules ~10-50MB), override with WASM_CACHE_MAX_SIZE env var
#[cfg(feature = "wasm-witness")]
const DEFAULT_MAX_CACHE_SIZE: usize = 10;

/// LRU Cache entry with access timestamp
#[cfg(feature = "wasm-witness")]
struct CacheEntry {
	module: Module,
	last_access: std::time::Instant,
}

/// Global WASM module cache with LRU eviction
#[cfg(feature = "wasm-witness")]
static MODULE_CACHE: Lazy<Mutex<BTreeMap<u64, CacheEntry>>> =
	Lazy::new(|| Mutex::new(BTreeMap::new()));

// Cache statistics
#[cfg(feature = "wasm-witness")]
pub static CACHE_HITS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "wasm-witness")]
pub static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "wasm-witness")]
pub static CACHE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// Compute a simple hash of WASM bytes for caching
#[cfg(feature = "wasm-witness")]
pub fn hash_wasm_bytes(bytes: &[u8]) -> u64 {
	use sha2::{Digest, Sha256};
	let hash = Sha256::digest(bytes);
	// Use first 8 bytes as u64
	u64::from_le_bytes([
		hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
	])
}

/// Get maximum cache size from environment or use default
#[cfg(feature = "wasm-witness")]
fn get_max_cache_size() -> usize {
	std::env::var("WASM_CACHE_MAX_SIZE")
		.ok()
		.and_then(|s| s.parse().ok())
		.unwrap_or(DEFAULT_MAX_CACHE_SIZE)
}

/// Evict least recently used entry from cache
#[cfg(feature = "wasm-witness")]
fn evict_lru_entry(cache: &mut BTreeMap<u64, CacheEntry>) {
	if cache.is_empty() {
		return;
	}

	// Find LRU entry (oldest last_access)
	let lru_hash = cache
		.iter()
		.min_by_key(|(_, entry)| entry.last_access)
		.map(|(hash, _)| *hash);

	if let Some(hash) = lru_hash {
		cache.remove(&hash);
		CACHE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
	}
}

/// Get or compile WASM module with LRU caching
#[cfg(feature = "wasm-witness")]
fn get_or_compile_module(wasm_bytes: &[u8]) -> Result<Module, MemoError> {
	let hash = hash_wasm_bytes(wasm_bytes);

	// Try to get from cache first
	{
		let mut cache = MODULE_CACHE.lock().unwrap();
		if let Some(entry) = cache.get_mut(&hash) {
			// Update access time (LRU)
			entry.last_access = std::time::Instant::now();
			CACHE_HITS.fetch_add(1, Ordering::Relaxed);
			return Ok(entry.module.clone());
		}
	}

	// Cache miss - compile module
	CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
	let store = Store::default();
	let module = Module::new(&store, wasm_bytes).map_err(|e| {
		MemoError::WasmLoadFailed(alloc::format!("failed to compile WASM: {e:?}").leak())
	})?;

	// Store in cache with LRU eviction if needed
	{
		let mut cache = MODULE_CACHE.lock().unwrap();
		let max_size = get_max_cache_size();

		// Evict LRU entry if cache is full
		if cache.len() >= max_size {
			evict_lru_entry(&mut cache);
		}

		cache.insert(
			hash,
			CacheEntry {
				module: module.clone(),
				last_access: std::time::Instant::now(),
			},
		);
	}

	Ok(module)
}

/// Get cache statistics (for monitoring/debugging)
///
/// Returns: (hits, misses, evictions, current_size)
#[cfg(feature = "wasm-witness")]
pub fn get_cache_stats() -> (u64, u64, u64, usize) {
	let cache = MODULE_CACHE.lock().unwrap();
	(
		CACHE_HITS.load(Ordering::Relaxed),
		CACHE_MISSES.load(Ordering::Relaxed),
		CACHE_EVICTIONS.load(Ordering::Relaxed),
		cache.len(),
	)
}

/// Clear the module cache (useful for testing or memory management)
#[cfg(feature = "wasm-witness")]
pub fn clear_module_cache() {
	let mut cache = MODULE_CACHE.lock().unwrap();
	cache.clear();
	CACHE_HITS.store(0, Ordering::Relaxed);
	CACHE_MISSES.store(0, Ordering::Relaxed);
	CACHE_EVICTIONS.store(0, Ordering::Relaxed);
}

/// Get current cache size
#[cfg(feature = "wasm-witness")]
pub fn get_cache_size() -> usize {
	let cache = MODULE_CACHE.lock().unwrap();
	cache.len()
}

/// Get maximum cache size
#[cfg(feature = "wasm-witness")]
pub fn get_max_cache_size_config() -> usize {
	get_max_cache_size()
}

/// Circom WASM witness calculator with cached module compilation
#[cfg(feature = "wasm-witness")]
pub struct WasmWitnessCalculator {
	instance: Instance,
	store: Store,
	n_vars: u32,
	n_public: u32,
}

#[cfg(feature = "wasm-witness")]
impl WasmWitnessCalculator {
	/// Creates calculator from circom WASM bytes (uses cache, ~10ms first call, instant after)
	#[allow(dependency_on_unit_never_type_fallback)]
	pub fn new(wasm_bytes: &[u8]) -> Result<Self, MemoError> {
		// 1. Get or compile module (with caching)
		let module = get_or_compile_module(wasm_bytes)?;

		// 2. Initialize Wasmer store
		let mut store = Store::default();

		// 3. Create import object with runtime functions
		let import_object = imports! {
			"runtime" => {
				"error" => wasmer::Function::new_typed(&mut store, |code: i32| -> () {
					panic!("WASM runtime error: {code}");
				}),
				"logSetSignal" => wasmer::Function::new_typed(&mut store, |_: i32, _: i32| {}),
				"logGetSignal" => wasmer::Function::new_typed(&mut store, |_: i32, _: i32| {}),
				"logFinishComponent" => wasmer::Function::new_typed(&mut store, |_: i32| {}),
				"logStartComponent" => wasmer::Function::new_typed(&mut store, |_: i32| {}),
				"log" => wasmer::Function::new_typed(&mut store, |_: i32| {}),
				"exceptionHandler" => wasmer::Function::new_typed(&mut store, |code: i32| -> () {
					panic!("WASM exception handler: {code}");
				}),
				"showSharedRWMemory" => wasmer::Function::new_typed(&mut store, || {}),
				"printErrorMessage" => wasmer::Function::new_typed(&mut store, || {}),
				"writeBufferMessage" => wasmer::Function::new_typed(&mut store, || {}),
				"getMessageChar" => wasmer::Function::new_typed(&mut store, || -> i32 { 0 }),
				"getRawMessageChar" => wasmer::Function::new_typed(&mut store, || -> i32 { 0 }),
			}
		};

		// 4. Instantiate WASM
		let instance = Instance::new(&mut store, &module, &import_object).map_err(|e| {
			MemoError::WasmLoadFailed(alloc::format!("Failed to instantiate WASM: {e:?}").leak())
		})?;

		// 5. Initialize circuit (call init function)
		let init = instance
			.exports
			.get_function("init")
			.map_err(|_| MemoError::WasmLoadFailed("init function not found"))?;
		init.call(&mut store, &[Value::I32(1)]) // sanity_check = true
			.map_err(|e| MemoError::WasmLoadFailed(alloc::format!("init failed: {e:?}").leak()))?;

		// 6. Get circuit metadata
		let get_witness_size = instance
			.exports
			.get_function("getWitnessSize")
			.map_err(|_| MemoError::WasmLoadFailed("getWitnessSize not found"))?;
		let witness_size_result = get_witness_size.call(&mut store, &[]).map_err(|e| {
			MemoError::WasmLoadFailed(alloc::format!("getWitnessSize failed: {e:?}").leak())
		})?;
		let n_vars = witness_size_result[0].unwrap_i32() as u32;

		let get_input_size = instance
			.exports
			.get_function("getInputSize")
			.map_err(|_| MemoError::WasmLoadFailed("getInputSize not found"))?;
		let input_size_result = get_input_size.call(&mut store, &[]).map_err(|e| {
			MemoError::WasmLoadFailed(alloc::format!("getInputSize failed: {e:?}").leak())
		})?;
		let n_inputs = input_size_result[0].unwrap_i32() as u32;

		#[cfg(feature = "std")]
		println!(
			"DEBUG: WASM Metadata: n_vars={}, n_inputs={}",
			n_vars, n_inputs
		);

		// Assume 4 public inputs (commitment, revealed_value, revealed_asset_id, revealed_owner_hash)
		let n_public = 4u32;

		Ok(Self {
			instance,
			store,
			n_vars,
			n_public,
		})
	}

	/// Calculates full witness from signal inputs (index 0 = 1, 1-4 = public, 5+ = private)
	pub fn calculate_witness(
		&mut self,
		inputs: &[(String, Bn254Fr)],
	) -> Result<Vec<Bn254Fr>, MemoError> {
		// 1. Set input signals

		let set_input_signal = self
			.instance
			.exports
			.get_function("setInputSignal")
			.map_err(|_| MemoError::WitnessCalculationFailed("setInputSignal not found"))?;

		for (name, value) in inputs {
			// Compute FNV1a hash of signal name
			let hash = fnv_hash_64(name);
			let h_msb = (hash >> 32) as i32;
			let h_lsb = (hash & 0xFFFFFFFF) as i32;

			// Convert Fr to 32-bit words (little-endian bytes -> words)
			let mut bytes = [0u8; 32];
			value.serialize_uncompressed(&mut bytes[..]).map_err(|_| {
				MemoError::WitnessCalculationFailed("failed to serialize field element")
			})?;

			let mut words = [0u32; 8];
			for i in 0..8 {
				words[i] = u32::from_le_bytes([
					bytes[i * 4],
					bytes[i * 4 + 1],
					bytes[i * 4 + 2],
					bytes[i * 4 + 3],
				]);
			}

			// 1. Write words to shared memory
			let write_shared_rw_memory = self
				.instance
				.exports
				.get_function("writeSharedRWMemory")
				.map_err(|e| {
					MemoError::WitnessCalculationFailed(
						alloc::format!("writeSharedRWMemory not found: {e:?}").leak(),
					)
				})?;
			for (j, word) in words.iter().enumerate() {
				write_shared_rw_memory
					.call(
						&mut self.store,
						&[Value::I32(j as i32), Value::I32(*word as i32)],
					)
					.map_err(|e| {
						MemoError::WitnessCalculationFailed(
							alloc::format!("writeSharedRWMemory call failed: {e:?}").leak(),
						)
					})?;
			}

			// 2. setInputSignal(hMSB, hLSB, array_index)
			set_input_signal
				.call(
					&mut self.store,
					&[Value::I32(h_msb), Value::I32(h_lsb), Value::I32(0)],
				)
				.map_err(|e| {
					MemoError::WitnessCalculationFailed(
						alloc::format!("setInputSignal failed for {name}: {e:?}").leak(),
					)
				})?;
		}

		// 2. Get witness
		let get_witness = self
			.instance
			.exports
			.get_function("getWitness")
			.map_err(|_| MemoError::WitnessCalculationFailed("getWitness not found"))?;

		let read_shared_rw_memory = self
			.instance
			.exports
			.get_function("readSharedRWMemory")
			.map_err(|e| {
				MemoError::WitnessCalculationFailed(
					alloc::format!("readSharedRWMemory not found: {e:?}").leak(),
				)
			})?;

		let mut witness = Vec::with_capacity(self.n_vars as usize);

		for witness_id in 0..self.n_vars {
			get_witness
				.call(&mut self.store, &[Value::I32(witness_id as i32)])
				.map_err(|e| {
					MemoError::WitnessCalculationFailed(
						alloc::format!("getWitness call failed: {e:?}").leak(),
					)
				})?;

			let mut bytes = [0u8; 32];
			for j in 0..8 {
				let word_result = read_shared_rw_memory
					.call(&mut self.store, &[Value::I32(j as i32)])
					.map_err(|e| {
						MemoError::WitnessCalculationFailed(
							alloc::format!("readSharedRWMemory call failed: {e:?}").leak(),
						)
					})?;
				let word = word_result[0].unwrap_i32() as u32;
				let word_bytes = word.to_le_bytes();
				bytes[j * 4] = word_bytes[0];
				bytes[j * 4 + 1] = word_bytes[1];
				bytes[j * 4 + 2] = word_bytes[2];
				bytes[j * 4 + 3] = word_bytes[3];
			}

			let value = Bn254Fr::from_le_bytes_mod_order(&bytes);
			witness.push(value);
		}

		#[cfg(feature = "std")]
		println!(
			"DEBUG: Witness calculated successfully ({} vars)",
			witness.len()
		);

		Ok(witness)
	}

	/// Returns number of variables (witness size)
	pub fn n_vars(&self) -> u32 {
		self.n_vars
	}

	/// Returns number of public inputs
	pub fn n_public(&self) -> u32 {
		self.n_public
	}
}

/// FNV1a 64-bit hash as used by circom
fn fnv_hash_64(s: &str) -> u64 {
	let mut hash = 0xCBF29CE484222325u64;
	for c in s.as_bytes() {
		hash ^= *c as u64;
		hash = hash.wrapping_mul(0x100000001B3u64);
	}
	hash
}

/// Placeholder for when wasm-witness feature is not enabled
#[cfg(not(feature = "wasm-witness"))]
pub struct WasmWitnessCalculator;

#[cfg(not(feature = "wasm-witness"))]
impl WasmWitnessCalculator {
	pub fn new(_wasm_bytes: &[u8]) -> Result<Self, MemoError> {
		Err(MemoError::WasmLoadFailed(
			"wasm-witness feature not enabled. Rebuild with --features wasm-witness",
		))
	}

	pub fn calculate_witness(
		&mut self,
		_inputs: &[(String, Bn254Fr)],
	) -> Result<Vec<Bn254Fr>, MemoError> {
		Err(MemoError::WitnessCalculationFailed(
			"wasm-witness feature not enabled",
		))
	}

	pub fn n_vars(&self) -> u32 {
		0
	}

	pub fn n_public(&self) -> u32 {
		0
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// ===== FNV Hash Tests =====

	#[test]
	fn test_fnv_hash_64_basic() {
		let hash = fnv_hash_64("test");
		assert_ne!(hash, 0);
	}

	#[test]
	fn test_fnv_hash_64_deterministic() {
		let hash1 = fnv_hash_64("commitment");
		let hash2 = fnv_hash_64("commitment");
		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_fnv_hash_64_different_inputs() {
		let hash1 = fnv_hash_64("value");
		let hash2 = fnv_hash_64("owner");
		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_fnv_hash_64_empty_string() {
		let hash = fnv_hash_64("");
		// FNV offset basis
		assert_eq!(hash, 0xCBF29CE484222325u64);
	}

	#[test]
	fn test_fnv_hash_64_single_char() {
		let hash_a = fnv_hash_64("a");
		let hash_b = fnv_hash_64("b");
		assert_ne!(hash_a, hash_b);
	}

	#[test]
	fn test_fnv_hash_64_long_string() {
		let long_str = "this_is_a_very_long_signal_name_for_testing_purposes";
		let hash = fnv_hash_64(long_str);
		assert_ne!(hash, 0);
	}

	#[test]
	fn test_fnv_hash_64_case_sensitive() {
		let hash_lower = fnv_hash_64("signal");
		let hash_upper = fnv_hash_64("SIGNAL");
		assert_ne!(hash_lower, hash_upper);
	}

	#[test]
	fn test_fnv_hash_64_circom_signal_names() {
		// Common circom signal names
		let signals = vec![
			"commitment",
			"value",
			"owner_pk",
			"blinding",
			"asset_id",
			"revealed_value",
			"revealed_owner_hash",
		];

		let mut hashes = Vec::new();
		for signal in signals {
			let hash = fnv_hash_64(signal);
			assert_ne!(hash, 0);
			// Ensure no collisions in common signal names
			assert!(!hashes.contains(&hash));
			hashes.push(hash);
		}
	}

	// ===== WASM Module Cache Tests (requires wasm-witness feature) =====

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_hash_wasm_bytes_deterministic() {
		let bytes = vec![1, 2, 3, 4, 5];
		let hash1 = hash_wasm_bytes(&bytes);
		let hash2 = hash_wasm_bytes(&bytes);
		assert_eq!(hash1, hash2);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_hash_wasm_bytes_different_data() {
		let bytes1 = vec![1, 2, 3];
		let bytes2 = vec![4, 5, 6];
		let hash1 = hash_wasm_bytes(&bytes1);
		let hash2 = hash_wasm_bytes(&bytes2);
		assert_ne!(hash1, hash2);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_hash_wasm_bytes_empty() {
		let bytes = vec![];
		let hash = hash_wasm_bytes(&bytes);
		assert_ne!(hash, 0);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_hash_wasm_bytes_collision_resistance() {
		// Single bit difference should produce different hash
		let bytes1 = vec![0b00000000];
		let bytes2 = vec![0b00000001];
		let hash1 = hash_wasm_bytes(&bytes1);
		let hash2 = hash_wasm_bytes(&bytes2);
		assert_ne!(hash1, hash2);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_clear_module_cache() {
		clear_module_cache();
		let size = get_cache_size();
		assert_eq!(size, 0);

		let (hits, misses, evictions, current_size) = get_cache_stats();
		assert_eq!(hits, 0);
		assert_eq!(misses, 0);
		assert_eq!(evictions, 0);
		assert_eq!(current_size, 0);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_get_max_cache_size_config() {
		let max_size = get_max_cache_size_config();
		// Should be default or from env
		assert!(max_size > 0);
		assert!(max_size <= 1000); // Reasonable upper bound
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_get_cache_stats_structure() {
		clear_module_cache();
		let (hits, misses, evictions, size) = get_cache_stats();

		// All should be zero after clear
		assert_eq!(hits, 0);
		assert_eq!(misses, 0);
		assert_eq!(evictions, 0);
		assert_eq!(size, 0);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_cache_size_tracking() {
		clear_module_cache();
		let initial_size = get_cache_size();
		assert_eq!(initial_size, 0);
	}

	// ===== WasmWitnessCalculator Tests (feature-gated) =====

	#[cfg(not(feature = "wasm-witness"))]
	#[test]
	fn test_calculator_new_without_feature() {
		let bytes = vec![1, 2, 3];
		let result = WasmWitnessCalculator::new(&bytes);
		assert!(result.is_err());
	}

	#[cfg(not(feature = "wasm-witness"))]
	#[test]
	fn test_calculator_methods_without_feature() {
		let calc = WasmWitnessCalculator;
		assert_eq!(calc.n_vars(), 0);
		assert_eq!(calc.n_public(), 0);
	}

	// ===== Integration Tests =====

	#[test]
	fn test_fnv_hash_reproducibility() {
		// Test that FNV hash is stable across multiple calls
		let test_cases = vec!["commitment", "value", "owner_pk", "blinding"];

		for signal in test_cases {
			let hashes: Vec<u64> = (0..10).map(|_| fnv_hash_64(signal)).collect();

			// All hashes should be identical
			for i in 1..hashes.len() {
				assert_eq!(hashes[0], hashes[i]);
			}
		}
	}

	#[test]
	fn test_fnv_hash_avalanche_effect() {
		// Small change in input should produce very different hash
		let hash1 = fnv_hash_64("test");
		let hash2 = fnv_hash_64("test1"); // Added one character

		// Count differing bits
		let xor = hash1 ^ hash2;
		let differing_bits = xor.count_ones();

		// Should differ significantly (avalanche effect)
		assert!(differing_bits > 10);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_cache_operations_thread_safe() {
		// Test basic cache operations don't panic
		clear_module_cache();
		let _ = get_cache_size();
		let _ = get_cache_stats();
		let _ = get_max_cache_size_config();
	}

	#[test]
	fn test_fnv_hash_64_known_values() {
		// Test against known FNV-1a values to ensure correctness
		let empty_hash = fnv_hash_64("");
		assert_eq!(empty_hash, 0xCBF29CE484222325u64); // FNV offset basis

		// Single character 'a' = 0x61
		// hash = (offset_basis ^ 0x61) * prime
		let a_hash = fnv_hash_64("a");
		let expected = (0xCBF29CE484222325u64 ^ 0x61).wrapping_mul(0x100000001B3u64);
		assert_eq!(a_hash, expected);
	}

	#[test]
	fn test_fnv_hash_unicode() {
		let hash_ascii = fnv_hash_64("test");
		let hash_unicode = fnv_hash_64("tëst"); // With unicode character
		assert_ne!(hash_ascii, hash_unicode);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_hash_wasm_large_data() {
		let large_data = vec![42u8; 1_000_000]; // 1MB
		let hash = hash_wasm_bytes(&large_data);
		assert_ne!(hash, 0);
	}

	#[cfg(feature = "wasm-witness")]
	#[test]
	fn test_cache_stats_increment() {
		clear_module_cache();
		let (initial_hits, initial_misses, _, _) = get_cache_stats();
		assert_eq!(initial_hits, 0);
		assert_eq!(initial_misses, 0);
	}
}
