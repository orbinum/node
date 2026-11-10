//! The host functions each build registers.

use super::HostFunctions;
use sc_executor::HostFunctions as _;

fn host_functions() -> Vec<&'static str> {
	HostFunctions::host_functions()
		.iter()
		.map(|f| f.name())
		.collect()
}

/// Every build registers `bn254_groth16_verify`, so a later runtime can call it on
/// any node from this release on.
#[test]
fn registers_the_groth16_host_function() {
	assert!(
		host_functions().contains(&"ext_groth_16_host_interface_bn254_groth16_verify_version_1")
	);
}

#[test]
fn registers_poseidon_only_with_poseidon_native() {
	let registered =
		host_functions().contains(&"ext_poseidon_host_interface_poseidon_hash_2_version_1");
	assert_eq!(registered, cfg!(feature = "poseidon-native"));
}

#[test]
fn registers_benchmarking_only_with_runtime_benchmarks() {
	let registered = host_functions().contains(&"ext_benchmarking_current_time_version_1");
	assert_eq!(registered, cfg!(feature = "runtime-benchmarks"));
}

#[test]
fn registers_each_host_function_once() {
	let mut names = host_functions();
	let total = names.len();
	names.sort_unstable();
	names.dedup();
	assert_eq!(names.len(), total);
}
