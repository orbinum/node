// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The host functions the runtime imports, which every node must provide.

/// The runtime imports `bn254_groth16_verify` (provided from node 0.4.0); a node
/// without it cannot instantiate the runtime and stops importing.
#[test]
fn the_runtime_imports_the_groth16_host_function() {
	let Some(blob) = crate::WASM_BINARY else {
		return; // SKIP_WASM_BUILD
	};
	// Release builds embed the compressed blob.
	let wasm = sp_maybe_compressed_blob::decompress(blob, 64 << 20).expect("runtime blob");
	let imports = |symbol: &[u8]| wasm.windows(symbol.len()).any(|w| w == symbol);
	assert!(imports(
		b"ext_groth_16_host_interface_bn254_groth16_verify_version_1"
	));
}
