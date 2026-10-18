/// Spec 19 imports `bn254_groth16_verify`, registered since node 0.4.0. A
/// node without it cannot instantiate the runtime and stops importing.
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
