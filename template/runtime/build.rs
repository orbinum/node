fn main() {
	#[cfg(feature = "std")]
	{
		let mut builder = substrate_wasm_builder::WasmBuilder::new()
			.with_current_project()
			.export_heap_base()
			.import_memory();

		// Poseidon (~3×) and Groth16 (~3.5×) through host functions. Not for try-runtime:
		// its stock executor lacks these host interfaces, so it gets pure Wasm.
		if std::env::var("CARGO_FEATURE_TRY_RUNTIME").is_err() {
			builder = builder
				.enable_feature("poseidon-native-runtime")
				.enable_feature("groth16-native-runtime");
		}

		builder.enable_metadata_hash("ORB", 18).build();
	}
}
