fn main() {
	#[cfg(feature = "std")]
	{
		let mut builder = substrate_wasm_builder::WasmBuilder::new()
			.with_current_project()
			.export_heap_base()
			.import_memory();

		// Poseidon (~3×) and Groth16 (~3.5×) via host functions. Skipped for
		// try-runtime builds: the stock try-runtime CLI executor lacks the
		// custom host interfaces, so those builds fall back to pure Wasm.
		if std::env::var("CARGO_FEATURE_TRY_RUNTIME").is_err() {
			builder = builder
				.enable_feature("poseidon-native-runtime")
				.enable_feature("groth16-native-runtime");
		}

		builder.enable_metadata_hash("ORB", 18).build();
	}
}
