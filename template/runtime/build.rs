fn main() {
	#[cfg(feature = "std")]
	{
		let mut builder = substrate_wasm_builder::WasmBuilder::new()
			.with_current_project()
			.export_heap_base()
			.import_memory();

		// Poseidon via host functions (~3× faster). Skipped for try-runtime
		// builds: the stock try-runtime CLI executor lacks the custom host
		// interface, so those builds fall back to the pure-wasm hasher.
		if std::env::var("CARGO_FEATURE_TRY_RUNTIME").is_err() {
			builder = builder.enable_feature("poseidon-native-runtime");
		}

		builder.enable_metadata_hash("ORB", 18).build();
	}
}
