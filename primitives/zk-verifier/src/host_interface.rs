#![allow(unexpected_cfgs)]
//! Groth16 verification as a native host function (~3.5× faster than Wasm).
//!
//! - **Frozen.** Executed blocks call version 1 and syncing nodes re-run them:
//!   any observable change is a new `#[version(N)]`, and version 1 stays.
//! - **Imported from spec 19.** Registered `register_only` since node 0.4.0;
//!   a node without it cannot instantiate a runtime that imports it.

use alloc::vec::Vec;
use sp_runtime_interface::{pass_by::PassFatPointerAndRead, runtime_interface};

/// Groth16 verification over BN254, natively.
#[runtime_interface]
pub trait Groth16HostInterface {
	/// [`crate::verify_prepared`], natively. It must never panic: natively a
	/// panic takes the node down instead of trapping the runtime.
	#[version(1)]
	fn bn254_groth16_verify(
		prepared_vk: PassFatPointerAndRead<&[u8]>,
		proof: PassFatPointerAndRead<&[u8]>,
		inputs: PassFatPointerAndRead<&[u8]>,
	) -> bool {
		crate::verify_prepared(prepared_vk, proof, inputs)
	}
}

#[cfg(all(test, feature = "std"))]
mod tests {
	use sp_runtime_interface::sp_wasm_interface::HostFunctions;

	/// The symbol runtimes import. Renaming the trait or the function changes
	/// it, and a runtime built against the old one would not instantiate.
	#[test]
	fn the_registered_symbol_is_frozen() {
		let names: alloc::vec::Vec<_> =
			super::groth_16_host_interface::HostFunctions::host_functions()
				.iter()
				.map(|f| f.name())
				.collect();
		assert_eq!(
			names,
			["ext_groth_16_host_interface_bn254_groth16_verify_version_1"]
		);
	}
}
