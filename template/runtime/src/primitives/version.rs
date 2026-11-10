//! The runtime version.

use crate::apis::RUNTIME_API_VERSIONS;
use alloc::borrow::Cow;
use sp_version::RuntimeVersion;

/// `#[runtime_version]` only reads literals, so the spec name is spliced in as a
/// token tree rather than a `const`.
macro_rules! runtime_version {
	($spec_name:tt) => {
		#[sp_version::runtime_version]
		pub const VERSION: RuntimeVersion = RuntimeVersion {
			spec_name: Cow::Borrowed($spec_name),
			impl_name: Cow::Borrowed("orbinum"),
			authoring_version: 1,
			spec_version: 21,
			impl_version: 1,
			apis: RUNTIME_API_VERSIONS,
			transaction_version: 8,
			system_version: 1,
		};
	};
}

#[cfg(not(any(feature = "fast-runtime", feature = "runtime-benchmarks")))]
runtime_version!("orbinum");
// Local-only builds take their own spec name, so `set_code` rejects them on any chain
// running the real runtime and the release workflow refuses to ship them:
// `fast-runtime` shortens sessions and eras; `runtime-benchmarks` opens benchmark-only
// paths (unfiltered candidates, zero bonds, a unit existential deposit).
#[cfg(all(feature = "fast-runtime", not(feature = "runtime-benchmarks")))]
runtime_version!("orbinum-fast");
#[cfg(feature = "runtime-benchmarks")]
runtime_version!("orbinum-bench");

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> sp_version::NativeVersion {
	sp_version::NativeVersion {
		runtime_version: VERSION,
		can_author_with: Default::default(),
	}
}
