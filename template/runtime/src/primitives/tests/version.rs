// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The spec name keeps local-only builds (`fast-runtime`, `runtime-benchmarks`) off
//! real chains: `set_code` refuses a runtime whose spec name differs from the one it
//! replaces, and the release workflow accepts only `orbinum`.

use crate::VERSION;

#[cfg(not(any(feature = "fast-runtime", feature = "runtime-benchmarks")))]
#[test]
fn release_runtime_is_named_orbinum() {
	assert_eq!(VERSION.spec_name, "orbinum");
}

#[cfg(all(feature = "fast-runtime", not(feature = "runtime-benchmarks")))]
#[test]
fn fast_runtime_has_its_own_spec_name() {
	assert_eq!(VERSION.spec_name, "orbinum-fast");
}

#[cfg(feature = "runtime-benchmarks")]
#[test]
fn benchmark_runtime_has_its_own_spec_name() {
	assert_eq!(VERSION.spec_name, "orbinum-bench");
}
