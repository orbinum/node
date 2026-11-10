//! `integrity_test`: verification is never compiled out of a live runtime.

/// The integrity_test must abort when verification is compiled out WITHOUT the
/// benchmark feature — i.e. a would-be release runtime with no verification. Only
/// compiles in that exact combination (skip on, benchmarks off).
#[cfg(all(
	feature = "skip-proof-verification",
	not(feature = "runtime-benchmarks")
))]
#[test]
#[should_panic(expected = "skip-proof-verification")]
fn integrity_test_panics_when_verification_disabled() {
	use crate::tests::mock::{Test, ZkVerifier};
	use frame_support::traits::Hooks;
	<ZkVerifier as Hooks<frame_system::pallet_prelude::BlockNumberFor<Test>>>::integrity_test();
}
