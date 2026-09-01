//! Bounds on a whitelisted state machine's slot duration.
//!
//! Upstream's `fetch_overlay_root_and_timestamp` derives header timestamps with an
//! unchecked `*slot * slot_duration`, still raw in `substrate-state-machine 2606.0.0`
//! (the fix is on Hyperbridge's `main`, unpublished). Zero makes every timestamp `0`, so
//! challenge-period checks against that chain pass vacuously without erroring; a very
//! large value overflows.
//!
//! Advisory, not enforced: `add_state_machines` is upstream's own extrinsic and takes no
//! hook, and it is root-only. What the tests below do enforce is that the value *we*
//! whitelist Hyperbridge with is inside these bounds.

/// Lower bound. Below this a chain is not producing blocks in any meaningful sense, and
/// zero is actively dangerous — see the module docs.
pub const MIN_SLOT_DURATION_MS: u64 = 1_000;

/// Upper bound, one hour: far above any real chain, and low enough that
/// `slot * slot_duration` cannot overflow `u64` for a reachable slot number
/// (`u64::MAX / 3_600_000` ≈ 5.1e12 slots).
pub const MAX_SLOT_DURATION_MS: u64 = 3_600_000;

pub const fn validate_slot_duration(slot_duration: u64) -> bool {
	slot_duration >= MIN_SLOT_DURATION_MS && slot_duration <= MAX_SLOT_DURATION_MS
}

/// Compile-time check on the value this runtime whitelists the coprocessor with.
///
/// The bounds cannot gate upstream's extrinsic, but they can gate *our* constant: a
/// build with an out-of-range `HYPERBRIDGE_SLOT_DURATION_MS` fails here rather than
/// producing a chain whose challenge-period checks are vacuous.
const _: () = assert!(validate_slot_duration(
	super::network::HYPERBRIDGE_SLOT_DURATION_MS
));

#[cfg(test)]
mod tests {
	use super::*;

	/// The value the setup path actually whitelists Hyperbridge with must be safe.
	///
	/// This is the only caller-facing assertion here: the bounds cannot gate upstream's
	/// extrinsic, but a typo in our own constant is a mistake we can catch.
	#[test]
	fn the_hyperbridge_slot_duration_we_whitelist_is_within_bounds() {
		assert!(validate_slot_duration(
			super::super::network::HYPERBRIDGE_SLOT_DURATION_MS
		));
	}

	#[test]
	fn rejects_the_values_that_break_timestamp_derivation() {
		assert!(!validate_slot_duration(0));
		assert!(!validate_slot_duration(u64::MAX));
		assert!(!validate_slot_duration(MIN_SLOT_DURATION_MS - 1));
		assert!(!validate_slot_duration(MAX_SLOT_DURATION_MS + 1));
	}

	#[test]
	fn accepts_real_chain_slot_durations() {
		assert!(validate_slot_duration(6_000)); // Polkadot, Orbinum
		assert!(validate_slot_duration(12_000)); // Ethereum
		assert!(validate_slot_duration(MIN_SLOT_DURATION_MS));
		assert!(validate_slot_duration(MAX_SLOT_DURATION_MS));
	}

	#[test]
	fn max_bound_cannot_overflow_the_timestamp_multiply() {
		let max_slots = u64::MAX / MAX_SLOT_DURATION_MS;
		assert!(max_slots > 5_000_000_000_000);
		assert!(max_slots.checked_mul(MAX_SLOT_DURATION_MS).is_some());
	}
}
