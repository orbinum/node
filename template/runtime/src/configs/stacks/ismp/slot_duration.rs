//! Bounds on a whitelisted state machine's slot duration.
//!
//! Upstream's `fetch_overlay_root_and_timestamp` derives header timestamps with an
//! unchecked `*slot * slot_duration` (`substrate-state-machine` 2606.0.0). Zero makes every
//! timestamp `0`, so challenge-period checks against that chain pass vacuously; a very
//! large value overflows.
//!
//! Advisory: `add_state_machines` is upstream's root-only extrinsic and takes no hook.
//! Only the value we whitelist Hyperbridge with is checked against these bounds.

/// Lower bound: no real chain is faster, and zero is unsafe (see the module docs).
pub const MIN_SLOT_DURATION_MS: u64 = 1_000;

/// Upper bound, one hour: far above any real chain, and low enough that
/// `slot * slot_duration` cannot overflow `u64` for a reachable slot number
/// (`u64::MAX / 3_600_000` ≈ 5.1e12 slots).
pub const MAX_SLOT_DURATION_MS: u64 = 3_600_000;

pub const fn validate_slot_duration(slot_duration: u64) -> bool {
	slot_duration >= MIN_SLOT_DURATION_MS && slot_duration <= MAX_SLOT_DURATION_MS
}

// An out-of-range `HYPERBRIDGE_SLOT_DURATION_MS` fails the build.
const _: () = assert!(validate_slot_duration(
	super::network::HYPERBRIDGE_SLOT_DURATION_MS
));

#[cfg(test)]
mod tests {
	use super::*;

	/// The value Hyperbridge is whitelisted with is within bounds.
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
		assert!(validate_slot_duration(6_000)); // Hyperbridge on Paseo, Orbinum
		assert!(validate_slot_duration(12_000)); // Hyperbridge on Polkadot, Ethereum
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
