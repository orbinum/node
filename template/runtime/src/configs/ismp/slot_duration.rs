//! Bounds for a whitelisted state machine's slot duration.
//!
//! `ismp_grandpa::add_state_machines` writes `slot_duration` to storage unvalidated.
//! Downstream, `substrate_state_machine::fetch_overlay_root_and_timestamp` derives a
//! header timestamp with an unchecked multiply, `*slot * slot_duration`. Zero makes
//! every timestamp `0`, so unbonding and challenge-period checks against that chain
//! become vacuous without erroring; a very large value overflows.
//!
//! Both are fixed on the 2606 line (`saturating_mul`, plus an error when the timestamp
//! still resolves to zero). Taking it needs `frame-support 48` against our `45.1.3`, so
//! on 2512 the exposure is live.
//!
//! **These bounds are advisory.** `add_state_machines` is an upstream extrinsic we
//! cannot intercept without a chain-wide `BaseCallFilter` — disproportionate for a
//! value only root can set. `slot_duration` comes from our own whitelist and derives
//! timestamps for *counterparty* headers, so a bad value corrupts our view of one
//! remote chain rather than opening an attack surface: a governance footgun, not an
//! escalation. Both edges are asserted on the exact stored value, so a change in
//! either direction surfaces rather than passing silently.

/// Lower bound, in milliseconds. Below this a chain is not producing blocks in any
/// meaningful sense, and zero is actively dangerous — see the module docs.
#[allow(dead_code)]
pub const MIN_SLOT_DURATION_MS: u64 = 1_000;

/// Upper bound, in milliseconds — one hour.
///
/// Far above any real chain (Polkadot 6s, Ethereum 12s) and low enough that
/// `slot * slot_duration` cannot overflow `u64` for any reachable slot number:
/// `u64::MAX / 3_600_000` is roughly 5.1e12 slots, about 580 million years at one
/// slot per hour.
#[allow(dead_code)]
pub const MAX_SLOT_DURATION_MS: u64 = 3_600_000;

/// Returns whether `slot_duration` is safe to whitelist.
///
/// See the module docs for what each bound prevents.
#[allow(dead_code)]
pub const fn validate_slot_duration(slot_duration: u64) -> bool {
	slot_duration >= MIN_SLOT_DURATION_MS && slot_duration <= MAX_SLOT_DURATION_MS
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rejects_the_values_that_break_timestamp_derivation() {
		// Zero makes every header timestamp to 0.
		assert!(!validate_slot_duration(0));
		// u64::MAX overflows `slot * slot_duration` on any non-zero slot.
		assert!(!validate_slot_duration(u64::MAX));
		// Just outside each bound.
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
		// Upstream computes `slot * slot_duration` unchecked. At MAX the slot number
		// would have to exceed ~5.1e12 to overflow, which no chain reaches.
		let max_slots = u64::MAX / MAX_SLOT_DURATION_MS;
		assert!(max_slots > 5_000_000_000_000);
		assert!(max_slots.checked_mul(MAX_SLOT_DURATION_MS).is_some());
	}
}
