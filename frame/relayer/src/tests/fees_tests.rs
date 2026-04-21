//! Tests for relay fee accounting.
//!
//! Covers:
//! - `accumulate_relay_fee`  — storage update, saturation, event
//! - `pending_relay_fees`    — zero for unknown, correct after accumulation
//! - `consume_relay_fee`     — happy path, partial, insufficient, event
//! - `claim_relay_fees`      — extrinsic path, signed guard, insufficient guard

use crate::traits::RelayerInterface;
use crate::{Error, Event, PendingRelayerFees, mock::*};
use frame_support::{assert_noop, assert_ok};

// ─── accumulate_relay_fee (via RelayerInterface) ─────────────────────────────

#[test]
fn accumulate_relay_fee_increments_balance() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 500);
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 500u128);
	});
}

#[test]
fn accumulate_relay_fee_sums_multiple_calls() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 300);
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 200);
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 500u128);
	});
}

#[test]
fn accumulate_relay_fee_saturates_on_overflow() {
	new_test_ext().execute_with(|| {
		let max = u128::MAX;
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, max);
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 1);
		// saturating_add must not panic, result stays at u128::MAX
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), u128::MAX);
	});
}

#[test]
fn accumulate_relay_fee_emits_event() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 100);
		System::assert_last_event(
			Event::RelayFeeAccumulated {
				relayer: 1u64,
				asset_id: 0,
				amount: 100,
			}
			.into(),
		);
	});
}

#[test]
fn accumulate_independently_per_asset() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 100);
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 1, 200);
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 100u128);
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 1), 200u128);
	});
}

// ─── pending_relay_fees (via RelayerInterface) ───────────────────────────────

#[test]
fn pending_relay_fees_is_zero_by_default() {
	new_test_ext().execute_with(|| {
		assert_eq!(crate::Pallet::<Test>::pending_relay_fees(&99u64, 0), 0u128);
	});
}

#[test]
fn pending_relay_fees_reflects_accumulated_amount() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&2u64, 5, 777);
		assert_eq!(crate::Pallet::<Test>::pending_relay_fees(&2u64, 5), 777u128);
	});
}

// ─── consume_relay_fee (via RelayerInterface) ────────────────────────────────

#[test]
fn consume_relay_fee_decrements_balance() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 1000);
		assert_ok!(crate::Pallet::<Test>::consume_relay_fee(&1u64, 0, 400));
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 600u128);
	});
}

#[test]
fn consume_relay_fee_drains_to_zero() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 500);
		assert_ok!(crate::Pallet::<Test>::consume_relay_fee(&1u64, 0, 500));
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 0u128);
	});
}

#[test]
fn consume_relay_fee_emits_event() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 300);
		assert_ok!(crate::Pallet::<Test>::consume_relay_fee(&1u64, 0, 100));
		System::assert_last_event(
			Event::RelayFeesConsumed {
				relayer: 1u64,
				asset_id: 0,
				amount: 100,
			}
			.into(),
		);
	});
}

#[test]
fn consume_relay_fee_fails_if_insufficient() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 50);
		assert_noop!(
			crate::Pallet::<Test>::consume_relay_fee(&1u64, 0, 51),
			Error::<Test>::InsufficientPendingFees,
		);
		// Storage unchanged after failure
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 50u128);
	});
}

#[test]
fn consume_relay_fee_fails_for_unknown_account() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::consume_relay_fee(&99u64, 0, 1),
			Error::<Test>::InsufficientPendingFees,
		);
	});
}

// ─── claim_relay_fees (extrinsic) ────────────────────────────────────────────

#[test]
fn claim_relay_fees_works() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 800);
		assert_ok!(Relayer::claim_relay_fees(RuntimeOrigin::signed(1), 0, 300));
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 500u128);
	});
}

#[test]
fn claim_relay_fees_emits_event() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 500);
		assert_ok!(Relayer::claim_relay_fees(RuntimeOrigin::signed(1), 0, 200));
		System::assert_last_event(
			Event::RelayFeesConsumed {
				relayer: 1u64,
				asset_id: 0,
				amount: 200,
			}
			.into(),
		);
	});
}

#[test]
fn claim_relay_fees_drains_fully() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 100);
		assert_ok!(Relayer::claim_relay_fees(RuntimeOrigin::signed(1), 0, 100));
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 0u128);
	});
}

#[test]
fn claim_relay_fees_fails_if_insufficient() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 50);
		assert_noop!(
			Relayer::claim_relay_fees(RuntimeOrigin::signed(1), 0, 51),
			Error::<Test>::InsufficientPendingFees,
		);
	});
}

#[test]
fn claim_relay_fees_requires_signed() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Relayer::claim_relay_fees(RuntimeOrigin::none(), 0, 1),
			frame_support::error::BadOrigin,
		);
	});
}

// ─── Cross-account isolation ──────────────────────────────────────────────────

/// Account 2 cannot drain fees that were accrued for account 1.
/// The storage map is keyed by the signed origin — there is no parameter that
/// lets a caller specify a different beneficiary.
#[test]
fn claim_relay_fees_cannot_drain_another_accounts_fees() {
	new_test_ext().execute_with(|| {
		// Only account 1 has fees
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 1000);

		// Account 2 tries to claim — its own pending balance is 0 → InsufficientPendingFees
		assert_noop!(
			Relayer::claim_relay_fees(RuntimeOrigin::signed(2), 0, 1),
			Error::<Test>::InsufficientPendingFees,
		);

		// Account 1's fees are untouched
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 1000u128);
	});
}

/// `consume_relay_fee` (called internally by claim_shielded_fees) also isolates
/// by AccountId — passing account 1's fees to account 2 is impossible.
#[test]
fn consume_relay_fee_cannot_drain_another_accounts_fees() {
	new_test_ext().execute_with(|| {
		crate::Pallet::<Test>::accumulate_relay_fee(&1u64, 0, 500);

		// Attempting to consume on behalf of account 2 fails (its balance is 0)
		assert_noop!(
			crate::Pallet::<Test>::consume_relay_fee(&2u64, 0, 1),
			Error::<Test>::InsufficientPendingFees,
		);

		// Account 1's balance is untouched
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 500u128);
	});
}

#[test]
fn claim_relay_fees_zero_amount_succeeds() {
	new_test_ext().execute_with(|| {
		// Claiming 0 is valid (no-op debit, event still emitted)
		assert_ok!(Relayer::claim_relay_fees(RuntimeOrigin::signed(1), 0, 0));
		assert_eq!(PendingRelayerFees::<Test>::get(1u64, 0), 0u128);
	});
}
