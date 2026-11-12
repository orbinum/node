// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The admin's levers: accepted sources, the outbound pause and the message fee, each
//! root-only and announced by an event.

use crate::tests::util::*;
use crate::{AcceptedSources, tests::mock::*};
use frame_support::{assert_noop, assert_ok};

#[test]
fn accept_source_is_root_only_and_observable() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::accept_source(RuntimeOrigin::signed(1), COPROCESSOR),
			sp_runtime::DispatchError::BadOrigin
		);
		assert_noop!(
			crate::Pallet::<Test>::remove_source(RuntimeOrigin::signed(1), COPROCESSOR),
			sp_runtime::DispatchError::BadOrigin
		);

		assert_ok!(crate::Pallet::<Test>::accept_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		// These two events are the only on-chain record of why inbound traffic from a
		// chain starts or stops — an unaccepted source emits nothing at all.
		let announced = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				RuntimeEvent::IsmpMessaging(crate::Event::SourceAccepted { source })
					if source == COPROCESSOR
			)
		});
		assert!(announced);
	});
}

#[test]
fn accepting_the_same_source_twice_is_harmless() {
	new_test_ext().execute_with(|| {
		// Re-running the setup script must not break a live chain.
		assert_ok!(crate::Pallet::<Test>::accept_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		assert_ok!(crate::Pallet::<Test>::accept_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		assert!(AcceptedSources::<Test>::contains_key(COPROCESSOR));

		assert_ok!(crate::Pallet::<Test>::remove_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		// Removing one that is not there is equally harmless.
		assert_ok!(crate::Pallet::<Test>::remove_source(
			RuntimeOrigin::root(),
			COPROCESSOR
		));
		assert!(!AcceptedSources::<Test>::contains_key(COPROCESSOR));
	});
}

#[test]
fn root_can_pause_signed_dispatch_without_stopping_its_own() {
	new_test_ext().execute_with(|| {
		assert_ok!(crate::Pallet::<Test>::set_outbound_paused(
			RuntimeOrigin::root(),
			true
		));
		assert!(crate::OutboundPaused::<Test>::get());

		// Every signed path is closed…
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			),
			crate::Error::<Test>::OutboundPaused
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				get_keys(1),
				10_403_542,
				600,
			),
			crate::Error::<Test>::OutboundPaused
		);
		assert_noop!(
			crate::Pallet::<Test>::confirm_delivery(
				RuntimeOrigin::signed(1),
				sp_core::H256::repeat_byte(9),
				42,
				600,
			),
			crate::Error::<Test>::OutboundPaused
		);

		// …while this chain's own automation is untouched, which is why the check lives in
		// the signed branch rather than at the top of the extrinsic.
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			0,
		));
		assert_ok!(crate::Pallet::<Test>::confirm_delivery(
			RuntimeOrigin::root(),
			sp_core::H256::repeat_byte(9),
			42,
			600
		));

		// And it lifts.
		assert_ok!(crate::Pallet::<Test>::set_outbound_paused(
			RuntimeOrigin::root(),
			false
		));
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			600,
		));
	});
}

#[test]
fn pausing_is_root_only() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::set_outbound_paused(RuntimeOrigin::signed(1), true),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn root_can_reprice_a_message_without_a_runtime_upgrade() {
	new_test_ext().execute_with(|| {
		// The whole reason the fee is storage and not a constant: the right price tracks
		// what the token is worth, and a constant in the WASM cannot follow it. Correcting
		// one would otherwise mean a build and a `setCode`.
		assert_eq!(crate::MessageFee::<Test>::get(), MESSAGE_FEE);
		assert_eq!(crate::MessageByteFee::<Test>::get(), MESSAGE_BYTE_FEE);

		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			5 * MESSAGE_FEE,
			2 * MESSAGE_BYTE_FEE,
		));

		let body = ping();
		let expected = 5 * MESSAGE_FEE
			+ 2 * MESSAGE_BYTE_FEE * (body.len() as u128 + b"demo/mod".len() as u128);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			body,
			600,
		));
		assert_eq!(
			balance(TREASURY),
			expected,
			"the new price took effect at once"
		);
	});
}

#[test]
fn a_repricing_is_capped_on_what_the_largest_message_would_cost() {
	new_test_ext().execute_with(|| {
		// The ceiling is what keeps the dial from becoming a foot-gun: a mistyped value
		// would otherwise price dispatch out of reach until the next runtime upgrade.
		use frame_support::traits::Get;
		let max = <Test as crate::Config>::MaxMessageFee::get();
		// The ceiling's size term is the largest of EVERY dispatch shape, not a body's: a
		// GET is priced on the sum of its key lengths, which can exceed `MaxBodyLen`.
		let worst_size = crate::outbound::max_chargeable_size::<Test>() as u128;

		assert_noop!(
			crate::Pallet::<Test>::set_message_fee(RuntimeOrigin::root(), max + 1, 0),
			crate::Error::<Test>::MessageFeeTooHigh
		);

		// The bound is on the WORST CASE, not on each term: a per-byte value at the flat
		// ceiling would price a full body at `MaxBodyLen` times the cap, which is the very
		// outcome the ceiling exists to prevent. Transposing the two arguments — they have
		// the same type — is the easy way to get there, so it must be refused.
		assert_noop!(
			crate::Pallet::<Test>::set_message_fee(RuntimeOrigin::root(), 0, max),
			crate::Error::<Test>::MessageFeeTooHigh
		);
		// One planck per byte over the budget is still over it.
		assert_noop!(
			crate::Pallet::<Test>::set_message_fee(RuntimeOrigin::root(), 0, max / worst_size + 1),
			crate::Error::<Test>::MessageFeeTooHigh
		);

		// A per-byte value whose worst case fits is allowed…
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			0,
			max / worst_size
		));
		// …as is the flat ceiling on its own.
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			max,
			0
		));

		// And now the part that matters: what the chain ACTUALLY charges for the largest
		// message of each shape, measured rather than recomputed.
		//
		// The previous version of this test asserted `fee + byte_fee × MaxBodyLen <= max`
		// — the same expression `set_message_fee` itself evaluates, with the same term. It
		// was a tautology, and it held while the largest GET cost sixteen times the ceiling,
		// because a GET is charged on its keys and `MaxBodyLen` never described them.
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			0,
			max / worst_size
		));

		let keys = <<Test as crate::Config>::MaxGetKeys as Get<u32>>::get();
		let key_len = <<Test as crate::Config>::MaxGetKeyLen as Get<u32>>::get();
		let before = balance(TREASURY);
		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			alloc::vec![alloc::vec![0u8; key_len as usize]; keys as usize],
			10_403_542,
			600,
		));
		let charged = balance(TREASURY) - before;
		assert!(
			charged <= max,
			"the largest GET cost {charged}, above the ceiling {max}"
		);

		let before = balance(TREASURY);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			alloc::vec![0u8; <<Test as crate::Config>::MaxBodyLen as Get<u32>>::get() as usize],
			600,
		));
		let charged = balance(TREASURY) - before;
		assert!(
			charged <= max,
			"the largest POST cost {charged}, above the ceiling {max}"
		);
	});
}

#[test]
fn repricing_and_pausing_announce_themselves() {
	new_test_ext().execute_with(|| {
		// Both are root levers whose effect is invisible in a block unless they emit: an
		// indexer watching for a price change has nothing else to watch.
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			7,
			11
		));
		assert_ok!(crate::Pallet::<Test>::set_outbound_paused(
			RuntimeOrigin::root(),
			true
		));

		let events = frame_system::Pallet::<Test>::events();
		assert!(events.iter().any(|r| matches!(
			r.event,
			RuntimeEvent::IsmpMessaging(crate::Event::MessageFeeUpdated {
				fee: 7,
				byte_fee: 11
			})
		)));
		assert!(events.iter().any(|r| matches!(
			r.event,
			RuntimeEvent::IsmpMessaging(crate::Event::OutboundPauseSet { paused: true })
		)));
	});
}

#[test]
fn repricing_is_root_only() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			crate::Pallet::<Test>::set_message_fee(RuntimeOrigin::signed(1), 0, 0),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn a_zero_fee_is_allowed_and_charges_nothing() {
	new_test_ext().execute_with(|| {
		// Root may price dispatch at zero — the anti-spam charge is a policy dial, not a
		// protocol requirement, and `dispatch_request` skips the transfer when it is zero.
		assert_ok!(crate::Pallet::<Test>::set_message_fee(
			RuntimeOrigin::root(),
			0,
			0
		));
		let before = balance(1);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			600,
		));
		assert_eq!(balance(1), before);
		assert_eq!(balance(TREASURY), 0);
	});
}
