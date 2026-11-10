//! Signed dispatch: who pays, and where it goes.
//!
//! `DispatchOrigin` is `EnsureSigned` here, as in the runtime. Accounts 1 and 2 hold
//! `100 × worst_case_fee()`, enough to pay for the largest legal message; account 3 holds
//! nothing. The charge is taken by this pallet into `TREASURY` and is NOT escrowed in
//! `FeeMetadata`, so it is never refunded — which is the whole point: a refundable anti-spam
//! charge can be recycled for free every timeout.

use crate::tests::util::*;
use crate::{PALLET_ID_BYTES, inbound::IsmpModuleCallback, payload::Message, tests::mock::*};
use frame_support::{assert_noop, assert_ok};
use ismp::{
	host::StateMachine,
	module::IsmpModule,
	router::{PostRequest, Request},
};
use scale_codec::Encode;

#[test]
fn an_unsigned_origin_cannot_dispatch() {
	new_test_ext().execute_with(|| {
		// Not Root and not admitted by `DispatchOrigin`: the one shape every call refuses.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::none(),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			),
			sp_runtime::DispatchError::BadOrigin
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				RuntimeOrigin::none(),
				COUNTERPARTY,
				get_keys(1),
				10_403_542,
				600,
			),
			sp_runtime::DispatchError::BadOrigin
		);
		assert_noop!(
			crate::Pallet::<Test>::confirm_delivery(
				RuntimeOrigin::none(),
				sp_core::H256::repeat_byte(9),
				42,
				600,
			),
			sp_runtime::DispatchError::BadOrigin
		);
	});
}

#[test]
fn a_signed_dispatch_pays_the_treasury_and_escrows_nothing() {
	new_test_ext().execute_with(|| {
		assert_eq!(balance(1), funded());
		assert_eq!(balance(TREASURY), 0);

		let body = ping();
		let expected = post_cost(&body);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			body,
			600,
		));

		// Moved, not burned: what left the signer is exactly what the treasury now holds.
		assert_eq!(balance(1), funded() - expected);
		assert_eq!(balance(TREASURY), expected);
		// And nothing reached upstream's escrow, so nothing can ever be refunded out of it.
		assert_eq!(balance(fees_account()), 0);
		let dispatched = frame_system::Pallet::<Test>::events().into_iter().any(|r| {
			matches!(
				r.event,
				RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched { .. })
			)
		});
		assert!(dispatched, "the dispatch itself still happens");
	});
}

#[test]
fn root_dispatches_for_free_and_may_never_expire() {
	new_test_ext().execute_with(|| {
		let pallet = crate::outbound::pallet_account::<Test>();

		// `timeout == 0` is refused from a signer below; Root is the one caller it is for.
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::root(),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			0,
		));

		assert_eq!(
			balance(pallet),
			0,
			"Root's stand-in account is a label, never debited"
		);
		assert_eq!(balance(TREASURY), 0, "and Root pays the treasury nothing");
		assert_eq!(balance(fees_account()), 0, "and nothing was escrowed");
	});
}

#[test]
fn a_signer_must_let_the_message_expire() {
	new_test_ext().execute_with(|| {
		let max = <Test as crate::Config>::MaxSignedTimeout::get();

		// "Never expires" would lock the fee for good: the only way it comes back is expiry.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				0,
			),
			crate::Error::<Test>::TimeoutRequired
		);
		// Too short to clear two finality rounds: it could only ever expire.
		let min = <Test as crate::Config>::MinSignedTimeout::get();
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				min - 1,
			),
			crate::Error::<Test>::TimeoutTooShort
		);
		// So would a timeout past any horizon a refund is worth waiting for.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				max + 1,
			),
			crate::Error::<Test>::TimeoutTooLong
		);
		// Both bounds themselves are allowed.
		for timeout in [min, max] {
			assert_ok!(crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				timeout,
			));
		}
	});
}

#[test]
fn an_unfunded_signer_is_refused_before_anything_is_written() {
	new_test_ext().execute_with(|| {
		assert_eq!(balance(3), 0);
		let nonce_before = pallet_ismp::Nonce::<Test>::get();

		// A named error, and `assert_noop!` proves no nonce, commitment or event was spent
		// finding out — the dispatcher's own failure would come after all of those.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(3),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			),
			crate::Error::<Test>::InsufficientBalance
		);
		assert_eq!(pallet_ismp::Nonce::<Test>::get(), nonce_before);
	});
}

#[test]
fn an_expired_signed_dispatch_reclaims_its_commitment_but_not_the_charge() {
	new_test_ext().execute_with(|| {
		use ismp::host::IsmpHost;

		// A real clock, so the deadline the dispatcher stamps is one this test can name.
		let now_secs: u64 = 1_700_000_000;
		Timestamp::set_timestamp(now_secs * 1_000);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			ping(),
			600,
		));
		let charge = post_cost(&ping());
		let after_dispatch = balance(1);
		assert_eq!(after_dispatch, funded() - charge);

		// The request exactly as the dispatcher built it, so its commitment is the one on
		// file. `from` is the pallet's module id — the payer lives in the metadata, not here.
		let request = Request::Post(PostRequest {
			source: StateMachine::Substrate(*b"orbi"),
			dest: COUNTERPARTY,
			nonce: pallet_ismp::Nonce::<Test>::get().saturating_sub(1),
			from: PALLET_ID_BYTES.to_vec(),
			to: b"demo/mod".to_vec(),
			timeout_timestamp: now_secs + 600,
			body: ping(),
		});

		// The two steps upstream's timeout handler takes (`handlers/timeout.rs:332,347`),
		// minus the non-membership proof it verifies first. The proof is upstream's to
		// test; what is ours is that the metadata still names the right payer and the
		// refund reaches them.
		let host = pallet_ismp::Pallet::<Test>::default();
		let meta = host
			.delete_request_commitment(&request)
			.expect("the commitment was on file");
		assert_ok!(IsmpModuleCallback::<Test>::default().on_timeout(request.clone()));
		host.on_request_timeout(&request, meta)
			.expect("refund is a plain transfer from ISMPFEES");

		// Expiry reclaims the commitment — and nothing else. The charge was taken by this
		// pallet, not escrowed upstream, so there is nothing for `on_request_timeout` to
		// hand back: `fee: 0` on the wire means its refund branch never fires. That is
		// deliberate. A charge that comes back on expiry is a charge a spammer recycles.
		assert_eq!(balance(1), after_dispatch, "the charge stays paid");
		assert_eq!(balance(TREASURY), charge, "and stays with the treasury");
		assert_eq!(balance(fees_account()), 0, "nothing was ever escrowed");
	});
}

#[test]
fn a_get_and_a_confirmation_cost_the_same_fee() {
	new_test_ext().execute_with(|| {
		// A GET is priced on its keys, the equivalent of a POST's body.
		let keys = get_keys(1);
		let get_cost =
			MESSAGE_FEE + MESSAGE_BYTE_FEE * keys.iter().map(|k| k.len() as u128).sum::<u128>();
		assert_ok!(crate::Pallet::<Test>::dispatch_get(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			keys,
			10_403_542,
			600,
		));
		assert_eq!(balance(1), funded() - get_cost);

		// `confirm_delivery` is a one-key GET — but it also carries a 32-byte context, the
		// commitment it is confirming, and that context travels on the wire and comes back
		// inside `GetResponse.get`. So it costs the key AND the context.
		//
		// This assertion used to count the key alone, which made the undercharge look like
		// correct behaviour: the signer paid for 47 bytes and sent 79.
		let confirm_keys = crate::receipts::confirmation_keys(sp_core::H256::repeat_byte(9));
		let confirm_context = 32u128;
		let confirm_cost = MESSAGE_FEE
			+ MESSAGE_BYTE_FEE
				* (confirm_keys.iter().map(|k| k.len() as u128).sum::<u128>() + confirm_context);
		assert_ok!(crate::Pallet::<Test>::confirm_delivery(
			RuntimeOrigin::signed(1),
			sp_core::H256::repeat_byte(9),
			42,
			600,
		));
		assert_eq!(balance(1), funded() - get_cost - confirm_cost);
		assert_eq!(balance(TREASURY), get_cost + confirm_cost);
		assert_eq!(balance(fees_account()), 0, "still nothing escrowed");
	});
}

#[test]
fn two_signers_sending_the_same_body_do_not_collide() {
	new_test_ext().execute_with(|| {
		// Identical args from two accounts: `impls.rs:93` rejects a duplicate commitment,
		// and the nonce is what keeps these two apart. Both must land.
		for who in [1u64, 2] {
			assert_ok!(crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(who),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			));
		}
		assert_eq!(pallet_ismp::Nonce::<Test>::get(), 2);
		let each = post_cost(&ping());
		assert_eq!(balance(TREASURY), 2 * each);
	});
}

#[test]
fn a_bigger_message_costs_more() {
	new_test_ext().execute_with(|| {
		// A flat fee prices one byte the same as a full body, while the cost this chain and
		// its relayer bear scales with size. Hyperbridge prices its own outbound traffic by
		// the byte for the same reason (`pallet-bandwidth`).
		let small = Message::Data {
			nonce: 1,
			data: alloc::vec![],
		}
		.encode();
		let large = Message::Data {
			nonce: 1,
			data: alloc::vec![0u8; 500],
		}
		.encode();

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			small.clone(),
			600,
		));
		let cheap = balance(TREASURY);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(2),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			large.clone(),
			600,
		));
		let dear = balance(TREASURY) - cheap;

		assert_eq!(cheap, post_cost(&small));
		assert_eq!(dear, post_cost(&large));
		assert!(dear > cheap, "{dear} should exceed {cheap}");
	});
}

#[test]
fn the_largest_legal_message_can_actually_be_paid_for() {
	new_test_ext().execute_with(|| {
		// Every size-boundary test in this file used to run as Root — the path that never
		// pays — because the mock funded accounts with `10 × MESSAGE_FEE` while a full body
		// costs `MESSAGE_FEE + MESSAGE_BYTE_FEE × MaxBodyLen`. The largest signed message
		// was literally unaffordable, so nothing checked that the bound and the charge agree.
		use frame_support::traits::Get;
		let body_max = <<Test as crate::Config>::MaxBodyLen as Get<u32>>::get();
		let before = balance(TREASURY);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			alloc::vec![0u8; body_max as usize],
			600,
		));

		assert_eq!(
			balance(TREASURY) - before,
			post_cost(&alloc::vec![0u8; body_max as usize]),
			"a full-length body is charged flat + per byte over the whole body"
		);

		// One byte more is refused on size, not on funds — the signer can still afford it.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				alloc::vec![0u8; body_max as usize + 1],
				600,
			),
			crate::Error::<Test>::BodyTooLarge
		);
	});
}

#[test]
fn a_signed_get_is_bounded_by_the_same_guards_as_root() {
	new_test_ext().execute_with(|| {
		// Every guard in `outbound::get` was only ever tested from Root. Moving them into
		// the paying branch of `fee_for` — or wrapping them in `if payer.is_none()` — would
		// leave signed users unbounded while the suite stayed green, which inverts what the
		// bounds are for: they cap work imposed on a REMOTE chain and a relayer, and the
		// signed caller is the one who is not us.
		use frame_support::traits::Get;
		let too_many = <<Test as crate::Config>::MaxGetKeys as Get<u32>>::get() as usize + 1;
		let signed = || RuntimeOrigin::signed(1);

		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(signed(), COUNTERPARTY, alloc::vec![], 42, 600),
			crate::Error::<Test>::NoKeysRequested
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				signed(),
				COUNTERPARTY,
				get_keys(too_many),
				42,
				600
			),
			crate::Error::<Test>::TooManyKeys
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(signed(), COUNTERPARTY, get_keys(1), 0, 600),
			crate::Error::<Test>::InvalidGetHeight
		);
		assert_noop!(
			crate::Pallet::<Test>::dispatch_get(
				signed(),
				StateMachine::Substrate(*b"orbi"),
				get_keys(1),
				42,
				600
			),
			crate::Error::<Test>::DestinationIsSelf
		);

		// And none of those cost the signer anything: each is refused before the charge.
		assert_eq!(balance(TREASURY), 0, "a refused GET is never charged for");
	});
}

#[test]
fn a_signer_may_spend_their_very_last_planck() {
	new_test_ext().execute_with(|| {
		// `ExistentialDeposit` is zero on this chain (`configs/chain/system.rs`), which is what
		// `fee_for` cites to justify `Preservation::Expendable`: there is no minimum to keep
		// back, so an account may legitimately pay its whole balance and be reaped.
		//
		// This is the test that holds that justification to account. The mock used to
		// inherit the balances prelude's ED of 1, under which no test could drain an account
		// at all — so `Expendable` could have been `Preserve` with the suite still green,
		// and a signer whose balance was exactly the fee would have been refused.
		let body = ping();
		let exact = post_cost(&body);

		// Account 3 starts empty. Give it exactly one message's worth, not a planck more.
		assert_ok!(pallet_balances::Pallet::<Test>::force_set_balance(
			RuntimeOrigin::root(),
			3,
			exact
		));
		assert_eq!(balance(3), exact);

		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(3),
			COUNTERPARTY,
			b"demo/mod".to_vec(),
			body,
			600,
		));

		assert_eq!(balance(3), 0, "the whole balance was spendable");
		assert_eq!(balance(TREASURY), exact);

		// And now genuinely broke: the next one cannot be paid for.
		assert_noop!(
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(3),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				ping(),
				600,
			),
			crate::Error::<Test>::InsufficientBalance
		);
	});
}

#[test]
fn context_bytes_are_charged_for_like_keys() {
	new_test_ext().execute_with(|| {
		// `context` travels on the wire and comes back inside `GetResponse.get`, which is why
		// `outbound::get` bounds it at all. For a while it was bounded and NOT charged, so the
		// larger half of a GET's payload was free: at runtime values a maximal GET carried
		// 2,048 bytes of keys and up to 8,192 of context, and only the keys were priced.
		//
		// Two GETs with identical keys and different context lengths must therefore cost
		// different amounts. Dispatched through `outbound::get` directly because no extrinsic
		// exposes `context` today — which is exactly what keeps this from being a live hole,
		// and exactly why it needs pinning before one does.
		let keys = get_keys(1);
		let key_bytes: u128 = keys.iter().map(|k| k.len() as u128).sum();

		let before = balance(TREASURY);
		assert_ok!(crate::outbound::get::<Test>(
			Some(1),
			COUNTERPARTY,
			keys.clone(),
			42,
			600,
			alloc::vec![],
		));
		let bare = balance(TREASURY) - before;
		assert_eq!(bare, MESSAGE_FEE + MESSAGE_BYTE_FEE * key_bytes);

		let before = balance(TREASURY);
		assert_ok!(crate::outbound::get::<Test>(
			Some(1),
			COUNTERPARTY,
			keys,
			42,
			600,
			alloc::vec![7u8; 100],
		));
		let with_context = balance(TREASURY) - before;

		assert_eq!(
			with_context - bare,
			MESSAGE_BYTE_FEE * 100,
			"a hundred context bytes must cost a hundred bytes' worth"
		);
	});
}

#[test]
fn the_module_id_is_charged_for_like_the_body() {
	new_test_ext().execute_with(|| {
		// Hyperbridge bills a POST by `encode_post_request(&request).len()`
		// (`gargantua/src/ismp.rs:383`), and that encoding carries `to` along with everything
		// else (`modules/ismp/core/src/abi.rs:64-76`). Charging the body alone left the
		// module id free while a GET's context was charged — an asymmetry against upstream's
		// own basis for billing.
		//
		// `ModuleId::from_bytes` admits exactly three lengths, so two of them priced
		// differently is the whole proof: same body, longer id, higher charge.
		let body = ping();

		let before = balance(TREASURY);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			b"demo/mod".to_vec(), // 8 bytes: a pallet id
			body.clone(),
			600,
		));
		let short_id = balance(TREASURY) - before;

		let before = balance(TREASURY);
		assert_ok!(crate::Pallet::<Test>::dispatch_post(
			RuntimeOrigin::signed(1),
			COUNTERPARTY,
			alloc::vec![9u8; 32], // 32 bytes: an account id
			body.clone(),
			600,
		));
		let long_id = balance(TREASURY) - before;

		assert_eq!(
			long_id - short_id,
			MESSAGE_BYTE_FEE * 24,
			"a 32-byte id must cost 24 bytes more than an 8-byte one"
		);
		assert_eq!(short_id, post_cost(&body));
	});
}

#[test]
fn a_dispatch_that_fails_refunds_the_charge() {
	new_test_ext().execute_with(|| {
		// The charge is taken before the dispatch, so the one place money and failure meet
		// is a dispatcher error after a successful transfer. Extrinsics are transactional,
		// which means the transfer unwinds — but nothing pinned that until now.
		//
		// Forced by making the dispatcher see a duplicate commitment (`impls.rs:92-94`).
		// Rather than recompute the hash here — which would re-derive the dispatcher's own
		// encoding and could drift from it — send one message, take the commitment the
		// chain actually recorded, and put it back. The nonce is rewound so the next
		// dispatch rebuilds the identical request.
		let body = ping();
		let send = || {
			crate::Pallet::<Test>::dispatch_post(
				RuntimeOrigin::signed(1),
				COUNTERPARTY,
				b"demo/mod".to_vec(),
				body.clone(),
				600,
			)
		};
		assert_ok!(send());
		let commitment = frame_system::Pallet::<Test>::events()
			.into_iter()
			.find_map(|r| match r.event {
				RuntimeEvent::IsmpMessaging(crate::Event::RequestDispatched {
					commitment, ..
				}) => Some(commitment),
				_ => None,
			})
			.expect("the first dispatch emitted one");
		let meta = pallet_ismp::child_trie::RequestCommitments::<Test>::get(commitment)
			.expect("and recorded it");
		let nonce_before = pallet_ismp::Nonce::<Test>::get();
		pallet_ismp::Nonce::<Test>::put(nonce_before - 1);
		pallet_ismp::child_trie::RequestCommitments::<Test>::insert(commitment, meta);

		let before = balance(1);
		let treasury_before = balance(TREASURY);
		assert_noop!(send(), crate::Error::<Test>::DispatchFailed);
		// `assert_noop!` already proves no storage changed; naming the balances says which
		// storage the reader should care about — the charge is taken BEFORE the dispatch,
		// so this is the one place money and failure meet.
		assert_eq!(balance(1), before, "the charge unwound with the dispatch");
		assert_eq!(balance(TREASURY), treasury_before);
	});
}
