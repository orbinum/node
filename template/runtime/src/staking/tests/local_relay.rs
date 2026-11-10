//! The clients' message calls (`staking::local_relay`): only the adapters reach
//! them, with origin `None`; accounts, bare extrinsics in the pool or in a block,
//! and `None` outside the adapters cannot.

use crate::staking::{
	local_relay::{DirectToAssetHub, DirectToRelay, LocalRelayFilter},
	recovery::plan_is_stalled,
};
use crate::test_utils::{
	account,
	blocks::active_era,
	network::{charlie, with_validators},
	with_ext,
};
use crate::{
	AccountId, Executive, Header, Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin, Session,
	System, UncheckedExtrinsic,
};
use frame_support::{
	assert_noop, assert_ok,
	dispatch::GetDispatchInfo,
	traits::{Contains, UnfilteredDispatchable},
};
use pallet_staking_async as staking;
use pallet_staking_async_ah_client::{self as ah_client, SendToAssetHub};
use pallet_staking_async_rc_client::{self as rc_client, SendToRelayChain};
use scale_codec::Encode;
use sp_keyring::Sr25519Keyring::{Alice, Bob};
use sp_runtime::{
	traits::{Dispatchable, Header as _},
	transaction_validity::{TransactionSource, TransactionValidityError, UnknownTransaction},
	DispatchError, Perbill,
};
use sp_staking::SessionIndex;

/// The account the forged messages favour.
fn attacker() -> AccountId {
	AccountId::from([0x0c; 32])
}

/// Every message call of the two clients, forged against `who` in `session`:
/// the session's points and an activation, a full slash, a set without `who`,
/// and `who`'s keys replaced, then purged.
fn messages(who: &AccountId, session: SessionIndex) -> [RuntimeCall; 5] {
	let raw: [u8; 32] = attacker().into();
	let keys = crate::opaque::SessionKeys {
		aura: sp_core::sr25519::Public::from_raw(raw).into(),
		grandpa: sp_core::ed25519::Public::from_raw(raw).into(),
	};
	[
		RuntimeCall::RcClient(rc_client::Call::relay_session_report {
			report: rc_client::SessionReport::new_terminal(
				session,
				vec![(attacker(), 1_000_000)],
				Some((1, session)),
			),
		}),
		RuntimeCall::RcClient(rc_client::Call::relay_new_offence_paged {
			offences: vec![(
				session,
				rc_client::Offence {
					offender: who.clone(),
					reporters: vec![attacker()],
					slash_fraction: Perbill::one(),
				},
			)],
		}),
		RuntimeCall::AhClient(ah_client::Call::validator_set {
			report: rc_client::ValidatorSetReport::new_terminal(vec![attacker()], session, None),
		}),
		RuntimeCall::AhClient(ah_client::Call::set_keys_from_ah {
			stash: who.clone(),
			keys: keys.encode(),
		}),
		RuntimeCall::AhClient(ah_client::Call::purge_keys_from_ah { stash: who.clone() }),
	]
}

/// What the messages change, encoded: the last session report, the eras and
/// their points, the queued set, `who`'s keys and the offence queue.
fn touched(who: &AccountId) -> Vec<u8> {
	let era = active_era();
	(
		rc_client::LastSessionReportEndingIndex::<Runtime>::get(),
		staking::ActiveEra::<Runtime>::get(),
		staking::CurrentEra::<Runtime>::get(),
		staking::ErasRewardPoints::<Runtime>::get(era),
		ah_client::ValidatorSet::<Runtime>::get(),
		pallet_session::NextKeys::<Runtime>::get(who),
		staking::OffenceQueueEras::<Runtime>::get(),
		staking::OffenceQueue::<Runtime>::iter().count() as u32,
	)
		.encode()
}

fn filtered() -> DispatchError {
	frame_system::Error::<Runtime>::CallFiltered.into()
}

#[test]
fn accounts_cannot_send_client_messages() {
	with_ext(|| {
		let signed = || RuntimeOrigin::signed(AccountId::from([0x0b; 32]));
		for call in messages(&AccountId::from([0x0a; 32]), 7) {
			assert_noop!(
				call.clone().dispatch(signed()).map_err(|e| e.error),
				filtered()
			);
			// Past the filter, the origin check refuses them too.
			assert_noop!(
				call.dispatch_bypass_filter(signed()).map_err(|e| e.error),
				DispatchError::BadOrigin
			);
		}
	});
}

#[test]
fn the_pool_refuses_bare_client_messages() {
	with_ext(|| {
		for call in messages(&AccountId::from([0x0a; 32]), 7) {
			assert!(call.get_dispatch_info().total_weight().ref_time() > 0);
			let xt = UncheckedExtrinsic::new_bare(call);
			assert_eq!(
				Executive::validate_transaction(
					TransactionSource::External,
					xt,
					Default::default()
				),
				Err(TransactionValidityError::Unknown(
					UnknownTransaction::NoUnsignedValidator
				))
			);
		}
	});
}

/// A block author can put a bare extrinsic in its block without the pool: it is
/// dispatched with origin `None`, and the call filter refuses it.
#[test]
fn bare_client_messages_are_refused_in_a_block() {
	with_validators(|| {
		let alice = account(Alice);
		let n = System::block_number() + 1;
		let parent = System::block_hash(n - 1);
		Executive::initialize_block(&Header::new(
			n,
			Default::default(),
			Default::default(),
			parent,
			Default::default(),
		));
		for call in messages(&alice, Session::current_index()) {
			let before = touched(&alice);
			let xt = UncheckedExtrinsic::new_bare(call.clone());
			assert_eq!(
				Executive::apply_extrinsic(xt),
				Ok(Err(filtered())),
				"{call:?}"
			);
			assert_eq!(touched(&alice), before, "{call:?}");
		}
	});
}

/// Origin `None` passes only while an adapter delivers a message: a dispatch
/// past the call filter is refused. Root still passes (upstream's
/// `ensure_origin_or_root`).
#[test]
fn client_messages_need_the_local_relay() {
	with_validators(|| {
		for call in messages(&account(Alice), Session::current_index()) {
			assert_noop!(
				call.clone()
					.dispatch_bypass_filter(RuntimeOrigin::none())
					.map_err(|e| e.error),
				DispatchError::BadOrigin
			);
		}
		let purge = RuntimeCall::AhClient(ah_client::Call::purge_keys_from_ah {
			stash: account(Alice),
		});
		assert_ok!(purge.dispatch(RuntimeOrigin::root()));
		assert!(pallet_session::NextKeys::<Runtime>::get(account(Alice)).is_none());
	});
}

#[test]
fn the_adapters_deliver() {
	with_validators(|| {
		let alice = account(Alice);
		let last = rc_client::LastSessionReportEndingIndex::<Runtime>::get().unwrap_or_default();
		assert_ok!(DirectToAssetHub::relay_session_report(
			rc_client::SessionReport::new_terminal(last + 1, vec![(alice.clone(), 20)], None)
		));
		assert_eq!(
			rc_client::LastSessionReportEndingIndex::<Runtime>::get(),
			Some(last + 1)
		);

		System::reset_events();
		assert_ok!(DirectToAssetHub::relay_new_offence_paged(vec![(
			Session::current_index(),
			rc_client::Offence {
				offender: charlie(),
				reporters: vec![],
				slash_fraction: Perbill::from_percent(10),
			},
		)]));
		assert!(System::events().iter().any(|r| matches!(
			r.event,
			RuntimeEvent::RcClient(rc_client::Event::OffenceReceived { .. })
		)));

		let mut set = vec![alice, account(Bob), charlie()];
		assert_ok!(DirectToRelay::validator_set(
			rc_client::ValidatorSetReport::new_terminal(set.clone(), 99, None)
		));
		set.sort();
		assert_eq!(ah_client::ValidatorSet::<Runtime>::get(), Some((99, set)));
	});
}

/// The historical roots a delivered set prunes are charged one write each,
/// however many sessions the era that left the bonding window lasted.
#[test]
fn the_pruned_historical_roots_are_charged() {
	use pallet_session::historical::{HistoricalSessions, StoredRange};
	with_validators(|| {
		for session in 0..500 {
			HistoricalSessions::<Runtime>::insert(session, (sp_core::H256::zero(), 3));
		}
		StoredRange::<Runtime>::put((0, 500));
		let mandatory =
			|| *System::block_weight().get(frame_support::dispatch::DispatchClass::Mandatory);
		let before = mandatory();
		let set = vec![account(Alice), account(Bob), charlie()];
		assert_ok!(DirectToRelay::validator_set(
			rc_client::ValidatorSetReport::new_terminal(set, 99, Some(499))
		));
		assert_eq!(StoredRange::<Runtime>::get(), Some((499, 500)));
		let db = <Runtime as frame_system::Config>::DbWeight::get();
		assert!(mandatory().all_gte(before + db.writes(499)));
	});
}

/// After an era held long, a validator set prunes at most `MAX_ROOTS_PRUNED`
/// roots; the next one takes the rest.
#[test]
fn a_long_backlog_of_roots_is_pruned_over_several_validator_sets() {
	use crate::staking::eras::local_relay::MAX_ROOTS_PRUNED;
	use pallet_session::historical::{HistoricalSessions, StoredRange};
	with_validators(|| {
		let backlog = 2 * MAX_ROOTS_PRUNED + 500;
		for session in 0..backlog {
			HistoricalSessions::<Runtime>::insert(session, (sp_core::H256::zero(), 3));
		}
		StoredRange::<Runtime>::put((0, backlog));
		let set = vec![account(Alice), account(Bob), charlie()];
		for (id, start) in [
			(99, MAX_ROOTS_PRUNED),
			(100, 2 * MAX_ROOTS_PRUNED),
			(101, backlog - 1),
		] {
			assert_ok!(DirectToRelay::validator_set(
				rc_client::ValidatorSetReport::new_terminal(set.clone(), id, Some(backlog - 1))
			));
			assert_eq!(StoredRange::<Runtime>::get(), Some((start, backlog)));
		}
	});
}

/// The plan reset and the commission clamp run only for a report rc-client
/// passes on to staking: a stale or duplicated one changes neither.
#[test]
fn a_stale_session_report_neither_resets_the_plan_nor_clamps() {
	with_ext(|| {
		let alice = account(Alice);
		let commission = || staking::Validators::<Runtime>::get(&alice).commission;
		let resets = || {
			System::events()
				.into_iter()
				.filter(|r| {
					matches!(
						r.event,
						RuntimeEvent::PagedElection(
							pallet_paged_election::Event::EraPlanReset { .. }
						)
					)
				})
				.count()
		};
		let report = |end_index| rc_client::SessionReport::new_terminal(end_index, vec![], None);

		// Era 2 planned with nothing holding its set, and a commission above the
		// ceiling.
		System::set_block_number(1);
		let active = 1;
		staking::ActiveEra::<Runtime>::put(staking::ActiveEraInfo {
			index: active,
			start: Some(0),
		});
		staking::CurrentEra::<Runtime>::put(active + 1);
		staking::Validators::<Runtime>::insert(
			&alice,
			staking::ValidatorPrefs {
				commission: Perbill::from_percent(50),
				blocked: false,
			},
		);
		staking::MaxCommission::<Runtime>::put(Perbill::from_percent(10));
		let last = 5;
		rc_client::LastSessionReportEndingIndex::<Runtime>::put(last);
		assert!(plan_is_stalled(&report(last + 1)));
		System::reset_events();

		for stale in [last - 1, last] {
			assert_ok!(DirectToAssetHub::relay_session_report(report(stale)));
		}
		assert_eq!(staking::CurrentEra::<Runtime>::get(), Some(active + 1));
		assert_eq!(commission(), Perbill::from_percent(50));
		assert_eq!(resets(), 0);
		assert_eq!(
			rc_client::LastSessionReportEndingIndex::<Runtime>::get(),
			Some(last)
		);

		assert_ok!(DirectToAssetHub::relay_session_report(report(last + 1)));
		assert_eq!(resets(), 1);
		assert_eq!(commission(), Perbill::from_percent(10));
	});
}

/// The call filter refuses every call of both clients from any account
/// (`sudo_as` included): their messages come from the adapters, keys go through
/// `session.set_keys`. Root skips the filter, so ah-client's admin calls work
/// through sudo; rc-client's key calls need a signed stash, which root is not.
#[test]
fn the_call_filter_refuses_every_client_call() {
	with_ext(|| {
		let key_calls = [
			RuntimeCall::RcClient(rc_client::Call::set_keys {
				keys: vec![0; 64],
				proof: vec![],
				max_delivery_and_remote_execution_fee: None,
			}),
			RuntimeCall::RcClient(rc_client::Call::purge_keys {
				max_delivery_and_remote_execution_fee: None,
			}),
		];
		let admin = RuntimeCall::AhClient(ah_client::Call::set_mode {
			mode: ah_client::OperatingMode::Active,
		});
		let signed = || RuntimeOrigin::signed(AccountId::from([0x0b; 32]));
		for call in key_calls
			.iter()
			.chain(&messages(&AccountId::from([0x0a; 32]), 7))
			.chain([&admin])
		{
			assert!(!LocalRelayFilter::contains(call));
			assert_noop!(
				call.clone().dispatch(signed()).map_err(|e| e.error),
				filtered()
			);
		}
		for call in key_calls {
			assert_noop!(
				call.dispatch(RuntimeOrigin::root()).map_err(|e| e.error),
				DispatchError::BadOrigin
			);
		}
		assert_ok!(admin.dispatch(RuntimeOrigin::root()));
		let session_keys = RuntimeCall::Session(pallet_session::Call::purge_keys {});
		assert!(LocalRelayFilter::contains(&session_keys));
	});
}
