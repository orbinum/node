// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Private staking as the runtime wires it: a pool's root opens it, entries are
//! bonded at once and minted as shares once their era is compounded, exits
//! unbond their value and mint an ORB note when it unlocks, fees earned in shares
//! are redeemed for ORB, and a destroying pool winds its shares down.
//!
//! A bound spend is simulated where its proof would settle: an entry's ORB is
//! paid into `m_P`, an exit's shares are burned from the shielded ledger, then
//! the action runs through `BoundActions`.

use crate::staking::private::{
	self, Action, Entries, EntryEscrow, EntryPoints, Exits, FeeExits, Pools,
};
use crate::test_utils::{
	blocks::{active_era, run_block},
	network::with_validators,
	ORB,
};
use crate::{
	AccountId, Balance, Balances, NominationPools, PrivateStaking, Runtime, RuntimeEvent,
	RuntimeOrigin, ShieldedPool, System,
};
use frame_support::{
	assert_noop, assert_ok,
	traits::fungible::{Inspect, Mutate},
};
use pallet_nomination_pools::{PoolId, PoolState};
use pallet_shielded_pool::{
	types::NATIVE_ASSET_ID, BoundActions, PendingFees, PoolBalancePerAsset,
};
use sp_keyring::Sr25519Keyring;

const POOL: PoolId = 1;
const MILLI: Balance = ORB / 1_000;

fn depositor() -> AccountId {
	AccountId::from([0x51; 32])
}

fn stranger() -> AccountId {
	AccountId::from([0x5f; 32])
}

fn signed(who: &AccountId) -> RuntimeOrigin {
	RuntimeOrigin::signed(who.clone())
}

fn m_p() -> AccountId {
	PrivateStaking::member_account(POOL)
}

/// A canonical one-time key or blinding.
fn key(n: u8) -> [u8; 32] {
	[n; 32]
}

fn enter(n: u8) -> Action {
	Action::Enter {
		pool_id: POOL,
		owner_pk: key(n),
		blinding: key(n + 1),
		min_shares: 0,
	}
}

fn exit(n: u8) -> Action {
	Action::Exit {
		pool_id: POOL,
		owner_pk: key(n),
		blinding: key(n + 1),
		min_value: 0,
	}
}

fn asset() -> u32 {
	Pools::<Runtime>::get(POOL).expect("private pool").asset_id
}

fn supply() -> u128 {
	Pools::<Runtime>::get(POOL).expect("private pool").supply
}

fn ledger(asset_id: u32) -> Balance {
	PoolBalancePerAsset::<Runtime>::get(asset_id)
}

/// Pool 1, created by the depositor nominating Alice, opened to private members.
fn with_private_pool<R>(run: impl FnOnce() -> R) -> R {
	with_validators(|| {
		Balances::set_balance(&depositor(), 1_000 * ORB);
		assert_ok!(NominationPools::create(
			signed(&depositor()),
			crate::staking::params::TEST_POOL_MIN_CREATE_BOND,
			depositor(),
			depositor(),
			depositor()
		));
		assert_ok!(NominationPools::nominate(
			signed(&depositor()),
			POOL,
			vec![crate::test_utils::account(Sr25519Keyring::Alice)]
		));
		assert_ok!(PrivateStaking::set_private(
			signed(&depositor()),
			POOL,
			true
		));
		run()
	})
}

/// An entry of `value` ORB: the spend pays `m_P`, then the action runs.
fn spend_into(action: Action, value: Balance) {
	assert_ok!(<PrivateStaking as BoundActions<AccountId>>::validate(
		&action,
		NATIVE_ASSET_ID,
		value,
		0
	));
	Balances::mint_into(&m_p(), value).expect("spend pays m_P");
	assert_ok!(<PrivateStaking as BoundActions<AccountId>>::execute(
		action,
		NATIVE_ASSET_ID,
		value,
		0
	));
}

/// An exit of `shares`: the spend burns them, then the action runs.
fn spend_out(action: Action, shares: u128) {
	let asset_id = asset();
	assert_ok!(<PrivateStaking as BoundActions<AccountId>>::validate(
		&action, asset_id, shares, 0
	));
	PoolBalancePerAsset::<Runtime>::mutate(asset_id, |b| *b -= shares);
	assert_ok!(<PrivateStaking as BoundActions<AccountId>>::execute(
		action, asset_id, shares, 0
	));
}

thread_local! {
	/// The pallet's events so far: a block's are cleared when the next starts.
	static SEEN: core::cell::RefCell<Vec<private::Event<Runtime>>> = Default::default();
}

fn record() {
	let events = System::events().into_iter().filter_map(|r| match r.event {
		RuntimeEvent::PrivateStaking(event) => Some(event),
		_ => None,
	});
	SEEN.with(|seen| {
		let mut seen = seen.borrow_mut();
		for event in events {
			if !seen.contains(&event) {
				seen.push(event);
			}
		}
	});
}

fn seen() -> Vec<private::Event<Runtime>> {
	record();
	SEEN.with(|seen| seen.borrow().clone())
}

fn run_blocks(count: u32) {
	let start = System::block_number() + 1;
	for n in start..start + count {
		record();
		run_block(n);
	}
	record();
}

/// Runs to `era` and on until its `on_idle` work is done.
fn settle_era(era: u32) {
	while active_era() < era {
		record();
		crate::test_utils::blocks::next_session();
	}
	run_blocks(50);
}

fn settled_entries() -> Vec<u128> {
	seen()
		.into_iter()
		.filter_map(|event| match event {
			private::Event::EntrySettled { shares, .. } => Some(shares),
			_ => None,
		})
		.collect()
}

fn settled_exits() -> Vec<u128> {
	seen()
		.into_iter()
		.filter_map(|event| match event {
			private::Event::ExitSettled { value, .. } => Some(value),
			_ => None,
		})
		.collect()
}

/// The pallet's invariants (its `try_state`).
fn assert_solvent() {
	let private = Pools::<Runtime>::get(POOL).expect("private pool");
	assert_eq!(private.supply, ledger(private.asset_id), "supply == ledger");
	assert!(EntryPoints::<Runtime>::get(POOL) <= PrivateStaking::member_points(POOL));
	let free: Balance = <Balances as Inspect<AccountId>>::balance(&m_p());
	assert!(
		private::Escrow::<Runtime>::get(POOL) + EntryEscrow::<Runtime>::get(POOL) <= free,
		"escrows exceed m_P's balance"
	);
}

#[test]
fn only_the_pool_root_opens_it_and_the_first_opening_issues_its_shares() {
	with_validators(|| {
		Balances::set_balance(&depositor(), 1_000 * ORB);
		assert_ok!(NominationPools::create(
			signed(&depositor()),
			crate::staking::params::TEST_POOL_MIN_CREATE_BOND,
			depositor(),
			depositor(),
			depositor()
		));
		assert_noop!(
			PrivateStaking::set_private(signed(&stranger()), POOL, true),
			private::Error::<Runtime>::NotRoot
		);
		assert_noop!(
			PrivateStaking::set_private(signed(&depositor()), 9, true),
			private::Error::<Runtime>::NoSuchPool
		);
		assert!(!<PrivateStaking as BoundActions<AccountId>>::is_executor(
			&m_p()
		));
		assert_noop!(
			PrivateStaking::set_private(signed(&depositor()), POOL, false),
			private::Error::<Runtime>::NotPrivate
		);

		assert_ok!(PrivateStaking::set_private(
			signed(&depositor()),
			POOL,
			true
		));
		let asset_id = asset();
		assert_ne!(asset_id, NATIVE_ASSET_ID);
		assert!(<PrivateStaking as BoundActions<AccountId>>::is_executor(
			&m_p()
		));
		assert_eq!(
			<PrivateStaking as BoundActions<AccountId>>::executor(&enter(1)),
			Some(m_p())
		);

		// Closing keeps the asset; reopening reuses it.
		assert_ok!(PrivateStaking::set_private(
			signed(&depositor()),
			POOL,
			false
		));
		assert_noop!(
			<PrivateStaking as BoundActions<AccountId>>::validate(
				&enter(1),
				NATIVE_ASSET_ID,
				100 * ORB,
				0
			),
			private::Error::<Runtime>::NotPrivate
		);
		assert_ok!(PrivateStaking::set_private(
			signed(&depositor()),
			POOL,
			true
		));
		assert_eq!(asset(), asset_id);
	});
}

#[test]
fn an_entry_breaking_a_rule_is_refused_at_admission() {
	with_private_pool(|| {
		let check = |action: &Action, asset_id: u32, value: Balance| {
			<PrivateStaking as BoundActions<AccountId>>::validate(action, asset_id, value, 0)
		};
		assert_noop!(
			check(&enter(1), NATIVE_ASSET_ID, 9 * ORB),
			private::Error::<Runtime>::BelowMinimum
		);
		assert_noop!(
			check(&enter(1), asset(), 100 * ORB),
			private::Error::<Runtime>::WrongAsset
		);
		let bad_key = Action::Enter {
			pool_id: POOL,
			owner_pk: [0xff; 32],
			blinding: key(1),
			min_shares: 0,
		};
		assert_noop!(
			check(&bad_key, NATIVE_ASSET_ID, 100 * ORB),
			private::Error::<Runtime>::InvalidKey
		);
		for (owner_pk, blinding) in [([0; 32], key(1)), (key(1), [0; 32])] {
			let zero = Action::Enter {
				pool_id: POOL,
				owner_pk,
				blinding,
				min_shares: 0,
			};
			assert_noop!(
				check(&zero, NATIVE_ASSET_ID, 100 * ORB),
				private::Error::<Runtime>::InvalidKey
			);
		}
		assert_noop!(
			PrivateStaking::set_min_entry(signed(&depositor()), ORB),
			sp_runtime::DispatchError::BadOrigin
		);
		assert_ok!(NominationPools::set_state(
			signed(&depositor()),
			POOL,
			PoolState::Blocked
		));
		assert_noop!(
			check(&enter(1), NATIVE_ASSET_ID, 100 * ORB),
			private::Error::<Runtime>::PoolNotOpen
		);
		assert_ok!(NominationPools::set_state(
			signed(&depositor()),
			POOL,
			PoolState::Destroying
		));
		assert_noop!(
			PrivateStaking::set_private(signed(&depositor()), POOL, true),
			private::Error::<Runtime>::PoolNotOpen
		);
	});
}

#[test]
fn an_entry_is_minted_after_its_era_compounds_and_shares_then_earn() {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 100 * ORB);
		// Held, not bonded: the entry draws no pool rewards while it waits.
		assert_eq!(EntryEscrow::<Runtime>::get(POOL), 100 * ORB);
		assert_eq!(PrivateStaking::member_points(POOL), 0);
		assert_eq!(EntryPoints::<Runtime>::get(POOL), 0);
		assert_eq!(Entries::<Runtime>::get(POOL, (era, 0)).len(), 1);
		assert_eq!(supply(), 0, "nothing minted in the entry era");
		assert_solvent();

		settle_era(era + 1);
		let minted = settled_entries();
		assert_eq!(minted.len(), 1, "the entry settles once its era compounded");
		assert_eq!(supply(), minted[0]);
		// Bonded when its shares were minted.
		assert_eq!(EntryEscrow::<Runtime>::get(POOL), 0);
		assert!(PrivateStaking::member_value(POOL) >= 100 * ORB - 1);
		assert!(!Entries::<Runtime>::contains_key(POOL, (era, 0)));
		let private = Pools::<Runtime>::get(POOL).unwrap();
		let worth = PrivateStaking::value_of(POOL, &private, minted[0]);
		assert!(worth >= 100 * ORB - 1, "the entry keeps its value: {worth}");
		assert_solvent();

		// The pool backs Alice now: a paid era raises every share's value.
		settle_era(era + 3);
		let private = Pools::<Runtime>::get(POOL).unwrap();
		let later = PrivateStaking::value_of(POOL, &private, minted[0]);
		assert!(later > worth, "compounded: {later} > {worth}");
		assert_solvent();
	});
}

#[test]
fn a_later_entry_buys_at_the_current_price_and_dilutes_nobody() {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 100 * ORB);
		settle_era(era + 3);
		let first = settled_entries()[0];
		let private = Pools::<Runtime>::get(POOL).unwrap();
		let before = PrivateStaking::value_of(POOL, &private, first);

		let entered = active_era();
		spend_into(enter(3), 50 * ORB);
		// The pending entry is not the minted shares' to share.
		let private = Pools::<Runtime>::get(POOL).unwrap();
		assert_eq!(PrivateStaking::value_of(POOL, &private, first), before);

		settle_era(entered + 1);
		let minted = settled_entries();
		assert_eq!(minted.len(), 2);
		let private = Pools::<Runtime>::get(POOL).unwrap();
		let second = PrivateStaking::value_of(POOL, &private, minted[1]);
		assert!(
			(50 * ORB - ORB / 1_000..=50 * ORB).contains(&second),
			"{second}"
		);
		assert!(PrivateStaking::value_of(POOL, &private, first) >= before);
		assert_solvent();
	});
}

#[test]
fn an_exit_unbonds_its_value_and_mints_an_orb_note_when_it_unlocks() {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 100 * ORB);
		settle_era(era + 2);
		let shares = supply();
		let private = Pools::<Runtime>::get(POOL).unwrap();
		let worth = PrivateStaking::value_of(POOL, &private, shares);
		let native = ledger(NATIVE_ASSET_ID);

		// The last shares out take the whole membership.
		let exited = active_era();
		spend_out(exit(5), shares);
		assert_eq!(supply(), 0);
		let unlock = exited + crate::staking::params::NOMINATOR_UNBOND_DURATION;
		let queued = Exits::<Runtime>::get(POOL, (unlock, 0));
		assert_eq!(queued.len(), 1);
		assert!(queued[0].value >= worth, "{} vs {worth}", queued[0].value);
		assert!(settled_exits().is_empty());

		settle_era(unlock);
		let paid = settled_exits();
		assert_eq!(paid, vec![queued[0].value]);
		assert_eq!(ledger(NATIVE_ASSET_ID), native + paid[0]);
		assert!(!Exits::<Runtime>::contains_key(POOL, (unlock, 0)));
		assert_solvent();
	});
}

#[test]
fn an_exit_leaving_the_membership_under_its_minimum_is_refused() {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 100 * ORB);
		settle_era(era + 1);
		let shares = supply();
		// All but a sliver: the rest would sit under the pool's join minimum.
		let check = <PrivateStaking as BoundActions<AccountId>>::validate(
			&exit(5),
			asset(),
			shares - shares / 1_000,
			0,
		);
		assert_noop!(check, private::Error::<Runtime>::RemainderBelowMinimum);
		assert_ok!(<PrivateStaking as BoundActions<AccountId>>::validate(
			&exit(5),
			asset(),
			shares / 2,
			0
		));
	});
}

#[test]
fn fees_earned_in_shares_are_redeemed_for_orb() {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 100 * ORB);
		settle_era(era + 1);
		let asset_id = asset();
		let fee = supply() / 10;
		let min = <PrivateStaking as BoundActions<AccountId>>::min_fee(asset_id).unwrap();
		assert!((1..=fee).contains(&min));

		// A spend in shares paid `fee` to the author: still in supply and ledger.
		let author = crate::test_utils::account(Sr25519Keyring::Alice);
		PendingFees::<Runtime>::insert(&author, asset_id, fee);
		assert_ok!(ShieldedPool::claim_fees(signed(&author), asset_id, fee));
		assert_eq!(PendingFees::<Runtime>::get(&author, asset_id), 0);
		assert_solvent();

		let unlock = active_era() + crate::staking::params::NOMINATOR_UNBOND_DURATION;
		let queued = FeeExits::<Runtime>::get(POOL, (unlock, 0));
		assert_eq!(queued.len(), 1);
		let value = queued[0].value;
		assert!(value > 9 * ORB, "a tenth of the shares: {value}");

		let before = Balances::balance(&author);
		settle_era(unlock);
		assert!(seen().iter().any(|event| matches!(
			event,
			private::Event::FeesRedeemed { value: v, .. } if *v == value
		)));
		// Alice also earns era rewards meanwhile: at least the fee's value.
		assert!(Balances::balance(&author) >= before + value);
		assert!(!FeeExits::<Runtime>::contains_key(POOL, (unlock, 0)));
	});
}

#[test]
fn a_destroying_pool_refunds_pending_entries_and_winds_its_shares_down() {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 100 * ORB);
		settle_era(era + 1);
		let first = supply();
		spend_into(enter(3), 20 * ORB);

		assert_ok!(NominationPools::set_state(
			signed(&depositor()),
			POOL,
			PoolState::Destroying
		));
		run_blocks(2);
		// The pending entry is refunded before the value is fixed.
		assert_eq!(settled_entries().len(), 1);
		assert!(seen()
			.iter()
			.any(|event| matches!(event, private::Event::EntryRefunded { .. })));
		let private = Pools::<Runtime>::get(POOL).unwrap();
		let wind = private.wind_down.expect("winding down");
		assert!(wind.value >= 100 * ORB - 1, "{}", wind.value);
		assert_eq!(EntryPoints::<Runtime>::get(POOL), 0);
		assert_noop!(
			<PrivateStaking as BoundActions<AccountId>>::validate(
				&enter(7),
				NATIVE_ASSET_ID,
				100 * ORB,
				0
			),
			private::Error::<Runtime>::NotPrivate
		);

		// Exits take their part of the fixed value and wait for the unbonding.
		let value = PrivateStaking::value_of(POOL, &private, first / 2);
		spend_out(exit(9), first / 2);
		let queued = Exits::<Runtime>::get(POOL, (wind.unlock_era, 0));
		assert_eq!(queued.last().unwrap().value, value);
		let rest = supply();
		spend_out(exit(11), rest);
		assert_eq!(supply(), 0);

		settle_era(wind.unlock_era);
		// The refund and both exits.
		let paid = settled_exits();
		assert_eq!(paid.len(), 3);
		assert!(paid.iter().sum::<u128>() >= wind.value + 20 * ORB - MILLI);
		// Paid out: forgotten, though the pool is still destroying.
		assert!(Pools::<Runtime>::get(POOL).is_none());
	});
}

/// What third parties, pool roles, slashing and load can do to the private
/// member: none of it may move value between private holders or lose an output.
mod adversarial {
	use super::*;
	use crate::staking::params::{NOMINATOR_UNBOND_DURATION, POOL_UNBONDING_WINDOW};
	use crate::test_utils::{
		blocks::{run_to_era, settle},
		network::{charlie, report_charlie},
	};
	use crate::RuntimeCall;
	use frame_support::{dispatch::GetDispatchInfo, traits::Get};
	use pallet_nomination_pools::{Call as PoolsCall, PoolMembers, SubPoolsStorage};
	use sp_runtime::traits::Dispatchable;

	const MILLI_ORB: Balance = ORB / 1_000;

	fn alice() -> AccountId {
		crate::test_utils::account(Sr25519Keyring::Alice)
	}

	fn dispatch(who: &AccountId, call: PoolsCall<Runtime>) {
		let _ = RuntimeCall::NominationPools(call).dispatch(signed(who));
	}

	fn m_p_points() -> Balance {
		PoolMembers::<Runtime>::get(m_p()).map_or(0, |m| m.points)
	}

	fn worth(shares: u128) -> Balance {
		PrivateStaking::value_of(POOL, &Pools::<Runtime>::get(POOL).unwrap(), shares)
	}

	/// A canonical key from a counter, for more notes than `key` has.
	fn wide_key(i: u16) -> [u8; 32] {
		let mut k = [0u8; 32];
		k[..2].copy_from_slice(&i.to_le_bytes());
		k[2] = 1;
		k
	}

	fn wide_enter(i: u16) -> Action {
		Action::Enter {
			pool_id: POOL,
			owner_pk: wide_key(2 * i),
			blinding: wide_key(2 * i + 1),
			min_shares: 0,
		}
	}

	fn wide_exit(i: u16) -> Action {
		Action::Exit {
			pool_id: POOL,
			owner_pk: wide_key(10_000 + 2 * i),
			blinding: wide_key(10_001 + 2 * i),
			min_value: 0,
		}
	}

	#[test]
	fn nobody_unbonds_the_private_member_of_a_destroying_pool() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			let first = supply();
			spend_into(enter(3), 20 * ORB);

			assert_ok!(NominationPools::set_state(
				signed(&depositor()),
				POOL,
				PoolState::Destroying
			));
			dispatch(
				&stranger(),
				PoolsCall::unbond {
					member_account: m_p(),
					unbonding_points: m_p_points(),
				},
			);
			run_blocks(2);

			let second = supply() - first;
			assert!(worth(second) <= 20 * ORB + MILLI_ORB, "{}", worth(second));
			assert!(worth(first) >= 100 * ORB - MILLI_ORB, "{}", worth(first));
		});
	}

	#[test]
	fn a_pool_root_cannot_kick_the_private_member() {
		with_private_pool(|| {
			spend_into(enter(1), 1_000 * ORB);
			settle_era(active_era() + 1);
			let victim = supply();

			assert_ok!(NominationPools::set_state(
				signed(&depositor()),
				POOL,
				PoolState::Blocked
			));
			dispatch(
				&depositor(),
				PoolsCall::unbond {
					member_account: m_p(),
					unbonding_points: m_p_points(),
				},
			);
			assert_ok!(NominationPools::set_state(
				signed(&depositor()),
				POOL,
				PoolState::Open
			));
			spend_into(enter(3), 10 * ORB);
			settle_era(active_era() + 1);

			let attacker = supply() - victim;
			assert!(
				worth(attacker) <= 10 * ORB + MILLI_ORB,
				"{}",
				worth(attacker)
			);
			assert!(
				worth(victim) >= 1_000 * ORB - MILLI_ORB,
				"{}",
				worth(victim)
			);
		});
	}

	#[test]
	fn settlement_goes_on_with_thousands_of_private_pools() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			for i in 0..9_000u32 {
				Pools::<Runtime>::insert(
					1_000 + i,
					private::PrivatePool {
						asset_id: 0,
						enabled: false,
						supply: 0,
						compounded_era: None,
						wind_down: None,
					},
				);
			}
			settle_era(active_era() + 1);
			run_blocks(200);
			assert_eq!(settled_entries().len(), 1, "the real pool still settles");
		});
	}

	#[test]
	fn exits_paid_across_blocks_survive_compounding() {
		with_private_pool(|| {
			for i in 0..40u16 {
				spend_into(wide_enter(i), 10 * ORB);
			}
			settle_era(active_era() + 1);
			let shares = settled_entries();
			assert_eq!(shares.len(), 40);
			// Keep one note in, so every exit is partial.
			for (i, s) in shares.iter().skip(1).enumerate() {
				spend_out(wide_exit(i as u16), *s);
			}
			let unlock = active_era() + NOMINATOR_UNBOND_DURATION;

			// The unlock era starts without a block: on_idle runs by hand.
			let now = pallet_staking_async::ActiveEra::<Runtime>::get().unwrap();
			pallet_staking_async::ActiveEra::<Runtime>::put(pallet_staking_async::ActiveEraInfo {
				index: unlock,
				start: now.start,
			});
			pallet_staking_async::CurrentEra::<Runtime>::put(unlock);
			// The previous era is paid, so the pool compounds once asked to.
			pallet_auto_payout::Queue::<Runtime>::kill();
			pallet_auto_payout::Current::<Runtime>::kill();
			// Pay a few exits, then compound, then the rest.
			let step = PrivateStaking::step_weight();
			let n = System::block_number();
			<PrivateStaking as frame_support::traits::Hooks<_>>::on_idle(n, step * 4);
			record();
			Pools::<Runtime>::mutate(POOL, |p| p.as_mut().unwrap().compounded_era = None);
			for b in 1..40 {
				<PrivateStaking as frame_support::traits::Hooks<_>>::on_idle(
					n + b,
					<Runtime as private::Config>::MaxIdleWeight::get(),
				);
				record();
			}
			assert_eq!(settled_exits().len(), 39, "every unlocked exit is paid");
		});
	}

	#[test]
	fn a_wound_down_pool_charges_the_usual_spend_fee() {
		with_private_pool(|| {
			spend_into(enter(1), 5_000 * ORB);
			settle_era(active_era() + 1);
			spend_into(enter(3), 10 * ORB);
			settle_era(active_era() + 1);
			assert_ok!(NominationPools::set_state(
				signed(&depositor()),
				POOL,
				PoolState::Destroying
			));
			run_blocks(2);
			assert!(Pools::<Runtime>::get(POOL).unwrap().wind_down.is_some());
			let min = <PrivateStaking as BoundActions<AccountId>>::min_fee(asset()).unwrap();
			let fee: u128 =
				<<Runtime as pallet_shielded_pool::Config>::MinSpendFee as Get<u128>>::get();
			assert!(worth(min) <= 2 * fee, "the floor is worth {}", worth(min));
		});
	}

	#[test]
	fn exits_never_run_out_of_queue_room() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			// An era's worth of squatted pages, as 8 192 tiny exits would leave.
			let unlock = active_era() + NOMINATOR_UNBOND_DURATION;
			let page: frame_support::BoundedVec<_, _> = vec![
				private::Pending {
					value: 1,
					funded: 0,
					owner_pk: key(5),
					blinding: key(6),
				};
				256
			]
			.try_into()
			.unwrap();
			for n in 0..32 {
				Exits::<Runtime>::insert(POOL, (unlock, n), page.clone());
			}
			private::Unlocks::<Runtime>::insert(
				POOL,
				unlock,
				private::Unlock {
					exits: private::Pages { next: 0, end: 32 },
					owed: 32 * 256,
					..Default::default()
				},
			);
			spend_out(exit(7), supply() / 10);
			assert_eq!(Exits::<Runtime>::get(POOL, (unlock, 32)).len(), 1);
			assert_ok!(<PrivateStaking as BoundActions<AccountId>>::validate(
				&exit(7),
				asset(),
				1_000_000,
				0
			));
		});
	}

	#[test]
	fn a_wind_down_pays_out_what_the_member_holds_free() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			// Rewards claimed into m_P since its last compounding.
			assert_ok!(Balances::mint_into(&m_p(), 10 * ORB));
			assert_ok!(NominationPools::set_state(
				signed(&depositor()),
				POOL,
				PoolState::Destroying
			));
			run_blocks(2);
			let wind = Pools::<Runtime>::get(POOL).unwrap().wind_down.unwrap();
			spend_out(exit(5), supply());
			settle_era(wind.unlock_era);
			run_blocks(5);
			let ed: Balance =
				<<Runtime as pallet_balances::Config>::ExistentialDeposit as Get<Balance>>::get();
			assert!(
				Balances::balance(&m_p()) <= ed + MILLI_ORB,
				"{}",
				Balances::balance(&m_p())
			);
			assert!(settled_exits().iter().sum::<u128>() >= 110 * ORB - MILLI_ORB);
		});
	}

	#[test]
	fn claiming_fees_in_shares_is_weighed_as_the_unbond_it_runs() {
		with_private_pool(|| {
			let call = RuntimeCall::ShieldedPool(pallet_shielded_pool::Call::claim_fees {
				asset_id: asset(),
				amount: 1,
			});
			use pallet_nomination_pools::WeightInfo as _;
			let unbond = <Runtime as pallet_nomination_pools::Config>::WeightInfo::unbond();
			assert!(call.get_dispatch_info().call_weight.all_gte(unbond));
		});
	}

	/// Pool 1 backing Alice and Charlie, open to private members, nominators slashable.
	fn with_slashable_private_pool<R>(run: impl FnOnce() -> R) -> R {
		crate::test_utils::network::with_validators(|| {
			super::super::nominators_slashable();
			Balances::set_balance(&depositor(), 1_000 * ORB);
			assert_ok!(NominationPools::create(
				signed(&depositor()),
				crate::staking::params::TEST_POOL_MIN_CREATE_BOND,
				depositor(),
				depositor(),
				depositor()
			));
			assert_ok!(NominationPools::nominate(
				signed(&depositor()),
				POOL,
				vec![alice(), charlie()]
			));
			assert_ok!(PrivateStaking::set_private(
				signed(&depositor()),
				POOL,
				true
			));
			run()
		})
	}

	fn apply_era() -> u32 {
		pallet_staking_async::UnappliedSlashes::<Runtime>::iter_keys()
			.map(|(era, _)| era)
			.next()
			.expect("a deferred slash")
	}

	#[test]
	fn a_slash_while_entries_are_pending_is_not_charged_to_them() {
		with_slashable_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			run_to_era(2);
			settle();
			run_blocks(20);
			let first = supply();
			assert!(first > 0);
			assert_ok!(report_charlie());
			settle();
			let apply_at = apply_era();
			run_to_era(apply_at - 1);
			settle();
			run_blocks(20);
			spend_into(enter(3), 1_000 * ORB);
			run_to_era(apply_at);
			settle();
			run_blocks(20);
			// Right after the entry is minted, before it earns a reward of its own.
			let second = supply() - first;
			assert!(second > 0, "the entry was minted");
			// Held unbonded while it waited, it was not exposed: the slash is the
			// holder's alone, and the entry is worth what it brought.
			let two = worth(second);
			assert!(
				two >= 1_000 * ORB - MILLI,
				"the entry kept its value: {two}"
			);
			assert!(two <= 1_000 * ORB, "and no more: {two}");
		});
	}

	#[test]
	fn exits_in_the_slash_window_share_the_slash() {
		with_slashable_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			spend_into(enter(3), 100 * ORB);
			run_to_era(2);
			settle();
			run_blocks(20);
			let shares = settled_entries();
			assert_eq!(shares.len(), 2);
			assert_ok!(report_charlie());
			settle();
			let apply_at = apply_era();
			spend_out(exit(5), shares[0]);
			spend_out(exit(7), shares[1]);
			let unlock = active_era() + crate::staking::params::BONDING_DURATION;
			let promised: Vec<u128> = Exits::<Runtime>::get(POOL, (unlock, 0))
				.iter()
				.map(|exit| exit.value)
				.collect();
			run_to_era(apply_at);
			settle();
			run_to_era(unlock);
			settle();
			run_blocks(20);
			let paid = settled_exits();
			assert_eq!(promised.len(), 2);
			assert_eq!(paid.len(), 2, "both exits are paid: {paid:?}");
			assert!(
				paid[0].abs_diff(paid[1]) <= paid[0] / 100,
				"pro rata: {paid:?}"
			);
			assert!(
				paid[0] < promised[0] && paid[1] < promised[1],
				"the slash reached the exits: {paid:?} of {promised:?}"
			);
		});
	}

	#[test]
	fn a_wind_down_after_unbonding_shortens_unlocks_with_its_own_chunk() {
		with_private_pool(|| {
			use crate::staking::params::BONDING_DURATION;
			pallet_staking_async::AreNominatorsSlashable::<Runtime>::put(true);
			spend_into(enter(1), 1_000 * ORB);
			settle_era(active_era() + 1);
			let long = active_era() + BONDING_DURATION;
			spend_out(exit(5), supply() / 50);
			let promised = Exits::<Runtime>::get(POOL, (long, 0))[0].value;
			pallet_staking_async::AreNominatorsSlashable::<Runtime>::put(false);
			let short = active_era() + NOMINATOR_UNBOND_DURATION;
			assert!(short < long);
			spend_out(exit(7), supply() / 50);
			assert_ok!(NominationPools::set_state(
				signed(&depositor()),
				POOL,
				PoolState::Destroying
			));
			run_blocks(2);
			let wind = Pools::<Runtime>::get(POOL).unwrap().wind_down.unwrap();
			assert_eq!(wind.unlock_era, short);

			settle_era(long);
			spend_out(exit(9), supply());
			run_blocks(5);
			let paid = settled_exits();
			assert_eq!(paid.len(), 3, "{paid:?}");
			assert!(paid.contains(&promised), "{paid:?} vs {promised}");
			assert!(
				paid[2] + MILLI_ORB >= wind.value,
				"{paid:?} vs {}",
				wind.value
			);
			let ed: Balance =
				<<Runtime as pallet_balances::Config>::ExistentialDeposit as Get<Balance>>::get();
			assert!(
				Balances::balance(&m_p()) <= ed + MILLI_ORB,
				"nothing stranded: {}",
				Balances::balance(&m_p())
			);
		});
	}

	#[test]
	fn a_slash_before_wind_down_is_not_charged_twice() {
		with_slashable_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			spend_into(enter(3), 100 * ORB);
			run_to_era(2);
			settle();
			run_blocks(20);
			let shares = settled_entries();
			assert_eq!(shares.len(), 2);
			assert_ok!(report_charlie());
			settle();
			let apply_at = apply_era();
			spend_out(exit(5), shares[0]);
			let unlock = active_era() + crate::staking::params::BONDING_DURATION;
			run_to_era(apply_at);
			settle();
			run_blocks(20);
			assert!(apply_at < unlock);
			// What the holder left in is worth after the slash.
			let held = PrivateStaking::net_value(POOL);
			assert_ok!(NominationPools::set_state(
				signed(&depositor()),
				POOL,
				PoolState::Destroying
			));
			run_blocks(20);
			let wind = Pools::<Runtime>::get(POOL).unwrap().wind_down.unwrap();
			assert!(
				wind.value + MILLI_ORB >= held,
				"the queued exit's slash stays with it: {} vs {held}",
				wind.value
			);
			run_to_era(unlock.max(wind.unlock_era));
			settle();
			run_blocks(20);
			spend_out(exit(9), supply());
			run_blocks(20);
			assert_eq!(settled_exits().len(), 2);
			let ed: Balance =
				<<Runtime as pallet_balances::Config>::ExistentialDeposit as Get<Balance>>::get();
			assert!(
				Balances::balance(&m_p()) <= ed + MILLI_ORB,
				"nothing stranded: {}",
				Balances::balance(&m_p())
			);
		});
	}

	#[test]
	fn a_destroy_leaves_uncompounded_rewards_with_the_minted_shares() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			let holder = supply();
			// Rewards claimed into m_P since its last compounding.
			assert_ok!(Balances::mint_into(&m_p(), 10 * ORB));
			spend_into(enter(3), 100 * ORB);
			assert_ok!(NominationPools::set_state(
				signed(&depositor()),
				POOL,
				PoolState::Destroying
			));
			run_blocks(2);
			assert_eq!(
				supply(),
				holder,
				"the pending entry is refunded, not minted"
			);
			assert!(worth(holder) >= 110 * ORB - MILLI_ORB, "{}", worth(holder));
			let refund = seen()
				.into_iter()
				.find_map(|event| match event {
					private::Event::EntryRefunded { value, .. } => Some(value),
					_ => None,
				})
				.expect("refunded");
			assert!(refund <= 100 * ORB, "{refund}");
		});
	}

	#[test]
	fn a_loaded_pool_yields_to_the_others_every_block() {
		with_private_pool(|| {
			let era = active_era();
			let (a, b) = (1_001, 1_002);
			for id in [a, b] {
				Pools::<Runtime>::insert(
					id,
					private::PrivatePool {
						asset_id: 0,
						enabled: false,
						supply: 0,
						compounded_era: Some(era),
						wind_down: None,
					},
				);
				Balances::set_balance(&PrivateStaking::member_account(id), 10 * ORB);
			}
			// Pools' order is their key hash: load whichever comes first.
			let loaded = Pools::<Runtime>::iter_keys()
				.find(|id| *id == a || *id == b)
				.unwrap();
			let other = if loaded == a { b } else { a };
			let queue = |id: PoolId, from: u16, count: u16| {
				let exits: Vec<private::Pending> = (from..from + count)
					.map(|i| private::Pending {
						value: MILLI_ORB,
						funded: MILLI_ORB,
						owner_pk: wide_key(2 * i),
						blinding: wide_key(2 * i + 1),
					})
					.collect();
				let pages = exits.chunks(256).count() as u32;
				for (n, page) in exits.chunks(256).enumerate() {
					Exits::<Runtime>::insert(
						id,
						(era, n as u32),
						frame_support::BoundedVec::<_, _>::try_from(page.to_vec()).unwrap(),
					);
				}
				private::Unlocks::<Runtime>::insert(
					id,
					era,
					private::Unlock {
						exits: private::Pages {
							next: 0,
							end: pages,
						},
						paid: Some(sp_runtime::Perquintill::one()),
						..Default::default()
					},
				);
			};
			queue(loaded, 0, 600);
			queue(other, 1_000, 1);
			private::NextPool::<Runtime>::kill();

			let settled = |id: PoolId| {
				System::events()
					.iter()
					.filter(|r| {
						matches!(
							&r.event,
							RuntimeEvent::PrivateStaking(private::Event::ExitSettled { pool_id, .. })
								if *pool_id == id
						)
					})
					.count()
			};
			let n = System::block_number();
			for k in 0..3 {
				<PrivateStaking as frame_support::traits::Hooks<_>>::on_idle(
					n + k,
					<Runtime as private::Config>::MaxIdleWeight::get(),
				);
			}
			assert_eq!(
				settled(other),
				1,
				"the other pool's exit within three blocks"
			);
			assert!(settled(loaded) < 600, "the loaded pool is still paying");
		});
	}

	#[test]
	fn queue_keys_are_charged_as_they_are_read() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			let idle = || {
				private::NextPool::<Runtime>::kill();
				<PrivateStaking as frame_support::traits::Hooks<_>>::on_idle(
					System::block_number(),
					<Runtime as private::Config>::MaxIdleWeight::get(),
				)
			};
			let quiet = idle();
			let era = active_era();
			for later in 1..=50 {
				private::Unlocks::<Runtime>::insert(POOL, era + later, private::Unlock::default());
			}
			let loaded = idle();
			let reads = <Runtime as frame_system::Config>::DbWeight::get().reads(50);
			assert!(
				loaded.all_gte(quiet.saturating_add(reads)),
				"{loaded:?} vs {quiet:?}"
			);
		});
	}

	#[test]
	fn turning_nominator_slashing_off_keeps_pool_records_readable() {
		with_private_pool(|| {
			pallet_staking_async::AreNominatorsSlashable::<Runtime>::put(true);
			spend_into(enter(1), 1_000 * ORB);
			settle_era(active_era() + 1);
			for k in 0..(NOMINATOR_UNBOND_DURATION + POOL_UNBONDING_WINDOW + 2) {
				spend_out(exit(5 + 2 * k as u8), supply() / 50);
				settle_era(active_era() + 1);
			}
			assert!(SubPoolsStorage::<Runtime>::get(POOL).is_some());
			pallet_staking_async::AreNominatorsSlashable::<Runtime>::put(false);
			assert!(
				SubPoolsStorage::<Runtime>::get(POOL).is_some(),
				"the pool's unbonding records still decode"
			);
		});
	}
}

/// The audit's hardening: minimum outputs, the last holder's way out, admission that
/// mirrors what the pool and staking refuse, and fees redeemed as they are paid.
mod hardening {
	use super::*;
	use crate::AutoPayout;

	#[test]
	fn an_entry_short_of_its_minimum_shares_is_refunded_in_orb() {
		with_private_pool(|| {
			let entry = Action::Enter {
				pool_id: POOL,
				owner_pk: key(1),
				blinding: key(2),
				min_shares: u128::MAX,
			};
			let era = active_era();
			spend_into(entry, 50 * ORB);
			settle_era(era + 1);
			assert!(settled_entries().is_empty(), "no shares below the minimum");
			assert_eq!(supply(), 0);
			let refunded_in = seen().into_iter().find_map(|event| match event {
				private::Event::EntryRefunded { unlock_era, .. } => Some(unlock_era),
				_ => None,
			});
			// Never bonded, so nothing unbonds: the ORB comes back in the era it settled.
			assert_eq!(refunded_in, Some(era + 1));
			let refunded = settled_exits();
			assert_eq!(refunded, vec![50 * ORB], "refunded in full, at once");
			assert_eq!(EntryEscrow::<Runtime>::get(POOL), 0);
			assert_eq!(private::Escrow::<Runtime>::get(POOL), 0);
			assert_solvent();
		});
	}

	#[test]
	fn an_exit_below_its_minimum_value_is_refused() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			let shares = supply() / 2;
			let worth =
				PrivateStaking::value_of(POOL, &Pools::<Runtime>::get(POOL).unwrap(), shares);
			let exit_at_least = |min_value| Action::Exit {
				pool_id: POOL,
				owner_pk: key(5),
				blinding: key(6),
				min_value,
			};
			assert_noop!(
				<PrivateStaking as BoundActions<AccountId>>::validate(
					&exit_at_least(worth + 1),
					asset(),
					shares,
					0
				),
				private::Error::<Runtime>::BelowMinimumOutput
			);
			assert_ok!(<PrivateStaking as BoundActions<AccountId>>::validate(
				&exit_at_least(worth),
				asset(),
				shares,
				0
			));
			// Never more shares, fee included, than the pool issued.
			let all = supply();
			for (shares, fee) in [(all + 1, 0), (all, 1), (u128::MAX, u128::MAX), (0, 0)] {
				assert!(<PrivateStaking as BoundActions<AccountId>>::validate(
					&exit_at_least(0),
					asset(),
					shares,
					fee
				)
				.is_err());
			}
		});
	}

	#[test]
	fn the_last_holder_leaves_in_full_past_dust_left_by_fees() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			// A fee in shares nobody redeemed: dust in the supply.
			let dust = 1_000_000_000u128;
			let holder = supply() - dust;
			assert_ok!(<PrivateStaking as BoundActions<AccountId>>::validate(
				&exit(5),
				asset(),
				holder,
				0
			));
			spend_out(exit(5), holder);
			assert_eq!(
				PrivateStaking::member_points(POOL),
				0,
				"all of m_P unbonded"
			);
		});
	}

	/// A bound spend's order: admission, the burn, the action, then its fee.
	fn bound_exit(shares: u128, fee: u128) -> sp_runtime::DispatchResult {
		let asset_id = asset();
		<PrivateStaking as BoundActions<AccountId>>::validate(&exit(5), asset_id, shares, fee)?;
		PoolBalancePerAsset::<Runtime>::mutate(asset_id, |b| *b -= shares);
		<PrivateStaking as BoundActions<AccountId>>::execute(exit(5), asset_id, shares, fee)?;
		pallet_shielded_pool::operations::fees::credit_fee::<Runtime>(asset_id, fee)
			.map_err(Into::into)
	}

	/// Shares worth about `value` now. Through 256 bits: a share supply and a value in
	/// planck multiply past u128.
	fn shares_for(value: u128) -> u128 {
		sp_runtime::helpers_128bit::multiply_by_rational_with_rounding(
			value,
			supply(),
			PrivateStaking::net_value(POOL),
			sp_runtime::Rounding::Down,
		)
		.expect("a share count fits u128")
	}

	#[test]
	fn an_admitted_exit_never_fails_on_its_own_fee() {
		with_private_pool(|| {
			spend_into(enter(1), 12 * ORB);
			settle_era(active_era() + 1);
			let min_join: u128 = pallet_nomination_pools::MinJoinBond::<Runtime>::get();
			// The exit leaves a bit over the join minimum, the fee then less.
			let rest = shares_for(min_join / 2);
			let fee = shares_for(min_join * 6 / 10);
			assert!(fee >= <PrivateStaking as BoundActions<AccountId>>::min_fee(asset()).unwrap());
			assert_ok!(bound_exit(supply() - rest - fee, fee));
			let author = pallet_authorship::Pallet::<Runtime>::author().unwrap();
			assert_eq!(
				PendingFees::<Runtime>::get(&author, asset()),
				fee,
				"the fee waits until it can be redeemed"
			);
			assert_solvent();
		});
	}

	#[test]
	fn the_last_holder_leaves_paying_the_minimum_fee() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			let all = supply();
			let worth = PrivateStaking::value_of(POOL, &Pools::<Runtime>::get(POOL).unwrap(), all);
			let fee = <PrivateStaking as BoundActions<AccountId>>::min_fee(asset()).unwrap();
			assert_ok!(bound_exit(all - fee, fee));
			assert_eq!(
				PrivateStaking::member_points(POOL),
				0,
				"all of m_P unbonded"
			);
			let unlock = active_era() + crate::staking::params::NOMINATOR_UNBOND_DURATION;
			assert!(Exits::<Runtime>::get(POOL, (unlock, 0))[0].value + 1 >= worth);
			// Its fee shares are worth nothing now: retired, not left pending.
			let author = pallet_authorship::Pallet::<Runtime>::author().unwrap();
			assert_eq!(PendingFees::<Runtime>::get(&author, asset()), 0);
			assert_eq!((supply(), ledger(asset())), (0, 0));
		});
	}

	#[test]
	fn the_last_holder_takes_the_dust_and_the_author_only_its_fee() {
		with_private_pool(|| {
			let era = active_era();
			spend_into(enter(1), 100 * ORB);
			settle_era(era + 2);
			let net = PrivateStaking::net_value(POOL);
			assert!(net > supply(), "a price above one leaves offset dust");
			let fee = shares_for(5 * ORB);
			let fee_worth =
				PrivateStaking::value_of(POOL, &Pools::<Runtime>::get(POOL).unwrap(), fee);
			assert_ok!(bound_exit(supply() - fee, fee));
			let unlock = active_era() + crate::staking::params::NOMINATOR_UNBOND_DURATION;
			let paid = Exits::<Runtime>::get(POOL, (unlock, 0))[0].value;
			assert!(paid + 1 >= net - fee_worth, "{paid} < {net} - {fee_worth}");
			let redeemed = FeeExits::<Runtime>::get(POOL, (unlock, 0))[0].value;
			assert!(redeemed <= fee_worth + 1, "{redeemed} > {fee_worth}");
			assert_eq!((supply(), ledger(asset())), (0, 0));
		});
	}

	#[test]
	fn below_a_price_of_one_shares_are_worth_their_pro_rata_part() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			// Half the value of every pool point lost, as a slash would.
			pallet_nomination_pools::BondedPools::<Runtime>::mutate(POOL, |pool| {
				let pool = pool.as_mut().unwrap();
				pool.points = pool.points.saturating_mul(2);
			});
			let (net, all) = (PrivateStaking::net_value(POOL), supply());
			assert!(net < all, "price below one");
			let half = all / 2;
			let worth = PrivateStaking::value_of(POOL, &Pools::<Runtime>::get(POOL).unwrap(), half);
			let pro_rata = sp_runtime::helpers_128bit::multiply_by_rational_with_rounding(
				half,
				net,
				all,
				sp_runtime::Rounding::Down,
			)
			.unwrap();
			assert_eq!(worth, pro_rata);
			// An exit asking for exactly that is paid at least that.
			let exit = Action::Exit {
				pool_id: POOL,
				owner_pk: key(5),
				blinding: key(6),
				min_value: worth,
			};
			spend_out(exit, half);
			let unlock = active_era() + crate::staking::params::NOMINATOR_UNBOND_DURATION;
			assert!(Exits::<Runtime>::get(POOL, (unlock, 0))[0].value >= worth);
			assert_solvent();
		});
	}

	#[test]
	fn a_chilled_pool_lets_exits_go_under_the_nominator_minimum() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			// Any exit now leaves the pool's bond under the nominator minimum.
			pallet_staking_async::MinNominatorBond::<Runtime>::put(10_000 * ORB);
			let shares = supply() / 2;
			let check = || {
				<PrivateStaking as BoundActions<AccountId>>::validate(&exit(5), asset(), shares, 0)
			};
			assert_noop!(check(), private::Error::<Runtime>::RemainderBelowMinimum);
			assert_ok!(NominationPools::chill(signed(&depositor()), POOL));
			assert_ok!(check());
		});
	}

	#[test]
	fn a_wound_down_private_side_is_forgotten_before_it_opens_again() {
		with_private_pool(|| {
			Pools::<Runtime>::mutate(POOL, |private| {
				private.as_mut().unwrap().wind_down = Some(private::WindDown {
					value: 0,
					liquid: 0,
					unlock_era: active_era(),
					withdrawn: true,
				});
			});
			assert_noop!(
				PrivateStaking::set_private(signed(&depositor()), POOL, true),
				private::Error::<Runtime>::PoolNotOpen
			);
			// Nothing left: forgotten while the pool itself stays.
			run_blocks(2);
			assert!(Pools::<Runtime>::get(POOL).is_none());
			assert!(pallet_nomination_pools::BondedPools::<Runtime>::contains_key(POOL));
			assert_ok!(PrivateStaking::set_private(
				signed(&depositor()),
				POOL,
				true
			));
			assert!(Pools::<Runtime>::get(POOL).unwrap().wind_down.is_none());
		});
	}

	#[test]
	fn a_pool_slashed_past_its_points_ratio_takes_no_entry() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			pallet_nomination_pools::BondedPools::<Runtime>::mutate(POOL, |pool| {
				let pool = pool.as_mut().unwrap();
				pool.points = pool.points.saturating_mul(100);
			});
			assert_noop!(
				<PrivateStaking as BoundActions<AccountId>>::validate(
					&enter(3),
					NATIVE_ASSET_ID,
					100 * ORB,
					0
				),
				private::Error::<Runtime>::PoolSlashed
			);
		});
	}

	#[test]
	fn the_entry_minimum_is_never_below_the_join_minimum() {
		with_private_pool(|| {
			assert_noop!(
				PrivateStaking::set_min_entry(RuntimeOrigin::root(), 0),
				private::Error::<Runtime>::BelowMinimum
			);
			assert_ok!(PrivateStaking::set_min_entry(
				RuntimeOrigin::root(),
				20 * ORB
			));
			assert_eq!(private::MinEntry::<Runtime>::get(), 20 * ORB);
		});
	}

	#[test]
	fn while_payouts_are_paused_entries_wait() {
		with_private_pool(|| {
			assert_ok!(AutoPayout::pause(RuntimeOrigin::root()));
			let era = active_era();
			spend_into(enter(1), 100 * ORB);
			settle_era(era + 1);
			assert!(
				settled_entries().is_empty(),
				"nothing is known paid while paused"
			);
			assert_ok!(AutoPayout::resume(RuntimeOrigin::root()));
			settle_era(era + 2);
			assert_eq!(settled_entries().len(), 1);
		});
	}

	#[test]
	fn a_fee_paid_in_shares_is_redeemed_for_the_author_at_once() {
		with_private_pool(|| {
			spend_into(enter(1), 100 * ORB);
			settle_era(active_era() + 1);
			let asset_id = asset();
			let author = pallet_authorship::Pallet::<Runtime>::author().expect("an author");
			let (before_supply, before_ledger) = (supply(), ledger(asset_id));
			let fee = supply() / 100;
			assert_ok!(
				pallet_shielded_pool::operations::fees::credit_fee::<Runtime>(asset_id, fee)
			);
			assert_eq!(PendingFees::<Runtime>::get(&author, asset_id), 0);
			assert_eq!(supply(), before_supply - fee);
			assert_eq!(ledger(asset_id), before_ledger - fee);
			let unlock = active_era() + crate::staking::params::NOMINATOR_UNBOND_DURATION;
			let queued = FeeExits::<Runtime>::get(POOL, (unlock, 0));
			assert_eq!(queued.len(), 1);
			assert_eq!(queued[0].validator, author);
			assert_solvent();
		});
	}

	#[test]
	fn the_router_hands_an_asset_only_to_the_pallet_that_issues_it() {
		with_private_pool(|| {
			use pallet_shielded_pool::BoundActions as _;
			type Router = crate::configs::privacy::BoundRouter;
			assert!(Router::min_fee(asset()).is_some());
			// The native asset, and an asset of no pallet, have no pallet floor.
			assert!(Router::min_fee(NATIVE_ASSET_ID).is_none());
			assert!(Router::min_fee(9_999).is_none());
			assert!(Router::redeem_fees(&depositor(), NATIVE_ASSET_ID, 1).is_err());
		});
	}
}

/// What a 10 ORB holder's shares are worth before and after `whale` ORB enters and
/// settles: the same eras pass either way.
fn holder_value_across_an_entry(whale: Balance) -> (u128, u128) {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 10 * ORB);
		settle_era(era + 3);
		let first = settled_entries()[0];
		let private = Pools::<Runtime>::get(POOL).unwrap();
		let before = PrivateStaking::value_of(POOL, &private, first);

		let entered = active_era();
		if whale > 0 {
			spend_into(enter(3), whale);
		}
		settle_era(entered + 2);
		let private = Pools::<Runtime>::get(POOL).unwrap();
		(before, PrivateStaking::value_of(POOL, &private, first))
	})
}

#[test]
fn a_pending_entry_s_rewards_do_not_go_to_the_shares_already_minted() {
	let (before_alone, after_alone) = holder_value_across_an_entry(0);
	let (before, after) = holder_value_across_an_entry(1_000 * ORB);
	let alone = after_alone - before_alone;
	let with_whale = after - before;
	// More stake behind the validator lowers every point's reward, so the holder may
	// earn less; it must never earn more off the pending entry's points.
	assert!(
		with_whale <= alone + alone / 100 + MILLI,
		"the holder earned {with_whale} with an entry pending, {alone} without"
	);
}

#[test]
fn events_name_the_entry_s_key_and_compounding_prices_the_share() {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 100 * ORB);
		settle_era(era + 3);
		let first = settled_entries()[0];
		spend_out(exit(5), first / 2);

		let events = seen();
		let entered = events.iter().find_map(|e| match e {
			private::Event::Entered { owner_pk, .. } => Some(*owner_pk),
			_ => None,
		});
		assert_eq!(entered, Some(key(1)), "the entry names its output key");
		let settled = events.iter().find_map(|e| match e {
			private::Event::EntrySettled { owner_pk, .. } => Some(*owner_pk),
			_ => None,
		});
		assert_eq!(settled, Some(key(1)), "its shares name the same key");
		let exited = events.iter().find_map(|e| match e {
			private::Event::Exited { owner_pk, .. } => Some(*owner_pk),
			_ => None,
		});
		assert_eq!(exited, Some(key(5)));

		// The last compounding prices the shares as `value_of` does.
		let (value, supply) = events
			.iter()
			.rev()
			.find_map(|e| match e {
				private::Event::Compounded { value, supply, .. } => Some((*value, *supply)),
				_ => None,
			})
			.expect("compounded");
		assert_eq!(supply, first, "one entry minted, nothing exited before it");
		let private = Pools::<Runtime>::get(POOL).unwrap();
		assert!(value > 0);
		assert!(PrivateStaking::value_of(POOL, &private, first) > 0);
	});
}

#[test]
fn a_refund_names_the_entry_s_key_and_its_orb_is_paid_to_it() {
	with_private_pool(|| {
		let era = active_era();
		spend_into(enter(1), 100 * ORB);
		settle_era(era + 3);
		// Asks for far more shares than its ORB can buy: refunded when it settles.
		let entered = active_era();
		spend_into(
			Action::Enter {
				pool_id: POOL,
				owner_pk: key(7),
				blinding: key(8),
				min_shares: 1_000_000 * ORB,
			},
			50 * ORB,
		);
		settle_era(entered + 1);
		let refunded = seen().into_iter().find_map(|e| match e {
			private::Event::EntryRefunded { owner_pk, .. } => Some(owner_pk),
			_ => None,
		});
		assert_eq!(refunded, Some(key(7)));

		settle_era(entered + 6);
		let paid = seen().into_iter().find_map(|e| match e {
			private::Event::ExitSettled {
				owner_pk, value, ..
			} if owner_pk == key(7) => Some(value),
			_ => None,
		});
		assert!(
			paid.is_some_and(|v| v > 0),
			"the refund is paid to the entry's key: {paid:?}"
		);
	});
}

/// Queues an entry as spec 23 left one: its ORB bonded at once, its points pending.
fn bonded_entry(n: u8, value: Balance, min_shares: u128) {
	let before = PrivateStaking::member_points(POOL);
	Balances::mint_into(&m_p(), value).expect("m_P funded");
	if before == 0 {
		assert_ok!(NominationPools::join(signed(&m_p()), value, POOL));
	} else {
		assert_ok!(NominationPools::bond_extra(
			signed(&m_p()),
			pallet_nomination_pools::BondExtra::FreeBalance(value)
		));
	}
	let points = PrivateStaking::member_points(POOL) - before;
	EntryPoints::<Runtime>::mutate(POOL, |p| *p += points);
	Entries::<Runtime>::try_mutate(POOL, (active_era(), 0), |queue| {
		queue.try_push(private::Entry {
			points,
			value,
			min_shares,
			owner_pk: key(n),
			blinding: key(n + 1),
		})
	})
	.expect("room in the queue");
}

#[test]
fn entries_bonded_before_spec_24_settle_on_their_points() {
	with_private_pool(|| {
		let era = active_era();
		bonded_entry(1, 100 * ORB, 0);
		bonded_entry(5, 40 * ORB, u128::MAX);
		settle_era(era + 1);

		// The first is minted on its points, as before.
		let minted = settled_entries();
		assert_eq!(minted.len(), 1);
		let private = Pools::<Runtime>::get(POOL).unwrap();
		let worth = PrivateStaking::value_of(POOL, &private, minted[0]);
		assert!(worth >= 100 * ORB - 1, "{worth}");
		assert_eq!(EntryPoints::<Runtime>::get(POOL), 0);
		// The second is refunded through an unbonding, as before: not at once.
		let unlock = seen().into_iter().find_map(|event| match event {
			private::Event::EntryRefunded { unlock_era, .. } => Some(unlock_era),
			_ => None,
		});
		assert!(unlock.is_some_and(|u| u > era + 1), "{unlock:?}");
		assert!(settled_exits().is_empty(), "paid once it unlocks");
		settle_era(unlock.unwrap());
		assert!(settled_exits().iter().any(|v| *v >= 40 * ORB - MILLI));
		assert_solvent();
	});
}
