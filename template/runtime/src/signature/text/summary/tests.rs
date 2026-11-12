// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Each call family's lines, the expiry and tip lines, and what is signable.

use super::{render, signable, MAX_LISTED_ACCOUNTS};
use crate::{
	signature::text::format::{fingerprint, hex},
	test_utils::{shield, signed_extra, signed_extra_with_era, transfer, BOB, ORB},
	AccountId, BalancesCall, Runtime, RuntimeCall, SignedExtra,
};
use pallet_nomination_pools::{BondExtra, ClaimPermission, ConfigOp, PoolState};
use pallet_staking_async::RewardDestination;
use scale_codec::Encode;
use sp_runtime::generic::Era;

fn extra(tip: u128) -> SignedExtra {
	signed_extra(0, tip)
}

fn extra_with_era(tip: u128, era: Era) -> SignedExtra {
	signed_extra_with_era(0, tip, era)
}

/// The call and its extension: the part of a payload `render` reads.
fn rendered_with(call: RuntimeCall, extra: SignedExtra) -> String {
	let mut out = Vec::new();
	render(&mut out, &[call.encode(), extra.encode()].concat());
	String::from_utf8(out).unwrap()
}

/// [`rendered_with`] an immortal extension at nonce 0, without its `expires: never` and
/// `nonce: 0` lines.
fn rendered(call: RuntimeCall, tip: u128) -> String {
	let text = rendered_with(call, extra(tip));
	assert_eq!(text.matches(NEVER).count(), 1, "{text}");
	text.replacen(NEVER, "", 1)
}

const NEVER: &str = "\nexpires: never\nnonce: 0";

fn fp(bytes: &[u8; 32]) -> String {
	String::from_utf8(fingerprint(bytes)).unwrap()
}

fn shielded(call: pallet_shielded_pool::Call<Runtime>) -> RuntimeCall {
	RuntimeCall::ShieldedPool(call)
}

#[test]
fn a_transfer_shows_its_recipient_and_amount() {
	let to = String::from_utf8(hex(&BOB)).unwrap();
	assert_eq!(
		rendered(transfer(3 * ORB / 2), 0),
		format!("Balances.transfer_keep_alive\nto: {to}\namount: 1.5 ORB")
	);
	let allow_death = RuntimeCall::Balances(BalancesCall::transfer_allow_death {
		dest: AccountId::from(BOB),
		value: 1,
	});
	assert_eq!(
		rendered(allow_death, 0),
		format!("Balances.transfer_allow_death\nto: {to}\namount: 0.000000000000000001 ORB")
	);
}

#[test]
fn transfer_all_shows_all_and_whether_it_keeps_the_account_alive() {
	let transfer_all = |keep_alive| {
		RuntimeCall::Balances(BalancesCall::transfer_all {
			dest: AccountId::from(BOB),
			keep_alive,
		})
	};
	assert!(rendered(transfer_all(true), 0).ends_with("\namount: all\nkeep alive: yes"));
	assert!(rendered(transfer_all(false), 0).ends_with("\namount: all\nkeep alive: no"));
}

#[test]
fn orb_shields_show_their_amount_commitment_and_memo() {
	let memo = sp_io::hashing::blake2_256(&[0x3e; 180]);
	assert_eq!(
		rendered(shield(0, 2 * ORB), 0),
		format!(
			"ShieldedPool.shield\namount: 2 ORB\ncommitment: {}\nmemo: {}",
			fp(&[0x1c; 32]),
			fp(&memo)
		)
	);
	assert!(
		rendered(shield(0, ORB), 0).contains("\ncommitment: 0x1c1c1c1c1c1c1c1c…1c1c1c1c1c1c1c1c\n")
	);
}

#[test]
fn fee_claims_show_their_amount() {
	let claim = shielded(pallet_shielded_pool::Call::claim_fees {
		asset_id: 0,
		amount: ORB / 4,
	});
	assert_eq!(
		rendered(claim, 0),
		"ShieldedPool.claim_fees\namount: 0.25 ORB"
	);
}

#[test]
fn other_assets_show_no_amount() {
	assert_eq!(rendered(shield(7, 5), 0), "ShieldedPool.shield");
	let claim = shielded(pallet_shielded_pool::Call::claim_fees {
		asset_id: 7,
		amount: 5,
	});
	assert_eq!(rendered(claim, 0), "ShieldedPool.claim_fees");
}

fn staking(call: pallet_staking_async::Call<Runtime>) -> RuntimeCall {
	RuntimeCall::Staking(call)
}

#[test]
fn a_bond_shows_its_amount_and_where_rewards_go() {
	let bond = |payee| {
		staking(pallet_staking_async::Call::bond {
			value: 10 * ORB,
			payee,
		})
	};
	assert_eq!(
		rendered(bond(RewardDestination::Staked), 0),
		"Staking.bond\namount: 10 ORB\nrewards to: staked"
	);
	assert!(rendered(bond(RewardDestination::Stash), 0).ends_with("rewards to: stash"));
	assert!(rendered(bond(RewardDestination::None), 0).ends_with("rewards to: none"));
	let to = String::from_utf8(hex(&BOB)).unwrap();
	assert!(
		rendered(bond(RewardDestination::Account(AccountId::from(BOB))), 0)
			.ends_with(&format!("rewards to: {to}"))
	);
}

#[test]
fn bond_changes_show_their_amount() {
	let calls = [
		(
			"bond_extra",
			staking(pallet_staking_async::Call::bond_extra {
				max_additional: ORB,
			}),
		),
		(
			"unbond",
			staking(pallet_staking_async::Call::unbond { value: ORB }),
		),
		(
			"rebond",
			staking(pallet_staking_async::Call::rebond { value: ORB }),
		),
	];
	for (name, call) in calls {
		assert_eq!(rendered(call, 0), format!("Staking.{name}\namount: 1 ORB"));
	}
}

#[test]
fn set_payee_shows_where_rewards_go() {
	let to = String::from_utf8(hex(&BOB)).unwrap();
	let call = staking(pallet_staking_async::Call::set_payee {
		payee: RewardDestination::Account(AccountId::from(BOB)),
	});
	assert_eq!(
		rendered(call, 0),
		format!("Staking.set_payee\nrewards to: {to}")
	);
}

#[test]
fn nominate_shows_every_target() {
	let (a, b) = ([0xa1; 32], [0xb2; 32]);
	let call = staking(pallet_staking_async::Call::nominate {
		targets: vec![AccountId::from(a), AccountId::from(b)],
	});
	let (a, b) = (
		String::from_utf8(hex(&a)).unwrap(),
		String::from_utf8(hex(&b)).unwrap(),
	);
	assert_eq!(
		rendered(call, 0),
		format!("Staking.nominate\nvalidator: {a}\nvalidator: {b}")
	);
}

#[test]
fn validate_shows_the_commission_and_a_block() {
	let validate = |percent: u32, blocked| {
		staking(pallet_staking_async::Call::validate {
			prefs: pallet_staking_async::ValidatorPrefs {
				commission: sp_runtime::Perbill::from_parts(percent),
				blocked,
			},
		})
	};
	assert_eq!(
		rendered(validate(125_000_000, false), 0),
		"Staking.validate\ncommission: 12.5%"
	);
	assert_eq!(
		rendered(validate(0, true), 0),
		"Staking.validate\ncommission: 0%\nblocked: yes"
	);
}

#[test]
fn payouts_show_the_validator_era_and_page() {
	let to = String::from_utf8(hex(&BOB)).unwrap();
	let call = staking(pallet_staking_async::Call::payout_stakers {
		validator_stash: AccountId::from(BOB),
		era: 42,
	});
	assert_eq!(
		rendered(call, 0),
		format!("Staking.payout_stakers\nvalidator: {to}\nera: 42")
	);
	let by_page = staking(pallet_staking_async::Call::payout_stakers_by_page {
		validator_stash: AccountId::from(BOB),
		era: 42,
		page: 3,
	});
	assert!(signs(by_page.clone()));
	assert_eq!(
		rendered(by_page, 0),
		format!("Staking.payout_stakers_by_page\nvalidator: {to}\nera: 42\npage: 3")
	);
}

fn pools(call: pallet_nomination_pools::Call<Runtime>) -> RuntimeCall {
	RuntimeCall::NominationPools(call)
}

#[test]
fn pool_member_calls_show_the_pool_amount_and_member() {
	use pallet_nomination_pools::Call;
	let bob = String::from_utf8(hex(&BOB)).unwrap();
	let cases = [
		(
			Call::join {
				amount: 5 * ORB,
				pool_id: 7,
			},
			"NominationPools.join\npool: 7\namount: 5 ORB".to_string(),
		),
		(
			Call::bond_extra {
				extra: BondExtra::FreeBalance(ORB / 2),
			},
			"NominationPools.bond_extra\namount: 0.5 ORB".to_string(),
		),
		(
			Call::bond_extra {
				extra: BondExtra::Rewards,
			},
			"NominationPools.bond_extra\namount: rewards".to_string(),
		),
		(
			Call::bond_extra_other {
				member: AccountId::from(BOB),
				extra: BondExtra::Rewards,
			},
			format!("NominationPools.bond_extra_other\nmember: {bob}\namount: rewards"),
		),
		(
			Call::claim_payout {},
			"NominationPools.claim_payout".to_string(),
		),
		(
			Call::claim_payout_other {
				other: AccountId::from(BOB),
			},
			format!("NominationPools.claim_payout_other\nmember: {bob}"),
		),
		(
			Call::unbond {
				member_account: AccountId::from(BOB),
				unbonding_points: 3 * ORB / 2,
			},
			format!("NominationPools.unbond\nmember: {bob}\npoints: 1.5"),
		),
		(
			Call::withdraw_unbonded {
				member_account: AccountId::from(BOB),
				num_slashing_spans: 0,
			},
			format!("NominationPools.withdraw_unbonded\nmember: {bob}"),
		),
		(
			Call::set_claim_permission {
				permission: ClaimPermission::PermissionlessCompound,
			},
			"NominationPools.set_claim_permission\npermission: permissionless compound".to_string(),
		),
	];
	for (call, text) in cases {
		let call = pools(call);
		assert!(signs(call.clone()), "{text}");
		assert_eq!(rendered(call, 0), text);
	}
}

#[test]
fn pool_operator_calls_show_the_pool_and_its_roles() {
	use pallet_nomination_pools::Call;
	let (a, b) = ([0xa1; 32], [0xb2; 32]);
	let [bob, a_hex, b_hex] = [BOB, a, b].map(|k| String::from_utf8(hex(&k)).unwrap());
	let cases = [
		(
			Call::create {
				amount: 100 * ORB,
				root: AccountId::from(BOB),
				nominator: AccountId::from(a),
				bouncer: AccountId::from(b),
			},
			format!(
				"NominationPools.create\namount: 100 ORB\nroot: {bob}\nnominator: \
				 {a_hex}\nbouncer: {b_hex}"
			),
		),
		(
			Call::nominate {
				pool_id: 3,
				validators: vec![AccountId::from(a), AccountId::from(b)],
			},
			format!("NominationPools.nominate\npool: 3\nvalidator: {a_hex}\nvalidator: {b_hex}"),
		),
		(
			Call::chill { pool_id: 3 },
			"NominationPools.chill\npool: 3".to_string(),
		),
		(
			Call::pool_withdraw_unbonded {
				pool_id: 3,
				num_slashing_spans: 0,
			},
			"NominationPools.pool_withdraw_unbonded\npool: 3".to_string(),
		),
		(
			Call::set_state {
				pool_id: 3,
				state: PoolState::Destroying,
			},
			"NominationPools.set_state\npool: 3\nstate: destroying".to_string(),
		),
		(
			Call::update_roles {
				pool_id: 3,
				new_root: ConfigOp::Noop,
				new_nominator: ConfigOp::Set(AccountId::from(a)),
				new_bouncer: ConfigOp::Remove,
			},
			format!("NominationPools.update_roles\npool: 3\nroot: keep\nnominator: {a_hex}\nbouncer: remove"),
		),
		(
			Call::update_roles {
				pool_id: 3,
				new_root: ConfigOp::Set(AccountId::from(BOB)),
				new_nominator: ConfigOp::Noop,
				new_bouncer: ConfigOp::Noop,
			},
			format!("NominationPools.update_roles\npool: 3\nroot: {bob}\nnominator: keep\nbouncer: keep"),
		),
	];
	for (call, text) in cases {
		let call = pools(call);
		assert!(signs(call.clone()), "{text}");
		assert_eq!(rendered(call, 0), text);
	}
}

/// Every commission parameter is on its own line: the rate, its payee (who receives every
/// later claim), the cap, the change rate and who may claim.
#[test]
fn pool_commission_calls_show_every_parameter() {
	use pallet_nomination_pools::{Call, CommissionChangeRate, CommissionClaimPermission};
	use sp_runtime::Perbill;
	let bob = String::from_utf8(hex(&BOB)).unwrap();
	let cases = [
		(
			Call::set_commission {
				pool_id: 3,
				new_commission: Some((Perbill::from_parts(125_000_000), AccountId::from(BOB))),
			},
			format!("NominationPools.set_commission\npool: 3\ncommission: 12.5%\npayee: {bob}"),
		),
		(
			Call::set_commission {
				pool_id: 3,
				new_commission: Some((Perbill::zero(), AccountId::from(BOB))),
			},
			format!("NominationPools.set_commission\npool: 3\ncommission: 0%\npayee: {bob}"),
		),
		(
			Call::set_commission {
				pool_id: 3,
				new_commission: None,
			},
			"NominationPools.set_commission\npool: 3\ncommission: none".to_string(),
		),
		(
			Call::set_commission_max {
				pool_id: 3,
				max_commission: Perbill::from_percent(20),
			},
			"NominationPools.set_commission_max\npool: 3\nmax commission: 20%".to_string(),
		),
		(
			Call::set_commission_change_rate {
				pool_id: 3,
				change_rate: CommissionChangeRate {
					max_increase: Perbill::from_parts(5_000_000),
					min_delay: 600,
				},
			},
			"NominationPools.set_commission_change_rate\npool: 3\nmax increase: 0.5%\nmin \
			 delay: 600 blocks"
				.to_string(),
		),
		(
			Call::claim_commission { pool_id: 3 },
			"NominationPools.claim_commission\npool: 3".to_string(),
		),
		(
			Call::set_commission_claim_permission {
				pool_id: 3,
				permission: Some(CommissionClaimPermission::Permissionless),
			},
			"NominationPools.set_commission_claim_permission\npool: 3\npermission: permissionless"
				.to_string(),
		),
		(
			Call::set_commission_claim_permission {
				pool_id: 3,
				permission: Some(CommissionClaimPermission::Account(AccountId::from(BOB))),
			},
			format!("NominationPools.set_commission_claim_permission\npool: 3\npermission: {bob}"),
		),
		(
			Call::set_commission_claim_permission {
				pool_id: 3,
				permission: None,
			},
			"NominationPools.set_commission_claim_permission\npool: 3\npermission: root only"
				.to_string(),
		),
	];
	for (call, text) in cases {
		let call = pools(call);
		assert!(signs(call.clone()), "{text}");
		assert_eq!(rendered(call, 0), text);
	}
}

/// Two commission calls that differ in any parameter render different texts, so no
/// text signs both.
#[test]
fn pool_commission_texts_tell_their_parameters_apart() {
	use pallet_nomination_pools::{Call, CommissionChangeRate, CommissionClaimPermission};
	use sp_runtime::Perbill;
	let rate = |max_increase, min_delay| CommissionChangeRate {
		max_increase: Perbill::from_parts(max_increase),
		min_delay,
	};
	let calls = [
		Call::set_commission {
			pool_id: 1,
			new_commission: Some((Perbill::from_percent(5), AccountId::from(BOB))),
		},
		Call::set_commission {
			pool_id: 2,
			new_commission: Some((Perbill::from_percent(5), AccountId::from(BOB))),
		},
		Call::set_commission {
			pool_id: 1,
			new_commission: Some((Perbill::from_parts(50_000_001), AccountId::from(BOB))),
		},
		Call::set_commission {
			pool_id: 1,
			new_commission: Some((Perbill::from_percent(5), AccountId::from([0xa1; 32]))),
		},
		Call::set_commission {
			pool_id: 1,
			new_commission: None,
		},
		Call::set_commission_max {
			pool_id: 1,
			max_commission: Perbill::from_percent(5),
		},
		Call::set_commission_max {
			pool_id: 1,
			max_commission: Perbill::from_percent(6),
		},
		Call::set_commission_change_rate {
			pool_id: 1,
			change_rate: rate(10_000_000, 10),
		},
		Call::set_commission_change_rate {
			pool_id: 1,
			change_rate: rate(10_000_001, 10),
		},
		Call::set_commission_change_rate {
			pool_id: 1,
			change_rate: rate(10_000_000, 11),
		},
		Call::claim_commission { pool_id: 1 },
		Call::claim_commission { pool_id: 2 },
		Call::set_commission_claim_permission {
			pool_id: 1,
			permission: None,
		},
		Call::set_commission_claim_permission {
			pool_id: 1,
			permission: Some(CommissionClaimPermission::Permissionless),
		},
		Call::set_commission_claim_permission {
			pool_id: 1,
			permission: Some(CommissionClaimPermission::Account(AccountId::from(BOB))),
		},
		Call::set_commission_claim_permission {
			pool_id: 1,
			permission: Some(CommissionClaimPermission::Account(AccountId::from(
				[0xa1; 32],
			))),
		},
	];
	let texts: std::collections::BTreeSet<_> = calls
		.into_iter()
		.map(|call| rendered(pools(call), 0))
		.collect();
	assert_eq!(texts.len(), 16);
}

#[test]
fn pool_calls_that_hide_value_or_authority_are_not_signable() {
	use pallet_nomination_pools::Call;
	let too_many = Call::nominate {
		pool_id: 1,
		validators: (0..=MAX_LISTED_ACCOUNTS)
			.map(|i| AccountId::from([i as u8; 32]))
			.collect(),
	};
	assert!(!signs(pools(too_many)));
	let metadata = Call::set_metadata {
		pool_id: 1,
		metadata: vec![1, 2],
	};
	assert!(!signs(pools(metadata)));
}

fn signs(call: RuntimeCall) -> bool {
	signable(&[call.encode(), extra(0).encode()].concat())
}

#[test]
fn only_calls_that_show_their_parameters_are_signable() {
	assert!(signs(transfer(ORB)));
	assert!(signs(shield(0, ORB)));
	assert!(signs(staking(pallet_staking_async::Call::chill {})));
	assert!(signs(RuntimeCall::System(frame_system::Call::remark {
		remark: vec![1]
	})));
	// Value moves, but the text would not show how much or to whom.
	let burn = RuntimeCall::Balances(BalancesCall::burn {
		value: ORB,
		keep_alive: false,
	});
	assert!(!signs(burn));
	assert!(!signs(shield(7, 5)));
	let remark_event =
		RuntimeCall::System(frame_system::Call::remark_with_event { remark: vec![1] });
	assert!(!signs(remark_event));
	let mut bytes = Vec::new();
	bytes.extend_from_slice(&[0xff; 40]);
	assert!(!signable(&bytes));
}

#[test]
fn account_lists_are_signable_up_to_the_nomination_limit() {
	let targets = |n: usize| (0..n).map(|i| AccountId::from([i as u8; 32])).collect();
	let nominate = |n| {
		staking(pallet_staking_async::Call::nominate {
			targets: targets(n),
		})
	};
	assert!(signs(nominate(MAX_LISTED_ACCOUNTS)));
	assert!(!signs(nominate(MAX_LISTED_ACCOUNTS + 1)));
	let kick = |n| staking(pallet_staking_async::Call::kick { who: targets(n) });
	assert!(signs(kick(1)));
	assert!(!signs(kick(MAX_LISTED_ACCOUNTS + 1)));
	// `[0; 32]` ends in the EVM marker: shown as the 20-byte address.
	assert!(rendered(kick(1), 0).ends_with(&format!(
		"nominator: {}",
		String::from_utf8(hex(&[0u8; 20])).unwrap()
	)));
}

/// An EVM account (`[address | 0x00×12]`) is shown as its 20-byte address, the
/// way its owner knows it; an account sharing those 20 bytes but not the
/// marker is shown in full, so the two never look alike.
#[test]
fn evm_accounts_show_their_address() {
	let address = [0xd4; 20];
	let evm = AccountId::from(crate::evm_h160_to_account_id_bytes(sp_core::H160(address)));
	let mut near = crate::evm_h160_to_account_id_bytes(sp_core::H160(address));
	near[31] = 1;
	let to = |dest: AccountId| {
		rendered(
			RuntimeCall::Balances(BalancesCall::transfer_allow_death { dest, value: 1 }),
			0,
		)
	};
	let shown = String::from_utf8(hex(&address)).unwrap();
	assert!(to(evm.clone()).contains(&format!("\nto: {shown}\n")));
	let full = String::from_utf8(hex(&near)).unwrap();
	assert!(to(AccountId::from(near)).contains(&format!("\nto: {full}\n")));
	assert_eq!((shown.len(), full.len()), (42, 66));
	let bond = staking(pallet_staking_async::Call::bond {
		value: ORB,
		payee: RewardDestination::Account(evm),
	});
	assert!(rendered(bond, 0).ends_with(&format!("rewards to: {shown}")));
}

#[test]
fn set_keys_shows_the_keys_registered() {
	let call = RuntimeCall::Session(pallet_session::Call::set_keys {
		keys: crate::opaque::SessionKeys {
			aura: sp_consensus_aura::sr25519::AuthorityId::from(
				sp_core::sr25519::Public::from_raw([0xa1; 32]),
			),
			grandpa: sp_consensus_grandpa::AuthorityId::from(sp_core::ed25519::Public::from_raw(
				[0x9a; 32],
			)),
		},
		proof: vec![1, 2, 3],
	});
	assert!(signs(call.clone()));
	let (aura, grandpa) = (
		String::from_utf8(hex(&[0xa1; 32])).unwrap(),
		String::from_utf8(hex(&[0x9a; 32])).unwrap(),
	);
	assert_eq!(
		rendered(call, 0),
		format!("Session.set_keys\naura key: {aura}\ngrandpa key: {grandpa}")
	);
}

#[test]
fn a_remark_shows_its_length_and_fingerprint() {
	let remark = RuntimeCall::System(frame_system::Call::remark { remark: vec![1, 2] });
	assert_eq!(
		rendered(remark, 0),
		format!(
			"System.remark\nlength: 2 bytes\nremark: {}",
			fp(&sp_io::hashing::blake2_256(&[1, 2]))
		)
	);
}

#[test]
fn calls_with_nothing_to_show_show_their_name_only() {
	let purge = RuntimeCall::Session(pallet_session::Call::purge_keys {});
	assert_eq!(rendered(purge, 0), "Session.purge_keys");
}

#[test]
fn the_expiry_follows_the_call_and_precedes_the_tip() {
	let mortal = Era::mortal(64, 1_000);
	assert_eq!(
		rendered_with(transfer(ORB), extra_with_era(0, mortal)),
		format!(
			"Balances.transfer_keep_alive\nto: {}\namount: 1 ORB\nexpires: within 64 blocks\nnonce: 0",
			String::from_utf8(hex(&BOB)).unwrap()
		)
	);
	assert!(rendered_with(transfer(ORB), extra_with_era(ORB, mortal))
		.ends_with("\nexpires: within 64 blocks\nnonce: 0\ntip: 1 ORB"));
	assert!(rendered_with(transfer(ORB), extra(0))
		.ends_with("\namount: 1 ORB\nexpires: never\nnonce: 0"));
}

#[test]
fn the_nonce_follows_the_expiry_mortal_or_not() {
	let mortal = Era::mortal(64, 1_000);
	assert!(
		rendered_with(transfer(ORB), signed_extra_with_era(7, ORB, mortal))
			.ends_with("\nexpires: within 64 blocks\nnonce: 7\ntip: 1 ORB")
	);
	assert!(rendered_with(transfer(ORB), signed_extra(4_294_967_295, 0))
		.ends_with("\nexpires: never\nnonce: 4294967295"));
}

#[test]
fn a_tip_is_the_last_line_when_not_zero() {
	assert!(rendered_with(transfer(ORB), extra(ORB / 100))
		.ends_with("\namount: 1 ORB\nexpires: never\nnonce: 0\ntip: 0.01 ORB"));
	assert!(!rendered(transfer(ORB), 0).contains("tip:"));
}

#[test]
fn bytes_that_are_no_call_show_unknown() {
	let mut out = Vec::new();
	render(&mut out, &[0xff; 40]);
	assert_eq!(out, b"unknown");
}

/// A call without a readable extension still shows; only the expiry, nonce and tip
/// lines are lost.
#[test]
fn a_call_without_its_extension_shows_no_expiry_or_tip() {
	let mut out = Vec::new();
	render(&mut out, &transfer(ORB).encode());
	assert!(String::from_utf8(out).unwrap().ends_with("\namount: 1 ORB"));
}

/// The calls a text signature may authorise, reviewed one by one. A new arm in a
/// renderer, or a new call it matches, fails here until listed.
const SIGNABLE_CALLS: &[&str] = &[
	"Balances.transfer_allow_death",
	"Balances.transfer_keep_alive",
	"Balances.transfer_all",
	"NominationPools.join",
	"NominationPools.bond_extra",
	"NominationPools.claim_payout",
	"NominationPools.unbond",
	"NominationPools.pool_withdraw_unbonded",
	"NominationPools.withdraw_unbonded",
	"NominationPools.create",
	"NominationPools.nominate",
	"NominationPools.set_state",
	"NominationPools.update_roles",
	"NominationPools.bond_extra_other",
	"NominationPools.set_claim_permission",
	"NominationPools.claim_payout_other",
	"NominationPools.set_commission",
	"NominationPools.set_commission_max",
	"NominationPools.set_commission_change_rate",
	"NominationPools.claim_commission",
	"NominationPools.chill",
	"NominationPools.set_commission_claim_permission",
	"Session.set_keys",
	"Session.purge_keys",
	"ShieldedPool.shield",
	"ShieldedPool.claim_fees",
	"Staking.bond",
	"Staking.bond_extra",
	"Staking.unbond",
	"Staking.withdraw_unbonded",
	"Staking.validate",
	"Staking.nominate",
	"Staking.chill",
	"Staking.set_payee",
	"Staking.payout_stakers",
	"Staking.rebond",
	"Staking.kick",
	"Staking.payout_stakers_by_page",
	"System.remark",
	"ValidatorSet.deregister_validator",
];

/// The SCALE encoding of a value of type `id` whose fields are all zero, empty, `None`
/// or the first variant.
fn zero_value(registry: &scale_info::PortableRegistry, id: u32, out: &mut Vec<u8>) {
	use scale_info::{TypeDef, TypeDefPrimitive as P};
	match &registry.resolve(id).expect("type in registry").type_def {
		TypeDef::Composite(c) => c
			.fields
			.iter()
			.for_each(|f| zero_value(registry, f.ty.id, out)),
		TypeDef::Variant(v) => {
			let first = v
				.variants
				.iter()
				.min_by_key(|v| v.index)
				.expect("a variant");
			out.push(first.index);
			first
				.fields
				.iter()
				.for_each(|f| zero_value(registry, f.ty.id, out));
		}
		TypeDef::Array(a) => (0..a.len).for_each(|_| zero_value(registry, a.type_param.id, out)),
		TypeDef::Tuple(t) => t
			.fields
			.iter()
			.for_each(|f| zero_value(registry, f.id, out)),
		TypeDef::Sequence(_) | TypeDef::Compact(_) | TypeDef::BitSequence(_) => out.push(0),
		TypeDef::Primitive(p) => {
			let len = match p {
				P::Bool | P::U8 | P::I8 => 1,
				P::U16 | P::I16 => 2,
				P::Char | P::U32 | P::I32 => 4,
				P::U64 | P::I64 => 8,
				P::U128 | P::I128 => 16,
				P::U256 | P::I256 => 32,
				P::Str => 1,
			};
			out.resize(out.len() + len, 0);
		}
	}
}

/// Pallets `details` renders: every call of theirs must build from zero values.
const RENDERED_PALLETS: &[&str] = &[
	"Balances",
	"NominationPools",
	"Session",
	"ShieldedPool",
	"Staking",
	"System",
	"ValidatorSet",
];

/// One instance of every call of the rendered pallets, all-zero parameters: an ORB
/// amount, asset 0, empty lists. Each call that renders lines is text-signable. Calls of
/// other pallets are tried too where zero values decode (`Ethereum.transact` does not).
#[test]
fn signable_call_set_is_exactly() {
	use scale_info::{form::PortableForm, TypeDef};
	let mut registry = scale_info::Registry::new();
	let call_id = registry
		.register_type(&scale_info::meta_type::<RuntimeCall>())
		.id;
	let registry = scale_info::PortableRegistry::from(registry);
	let variants = |id: u32| -> Vec<scale_info::Variant<PortableForm>> {
		match &registry.resolve(id).unwrap().type_def {
			TypeDef::Variant(v) => v.variants.clone(),
			_ => panic!("type {id} is not an enum"),
		}
	};
	let mut signable_calls = Vec::new();
	for pallet in variants(call_id) {
		let [field] = pallet.fields.as_slice() else {
			panic!("{} wraps more than its call enum", pallet.name)
		};
		for call in variants(field.ty.id) {
			let mut encoded = vec![pallet.index, call.index];
			call.fields
				.iter()
				.for_each(|f| zero_value(&registry, f.ty.id, &mut encoded));
			let name = format!("{}.{}", pallet.name, call.name);
			let decoded = <RuntimeCall as scale_codec::DecodeAll>::decode_all(&mut &encoded[..]);
			if decoded.is_err() {
				let rendered = RENDERED_PALLETS.contains(&pallet.name.as_str());
				assert!(!rendered, "{name} does not decode from zero values");
				continue;
			}
			if signable(&encoded) {
				signable_calls.push(name);
			}
		}
	}
	signable_calls.sort();
	let mut expected: Vec<_> = SIGNABLE_CALLS.iter().map(|c| c.to_string()).collect();
	expected.sort();
	assert_eq!(signable_calls, expected);
}
