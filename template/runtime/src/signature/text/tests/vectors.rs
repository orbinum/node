// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Texts shared with clients (`fixtures/ed25519_text_vectors.json`, copied to
//! ts-protocol's tests): the same payload must render the same text, byte for byte.

use super::*;
use crate::{
	test_utils::{ALITH_ADDRESS, ALITH_KEY},
	BalancesCall, SignedExtraFields,
};

const VECTORS: &str = include_str!("fixtures/ed25519_text_vectors.json");

/// `(name, msg)` for every vector, `msg` being the whole signing payload.
fn vector_messages() -> Vec<(&'static str, Vec<u8>)> {
	let claim = |asset_id, amount| {
		RuntimeCall::ShieldedPool(pallet_shielded_pool::Call::claim_fees { asset_id, amount })
	};
	let staking = |call: pallet_staking_async::Call<Runtime>| {
		payload_with_tip(&RuntimeCall::Staking(call), 0)
	};
	let pools = |call: pallet_nomination_pools::Call<Runtime>| {
		payload_with_tip(&RuntimeCall::NominationPools(call), 0)
	};
	vec![
		(
			"transfer_keep_alive",
			payload_with_tip(&transfer(3 * ORB / 2), 0),
		),
		(
			"transfer_allow_death_one_wei",
			payload_with_tip(
				&RuntimeCall::Balances(BalancesCall::transfer_allow_death {
					dest: AccountId::from(BOB),
					value: 1,
				}),
				0,
			),
		),
		(
			"transfer_all",
			payload_with_tip(
				&RuntimeCall::Balances(BalancesCall::transfer_all {
					dest: AccountId::from(BOB),
					keep_alive: false,
				}),
				0,
			),
		),
		(
			"transfer_all_keep_alive",
			payload_with_tip(
				&RuntimeCall::Balances(BalancesCall::transfer_all {
					dest: AccountId::from(BOB),
					keep_alive: true,
				}),
				0,
			),
		),
		(
			"transfer_with_tip",
			payload_with_tip(&transfer(ORB), ORB / 100),
		),
		(
			"transfer_mortal_with_tip",
			mortal_payload(&transfer(ORB), ORB / 100),
		),
		(
			"transfer_nonce_1000000",
			raw_payload(&transfer(ORB), 1_000_000),
		),
		(
			"transfer_to_evm_account",
			payload_with_tip(
				&RuntimeCall::Balances(BalancesCall::transfer_keep_alive {
					dest: crate::evm_bytes_to_account_id_bytes(ALITH_ADDRESS).into(),
					value: ORB,
				}),
				0,
			),
		),
		(
			"transfer_to_evm_lookalike",
			payload_with_tip(
				&RuntimeCall::Balances(BalancesCall::transfer_keep_alive {
					dest: {
						let mut raw = crate::evm_bytes_to_account_id_bytes(ALITH_ADDRESS);
						raw[31] = 1;
						raw.into()
					},
					value: ORB,
				}),
				0,
			),
		),
		("claim_fees_orb", payload_with_tip(&claim(0, ORB / 4), 0)),
		("claim_fees_other_asset", payload_with_tip(&claim(7, 5), 0)),
		("remark", raw_payload(&remark(20), 0)),
		("remark_over_256_bytes", raw_payload(&remark(300), 0)),
		("shield", payload_with_tip(&shield(0, 2 * ORB), 0)),
		(
			"staking_bond_to_account",
			staking(pallet_staking_async::Call::bond {
				value: 10 * ORB,
				payee: pallet_staking_async::RewardDestination::Account(AccountId::from(BOB)),
			}),
		),
		(
			"staking_bond_staked",
			staking(pallet_staking_async::Call::bond {
				value: 3 * ORB / 2,
				payee: pallet_staking_async::RewardDestination::Staked,
			}),
		),
		(
			"staking_unbond",
			staking(pallet_staking_async::Call::unbond { value: ORB }),
		),
		(
			"staking_set_payee_stash",
			staking(pallet_staking_async::Call::set_payee {
				payee: pallet_staking_async::RewardDestination::Stash,
			}),
		),
		(
			"staking_nominate",
			staking(pallet_staking_async::Call::nominate {
				targets: vec![AccountId::from(BOB), AccountId::from([0xa1; 32])],
			}),
		),
		(
			"staking_validate_blocked",
			staking(pallet_staking_async::Call::validate {
				prefs: pallet_staking_async::ValidatorPrefs {
					commission: sp_runtime::Perbill::from_parts(125_000_000),
					blocked: true,
				},
			}),
		),
		(
			"staking_payout_stakers",
			staking(pallet_staking_async::Call::payout_stakers {
				validator_stash: AccountId::from(BOB),
				era: 42,
			}),
		),
		(
			"staking_payout_stakers_by_page",
			staking(pallet_staking_async::Call::payout_stakers_by_page {
				validator_stash: AccountId::from(BOB),
				era: 42,
				page: 3,
			}),
		),
		(
			"balances_burn",
			payload_with_tip(
				&RuntimeCall::Balances(BalancesCall::burn {
					value: ORB,
					keep_alive: false,
				}),
				0,
			),
		),
		(
			"session_set_keys",
			payload_with_tip(
				&RuntimeCall::Session(pallet_session::Call::set_keys {
					keys: crate::opaque::SessionKeys {
						aura: sp_consensus_aura::sr25519::AuthorityId::from(
							sp_core::sr25519::Public::from_raw([0xa1; 32]),
						),
						grandpa: sp_consensus_grandpa::AuthorityId::from(
							sp_core::ed25519::Public::from_raw([0x9a; 32]),
						),
					},
					proof: vec![0x5a; 128],
				}),
				0,
			),
		),
		(
			"staking_kick",
			staking(pallet_staking_async::Call::kick {
				who: vec![AccountId::from(BOB)],
			}),
		),
		(
			"staking_chill",
			staking(pallet_staking_async::Call::chill {}),
		),
		(
			"staking_nominate_too_many",
			staking(pallet_staking_async::Call::nominate {
				targets: (0..17u8).map(|i| AccountId::from([i; 32])).collect(),
			}),
		),
		(
			"staking_bond_extra",
			staking(pallet_staking_async::Call::bond_extra {
				max_additional: 2 * ORB,
			}),
		),
		(
			"staking_rebond",
			staking(pallet_staking_async::Call::rebond { value: ORB / 4 }),
		),
		(
			"staking_withdraw_unbonded",
			staking(pallet_staking_async::Call::withdraw_unbonded {
				num_slashing_spans: 0,
			}),
		),
		(
			"staking_set_payee_account",
			staking(pallet_staking_async::Call::set_payee {
				payee: pallet_staking_async::RewardDestination::Account(AccountId::from(BOB)),
			}),
		),
		(
			"staking_set_payee_none",
			staking(pallet_staking_async::Call::set_payee {
				payee: pallet_staking_async::RewardDestination::None,
			}),
		),
		(
			"session_purge_keys",
			payload_with_tip(
				&RuntimeCall::Session(pallet_session::Call::purge_keys {}),
				0,
			),
		),
		(
			"validator_set_deregister_validator",
			payload_with_tip(
				&RuntimeCall::ValidatorSet(pallet_validator_set::Call::deregister_validator {}),
				0,
			),
		),
		("not_a_call", vec![0xff; 40]),
		(
			"pools_join",
			pools(pallet_nomination_pools::Call::join {
				amount: 5 * ORB,
				pool_id: 7,
			}),
		),
		(
			"pools_bond_extra",
			pools(pallet_nomination_pools::Call::bond_extra {
				extra: pallet_nomination_pools::BondExtra::FreeBalance(ORB / 2),
			}),
		),
		(
			"pools_bond_extra_rewards",
			pools(pallet_nomination_pools::Call::bond_extra {
				extra: pallet_nomination_pools::BondExtra::Rewards,
			}),
		),
		(
			"pools_bond_extra_other_rewards",
			pools(pallet_nomination_pools::Call::bond_extra_other {
				member: AccountId::from(BOB),
				extra: pallet_nomination_pools::BondExtra::Rewards,
			}),
		),
		(
			"pools_claim_payout",
			pools(pallet_nomination_pools::Call::claim_payout {}),
		),
		(
			"pools_claim_payout_other",
			pools(pallet_nomination_pools::Call::claim_payout_other {
				other: AccountId::from(BOB),
			}),
		),
		(
			"pools_unbond",
			pools(pallet_nomination_pools::Call::unbond {
				member_account: AccountId::from(BOB),
				unbonding_points: 3 * ORB / 2,
			}),
		),
		(
			"pools_withdraw_unbonded",
			pools(pallet_nomination_pools::Call::withdraw_unbonded {
				member_account: AccountId::from(BOB),
				num_slashing_spans: 0,
			}),
		),
		(
			"pools_pool_withdraw_unbonded",
			pools(pallet_nomination_pools::Call::pool_withdraw_unbonded {
				pool_id: 7,
				num_slashing_spans: 0,
			}),
		),
		(
			"pools_create",
			pools(pallet_nomination_pools::Call::create {
				amount: 100 * ORB,
				root: AccountId::from(BOB),
				nominator: AccountId::from([0xa1; 32]),
				bouncer: AccountId::from([0xb2; 32]),
			}),
		),
		(
			"pools_nominate",
			pools(pallet_nomination_pools::Call::nominate {
				pool_id: 7,
				validators: vec![AccountId::from(BOB), AccountId::from([0xa1; 32])],
			}),
		),
		(
			"pools_chill",
			pools(pallet_nomination_pools::Call::chill { pool_id: 7 }),
		),
		(
			"pools_set_state_destroying",
			pools(pallet_nomination_pools::Call::set_state {
				pool_id: 7,
				state: pallet_nomination_pools::PoolState::Destroying,
			}),
		),
		(
			"pools_set_claim_permission",
			pools(pallet_nomination_pools::Call::set_claim_permission {
				permission: pallet_nomination_pools::ClaimPermission::PermissionlessAll,
			}),
		),
		(
			"pools_set_commission",
			pools(pallet_nomination_pools::Call::set_commission {
				pool_id: 7,
				new_commission: Some((sp_runtime::Perbill::from_percent(5), AccountId::from(BOB))),
			}),
		),
		(
			"pools_set_commission_fraction",
			pools(pallet_nomination_pools::Call::set_commission {
				pool_id: 7,
				new_commission: Some((
					sp_runtime::Perbill::from_parts(125_000_001),
					AccountId::from([0xa1; 32]),
				)),
			}),
		),
		(
			"pools_set_commission_none",
			pools(pallet_nomination_pools::Call::set_commission {
				pool_id: 7,
				new_commission: None,
			}),
		),
		(
			"pools_set_commission_max",
			pools(pallet_nomination_pools::Call::set_commission_max {
				pool_id: 7,
				max_commission: sp_runtime::Perbill::from_percent(20),
			}),
		),
		(
			"pools_set_commission_change_rate",
			pools(pallet_nomination_pools::Call::set_commission_change_rate {
				pool_id: 7,
				change_rate: pallet_nomination_pools::CommissionChangeRate {
					max_increase: sp_runtime::Perbill::from_parts(5_000_000),
					min_delay: 600,
				},
			}),
		),
		(
			"pools_claim_commission",
			pools(pallet_nomination_pools::Call::claim_commission { pool_id: 7 }),
		),
		(
			"pools_set_commission_claim_permission_permissionless",
			pools(
				pallet_nomination_pools::Call::set_commission_claim_permission {
					pool_id: 7,
					permission: Some(
						pallet_nomination_pools::CommissionClaimPermission::Permissionless,
					),
				},
			),
		),
		(
			"pools_set_commission_claim_permission_account",
			pools(
				pallet_nomination_pools::Call::set_commission_claim_permission {
					pool_id: 7,
					permission: Some(pallet_nomination_pools::CommissionClaimPermission::Account(
						AccountId::from(BOB),
					)),
				},
			),
		),
		(
			"pools_set_commission_claim_permission_none",
			pools(
				pallet_nomination_pools::Call::set_commission_claim_permission {
					pool_id: 7,
					permission: None,
				},
			),
		),
		(
			"pools_update_roles",
			pools(pallet_nomination_pools::Call::update_roles {
				pool_id: 7,
				new_root: pallet_nomination_pools::ConfigOp::Noop,
				new_nominator: pallet_nomination_pools::ConfigOp::Set(AccountId::from(BOB)),
				new_bouncer: pallet_nomination_pools::ConfigOp::Remove,
			}),
		),
		(
			"pools_set_metadata",
			pools(pallet_nomination_pools::Call::set_metadata {
				pool_id: 7,
				metadata: vec![1, 2, 3],
			}),
		),
	]
}

fn render_vectors() -> serde_json::Value {
	let vectors: Vec<_> = vector_messages()
		.into_iter()
		.map(|(name, msg)| {
			// What a client reads from a polkadot-js payload: the call, era, nonce and tip.
			let input = &mut &msg[..];
			let (call, era, nonce, tip) = match RuntimeCall::decode(input) {
				Ok(call) => {
					let extra = SignedExtra::decode(input).unwrap();
					(
						call.encode(),
						extra.era().encode(),
						extra.nonce(),
						extra.tip(),
					)
				}
				Err(_) => (
					msg.clone(),
					sp_runtime::generic::Era::Immortal.encode(),
					0,
					0,
				),
			};
			serde_json::json!({
				"name": name,
				"payload": format!("0x{}", to_hex(&msg)),
				"call": format!("0x{}", to_hex(&call)),
				"era": format!("0x{}", to_hex(&era)),
				"nonce": nonce,
				"tip": tip.to_string(),
				"text": String::from_utf8(text_message(&TESTNET_GENESIS, &msg)).unwrap(),
				"signable": crate::signature::text_signable(&msg),
			})
		})
		.collect();
	// EcdsaText signatures: RFC 6979 is deterministic, so clients reproduce them byte for
	// byte with Alith's key (`personal_sign` with `v` as the raw recovery id). The shield's
	// text holds `…` (3 UTF-8 bytes), so its EIP-191 length is the text's byte length.
	let pair = sp_core::ecdsa::Pair::from_seed(&ALITH_KEY);
	let ecdsa: Vec<_> = [
		("transfer", payload_with_tip(&transfer(3 * ORB / 2), 0)),
		("shield_multibyte", payload_with_tip(&shield(0, 2 * ORB), 0)),
	]
	.into_iter()
	.map(|(name, payload)| {
		let message = crate::signature::eip191_text_message(&TESTNET_GENESIS, &payload);
		serde_json::json!({
			"name": name,
			"privateKey": format!("0x{}", to_hex(&ALITH_KEY)),
			"address": format!("0x{}", to_hex(&ALITH_ADDRESS)),
			"payload": format!("0x{}", to_hex(&payload)),
			"message": format!("0x{}", to_hex(&message)),
			"signature": format!("0x{}", to_hex(&super::ecdsa::sign_eip191(&pair, &payload).0)),
		})
	})
	.collect();
	serde_json::json!({
		"genesis": format!("0x{}", to_hex(&TESTNET_GENESIS)),
		"vectors": vectors,
		"ecdsa": ecdsa,
	})
}

/// ts-protocol renders these same texts; a change here must reach it, or its ed25519
/// accounts sign texts the runtime refuses.
#[test]
fn shared_vectors_match_the_runtime() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let pinned: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
		assert_eq!(pinned, render_vectors());
	});
}

/// Writes the fixture. Only when the format changes on purpose.
#[test]
#[ignore]
fn regenerate_shared_vectors() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		std::fs::write(
			concat!(
				env!("CARGO_MANIFEST_DIR"),
				"/src/signature/text/tests/fixtures/ed25519_text_vectors.json"
			),
			serde_json::to_string_pretty(&render_vectors()).unwrap() + "\n",
		)
		.unwrap();
	});
}

/// EIP-191 counts bytes, not characters: a text with `…` (U+2026) is longer in bytes.
#[test]
fn the_eip191_length_is_the_utf8_byte_length() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let payload = payload_with_tip(&shield(0, 2 * ORB), 0);
		let text = text_message(&TESTNET_GENESIS, &payload);
		let chars = String::from_utf8(text.clone()).unwrap().chars().count();
		assert!(text.len() > chars);
		let message = crate::signature::eip191_text_message(&TESTNET_GENESIS, &payload);
		let prefix = format!("\x19Ethereum Signed Message:\n{}", text.len());
		assert_eq!(message, [prefix.as_bytes(), &text].concat());
	});
}
