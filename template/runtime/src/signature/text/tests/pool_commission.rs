// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Pool commission signed as text (`Ed25519Text`, `Ed25519WrappedText`, `EcdsaText`):
//! each call is accepted and dispatches; a text that misstates any of its parameters,
//! or another key's signature, is refused; the pool's commission rules hold for
//! text-signed calls; and the payee a text shows is the account the commission is
//! paid to.

use super::*;
use crate::{
	signature::OrbinumSigner,
	staking::params::TEST_POOL_MIN_CREATE_BOND,
	test_utils::{
		account,
		blocks::{run_block, run_block_with, run_to_era},
		network::with_validators,
		ALITH_KEY,
	},
	Balances, Executive, NominationPools, RuntimeEvent, RuntimeOrigin, System,
};
use frame_support::traits::fungible::{Inspect, Mutate};
use pallet_nomination_pools::{
	BondedPools, Call as PoolCall, CommissionChangeRate, CommissionClaimPermission, ConfigOp,
	Error, GlobalMaxCommission, PoolId,
};
use sp_core::ecdsa;
use sp_keyring::Sr25519Keyring;
use sp_runtime::{
	traits::IdentifyAccount, transaction_validity::InvalidTransaction, ApplyExtrinsicResult,
	DispatchError, Perbill,
};

/// A key that signs as text, under one of the three variants.
#[derive(Clone)]
enum Key {
	Text(ed25519::Pair),
	Wrapped(ed25519::Pair),
	Evm(ecdsa::Pair),
}

impl Key {
	fn text(seed: u8) -> Self {
		Key::Text(ed25519::Pair::from_seed(&[seed; 32]))
	}

	fn wrapped(seed: u8) -> Self {
		Key::Wrapped(ed25519::Pair::from_seed(&[seed; 32]))
	}

	fn evm(seed: [u8; 32]) -> Self {
		Key::Evm(ecdsa::Pair::from_seed(&seed))
	}

	/// One key of each variant, with distinct accounts.
	fn each() -> [Key; 3] {
		[Key::text(0x31), Key::wrapped(0x32), Key::evm(ALITH_KEY)]
	}

	fn account(&self) -> AccountId {
		match self {
			Key::Text(pair) | Key::Wrapped(pair) => AccountId::from(pair.public().0),
			Key::Evm(pair) => OrbinumSigner::Ecdsa(pair.public()).into_account(),
		}
	}

	/// Signs `text` as this variant's wallet does: as is, inside `<Bytes>…</Bytes>`, or
	/// through EIP-191.
	fn sign(&self, text: &[u8]) -> OrbinumSignature {
		match self {
			Key::Text(pair) => OrbinumSignature::Ed25519Text(pair.sign(text)),
			Key::Wrapped(pair) => OrbinumSignature::Ed25519WrappedText(
				pair.sign(&[b"<Bytes>".as_slice(), text, b"</Bytes>"].concat()),
			),
			Key::Evm(pair) => {
				let prefix = format!("\x19Ethereum Signed Message:\n{}", text.len());
				let message = [prefix.as_bytes(), text].concat();
				OrbinumSignature::EcdsaText(
					pair.sign_prehashed(&sp_io::hashing::keccak_256(&message)),
				)
			}
		}
	}
}

fn genesis() -> [u8; 32] {
	frame_system::Pallet::<Runtime>::block_hash(0u32).to_fixed_bytes()
}

/// The text the runtime renders for `call` at `nonce`.
fn honest_text(call: &RuntimeCall, nonce: u32) -> String {
	String::from_utf8(text_message(&genesis(), &raw_payload(call, nonce))).unwrap()
}

fn nonce(who: &AccountId) -> u32 {
	System::account_nonce(who)
}

/// `call` from `from`, signed by `key` over `text`, applied as a block author would
/// apply it: an invalid extrinsic leaves no trace, and one that does not fit a full
/// block (a session or election block) goes in the next.
fn apply_signed(
	from: &AccountId,
	key: &Key,
	call: RuntimeCall,
	text: &str,
) -> ApplyExtrinsicResult {
	let sig = key.sign(text.as_bytes());
	let xt = UncheckedExtrinsic::new_signed(call, from.clone(), sig, signed_extra(nonce(from), 0));
	let xt = UncheckedExtrinsic::decode(&mut &xt.encode()[..]).unwrap();
	let full = Err(InvalidTransaction::ExhaustsResources.into());
	for _ in 0..10 {
		let mut result = None;
		run_block_with(System::block_number() + 1, || {
			sp_io::storage::start_transaction();
			let applied = Executive::apply_extrinsic(xt.clone());
			if applied.is_ok() {
				sp_io::storage::commit_transaction();
			} else {
				sp_io::storage::rollback_transaction();
			}
			result = Some(applied);
		});
		let result = result.unwrap();
		if result != full {
			return result;
		}
	}
	full
}

/// `call` signed by `key` over the text the runtime renders for it, for its own account.
fn submit(key: &Key, call: PoolCall<Runtime>) -> ApplyExtrinsicResult {
	let call = RuntimeCall::NominationPools(call);
	let who = key.account();
	let text = honest_text(&call, nonce(&who));
	apply_signed(&who, key, call, &text)
}

fn dispatched(result: ApplyExtrinsicResult) -> Result<(), DispatchError> {
	result.expect("the signature is accepted")
}

fn refused<E: Into<DispatchError>>(error: E) -> Result<(), DispatchError> {
	Err(error.into())
}

fn bad_proof() -> ApplyExtrinsicResult {
	Err(InvalidTransaction::BadProof.into())
}

fn alice() -> AccountId {
	account(Sr25519Keyring::Alice)
}

fn fund(who: &AccountId) {
	Balances::set_balance(who, 10_000 * ORB);
}

/// A pool whose roles are all `key`'s account, nominating Alice. Created by a direct
/// call: only the commission calls under test are signed as text.
fn create_pool(key: &Key) -> PoolId {
	let root = key.account();
	fund(&root);
	assert_ok(NominationPools::create(
		RuntimeOrigin::signed(root.clone()),
		TEST_POOL_MIN_CREATE_BOND,
		root.clone(),
		root.clone(),
		root.clone(),
	));
	let id = pallet_nomination_pools::LastPoolId::<Runtime>::get();
	assert_ok(NominationPools::nominate(
		RuntimeOrigin::signed(root),
		id,
		vec![alice()],
	));
	id
}

fn assert_ok(result: frame_support::dispatch::DispatchResult) {
	assert_eq!(result, Ok(()));
}

fn commission(id: PoolId) -> pallet_nomination_pools::Commission<Runtime> {
	BondedPools::<Runtime>::get(id).unwrap().commission
}

fn run_blocks(count: u32) {
	for _ in 0..count {
		run_block(System::block_number() + 1);
	}
}

fn rate(max_increase: u32, min_delay: u32) -> CommissionChangeRate<u32> {
	CommissionChangeRate {
		max_increase: Perbill::from_percent(max_increase),
		min_delay,
	}
}

fn set_commission(id: PoolId, percent: u32, payee: &AccountId) -> PoolCall<Runtime> {
	PoolCall::set_commission {
		pool_id: id,
		new_commission: Some((Perbill::from_percent(percent), payee.clone())),
	}
}

fn payee() -> AccountId {
	AccountId::from([0x7a; 32])
}

fn stranger() -> AccountId {
	AccountId::from([0x7b; 32])
}

// Accepted and dispatched

/// Each commission call, signed as text under each variant by the pool's root, passes
/// the signature check and changes the pool as its text says.
#[test]
fn each_commission_call_signed_as_text_dispatches() {
	with_validators(|| {
		for key in Key::each() {
			let id = create_pool(&key);
			let root = key.account();

			assert_eq!(
				dispatched(submit(
					&key,
					PoolCall::set_commission_max {
						pool_id: id,
						max_commission: Perbill::from_percent(50),
					}
				)),
				Ok(())
			);
			assert_eq!(commission(id).max, Some(Perbill::from_percent(50)));

			assert_eq!(
				dispatched(submit(&key, set_commission(id, 5, &payee()))),
				Ok(())
			);
			assert_eq!(
				commission(id).current,
				Some((Perbill::from_percent(5), payee()))
			);

			assert_eq!(
				dispatched(submit(
					&key,
					PoolCall::set_commission_change_rate {
						pool_id: id,
						change_rate: rate(2, 10),
					}
				)),
				Ok(())
			);
			assert_eq!(commission(id).change_rate, Some(rate(2, 10)));

			let permission = Some(CommissionClaimPermission::Account(stranger()));
			assert_eq!(
				dispatched(submit(
					&key,
					PoolCall::set_commission_claim_permission {
						pool_id: id,
						permission: permission.clone(),
					}
				)),
				Ok(())
			);
			assert_eq!(commission(id).claim_permission, permission);

			// Nothing earned yet: the call ran and the pool refused it.
			assert_eq!(
				dispatched(submit(&key, PoolCall::claim_commission { pool_id: id })),
				refused(Error::<Runtime>::NoPendingCommission)
			);

			assert_eq!(
				dispatched(submit(
					&key,
					PoolCall::set_commission {
						pool_id: id,
						new_commission: None,
					}
				)),
				Ok(())
			);
			assert_eq!(commission(id).current, None);
			assert!(nonce(&root) >= 6);
		}
	});
}

/// The payee line of the signed text names the account paid on a claim, whoever
/// claims: the root, or anyone when the pool lets anyone claim.
#[test]
fn the_payee_the_text_shows_receives_the_claimed_commission() {
	with_validators(|| {
		let keys = Key::each();
		let ids: Vec<_> = keys.iter().map(create_pool).collect();
		let claimer = Key::text(0x41);
		fund(&claimer.account());
		for (n, (key, id)) in keys.iter().zip(&ids).enumerate() {
			let payee = AccountId::from([0x80 + n as u8; 32]);
			let call = RuntimeCall::NominationPools(set_commission(*id, 10, &payee));
			let text = honest_text(&call, nonce(&key.account()));
			let shown = text
				.lines()
				.find_map(|line| line.strip_prefix("payee: "))
				.expect("a payee line");
			assert_eq!(shown, format!("0x{}", to_hex(payee.as_ref())));
			assert_eq!(
				dispatched(apply_signed(&key.account(), key, call, &text)),
				Ok(())
			);
		}
		run_to_era(3);
		run_blocks(50);

		for (n, (key, id)) in keys.iter().zip(&ids).enumerate() {
			let payee = AccountId::from([0x80 + n as u8; 32]);
			let claimant = if n == 0 {
				key.clone()
			} else {
				assert_eq!(
					dispatched(submit(
						key,
						PoolCall::set_commission_claim_permission {
							pool_id: *id,
							permission: Some(CommissionClaimPermission::Permissionless),
						}
					)),
					Ok(())
				);
				claimer.clone()
			};
			let before = Balances::balance(&claimant.account());
			System::reset_events();
			assert_eq!(
				dispatched(submit(
					&claimant,
					PoolCall::claim_commission { pool_id: *id }
				)),
				Ok(())
			);
			let claimed = System::events()
				.iter()
				.find_map(|r| match r.event {
					RuntimeEvent::NominationPools(
						pallet_nomination_pools::Event::PoolCommissionClaimed {
							pool_id,
							commission,
						},
					) if pool_id == *id => Some(commission),
					_ => None,
				})
				.expect("commission claimed");
			assert!(claimed > 0);
			assert_eq!(Balances::balance(&payee), claimed);
			// The claimant only pays the fee.
			assert!(Balances::balance(&claimant.account()) < before);
		}
	});
}

// Refused signatures

/// What a misstating text keeps of the honest one: its frame and its `payload:` line,
/// which hashes the real payload.
fn with_lines_of(real: &str, other: &str) -> String {
	let payload_line = real.lines().last().unwrap();
	let mut lines: Vec<_> = other.lines().collect();
	*lines.last_mut().unwrap() = payload_line;
	lines.join("\n")
}

/// Pairs of calls that differ in one parameter: pool, commission, payee, removal, max,
/// either change-rate field, or claim permission.
fn misstatements() -> Vec<(PoolCall<Runtime>, PoolCall<Runtime>)> {
	let bob = AccountId::from(BOB);
	let other = AccountId::from([0xa1; 32]);
	let permission = |p| PoolCall::set_commission_claim_permission {
		pool_id: 1,
		permission: p,
	};
	let change_rate = |r| PoolCall::set_commission_change_rate {
		pool_id: 1,
		change_rate: r,
	};
	let max = |m| PoolCall::set_commission_max {
		pool_id: 1,
		max_commission: Perbill::from_percent(m),
	};
	vec![
		(set_commission(1, 50, &bob), set_commission(1, 5, &bob)),
		(set_commission(1, 5, &other), set_commission(1, 5, &bob)),
		(set_commission(2, 5, &bob), set_commission(1, 5, &bob)),
		(
			set_commission(1, 5, &bob),
			PoolCall::set_commission {
				pool_id: 1,
				new_commission: None,
			},
		),
		(max(90), max(10)),
		(
			max(10),
			PoolCall::set_commission_max {
				pool_id: 2,
				max_commission: Perbill::from_percent(10),
			},
		),
		(change_rate(rate(50, 10)), change_rate(rate(1, 10))),
		(change_rate(rate(1, 0)), change_rate(rate(1, 1_000))),
		(
			permission(Some(CommissionClaimPermission::Permissionless)),
			permission(None),
		),
		(
			permission(Some(CommissionClaimPermission::Account(other.clone()))),
			permission(Some(CommissionClaimPermission::Account(bob.clone()))),
		),
		(
			permission(Some(CommissionClaimPermission::Account(other))),
			permission(Some(CommissionClaimPermission::Permissionless)),
		),
		(
			PoolCall::claim_commission { pool_id: 2 },
			PoolCall::claim_commission { pool_id: 1 },
		),
	]
}

fn check_text(key: &Key, call: RuntimeCall, text: &str) -> Result<(), TransactionValidityError> {
	check(call, &key.account(), key.sign(text.as_bytes()), 0)
}

/// A signature over a text that shows other parameters than the payload's authorizes
/// nothing, under every variant: neither the other call's text nor its lines over the
/// real payload's hash.
#[test]
fn a_text_that_misstates_a_commission_parameter_is_refused() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		for key in Key::each() {
			for (real, shown) in misstatements() {
				let (real, shown) = (
					RuntimeCall::NominationPools(real),
					RuntimeCall::NominationPools(shown),
				);
				let honest = honest_text(&real, 0);
				let other = honest_text(&shown, 0);
				assert_ne!(honest, other);
				assert_eq!(check_text(&key, real.clone(), &honest), Ok(()), "{honest}");
				for lie in [other.clone(), with_lines_of(&honest, &other)] {
					assert_eq!(
						check_text(&key, real.clone(), &lie),
						Err(InvalidTransaction::BadProof.into()),
						"{lie}"
					);
				}
			}
		}
	});
}

/// The root's honest text signed by any other key, of any variant, is refused.
#[test]
fn another_key_cannot_sign_for_the_root() {
	with_ext(|| {
		set_genesis(TESTNET_GENESIS);
		let others = [Key::text(0x51), Key::wrapped(0x52), Key::evm([0x53; 32])];
		for root in Key::each() {
			for (call, _) in misstatements() {
				let call = RuntimeCall::NominationPools(call);
				let text = honest_text(&call, 0);
				for other in &others {
					let sig = other.sign(text.as_bytes());
					assert_eq!(
						check(call.clone(), &root.account(), sig, 0),
						Err(InvalidTransaction::BadProof.into())
					);
				}
			}
		}
	});
}

/// The same refusal through block application: the extrinsic is invalid and the pool
/// unchanged.
#[test]
fn a_misstated_commission_is_not_applied() {
	with_validators(|| {
		for key in Key::each() {
			let id = create_pool(&key);
			let call = RuntimeCall::NominationPools(set_commission(id, 100, &stranger()));
			let honest = honest_text(&call, nonce(&key.account()));
			let shown = RuntimeCall::NominationPools(set_commission(id, 1, &payee()));
			let lie = with_lines_of(&honest, &honest_text(&shown, nonce(&key.account())));
			assert_eq!(apply_signed(&key.account(), &key, call, &lie), bad_proof());
			assert_eq!(commission(id).current, None);
		}
	});
}

// The pool's rules hold for text-signed calls

/// Only the root manages commission; the other text keys are refused by the pool.
#[test]
fn a_text_signer_that_is_not_the_root_is_refused() {
	with_validators(|| {
		let roots = Key::each();
		let ids: Vec<_> = roots.iter().map(create_pool).collect();
		let outsiders = [Key::text(0x61), Key::wrapped(0x62), Key::evm([0x63; 32])];
		for key in &outsiders {
			fund(&key.account());
		}
		for (id, outsider) in ids.iter().zip(&outsiders) {
			let calls = [
				set_commission(*id, 5, &outsider.account()),
				PoolCall::set_commission_max {
					pool_id: *id,
					max_commission: Perbill::from_percent(1),
				},
				PoolCall::set_commission_change_rate {
					pool_id: *id,
					change_rate: rate(1, 1),
				},
				PoolCall::set_commission_claim_permission {
					pool_id: *id,
					permission: Some(CommissionClaimPermission::Permissionless),
				},
				PoolCall::claim_commission { pool_id: *id },
			];
			for call in calls {
				assert_eq!(
					dispatched(submit(outsider, call)),
					refused(Error::<Runtime>::DoesNotHavePermission)
				);
			}
			assert_eq!(commission(*id), Default::default());
		}
	});
}

/// Commission stays under the pool's max and the global max; the max only goes down.
#[test]
fn commission_and_its_max_stay_under_the_caps() {
	with_validators(|| {
		for key in Key::each() {
			let id = create_pool(&key);
			let max = |percent| PoolCall::set_commission_max {
				pool_id: id,
				max_commission: Perbill::from_percent(percent),
			};
			assert_eq!(dispatched(submit(&key, max(20))), Ok(()));
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 21, &payee()))),
				refused(Error::<Runtime>::CommissionExceedsMaximum)
			);
			assert_eq!(
				dispatched(submit(&key, max(21))),
				refused(Error::<Runtime>::MaxCommissionRestricted)
			);
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 20, &payee()))),
				Ok(())
			);
			// Lowering the max lowers a commission above it.
			assert_eq!(dispatched(submit(&key, max(15))), Ok(()));
			assert_eq!(
				commission(id).current,
				Some((Perbill::from_percent(15), payee()))
			);
		}

		assert_ok(NominationPools::set_configs(
			RuntimeOrigin::root(),
			ConfigOp::Noop,
			ConfigOp::Noop,
			ConfigOp::Noop,
			ConfigOp::Noop,
			ConfigOp::Noop,
			ConfigOp::Set(Perbill::from_percent(10)),
		));
		assert_eq!(
			GlobalMaxCommission::<Runtime>::get(),
			Some(Perbill::from_percent(10))
		);
		for key in [Key::text(0x71), Key::wrapped(0x72), Key::evm([0x73; 32])] {
			let id = create_pool(&key);
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 11, &payee()))),
				refused(Error::<Runtime>::CommissionExceedsGlobalMaximum)
			);
			assert_eq!(
				dispatched(submit(
					&key,
					PoolCall::set_commission_max {
						pool_id: id,
						max_commission: Perbill::from_percent(11),
					}
				)),
				refused(Error::<Runtime>::CommissionExceedsGlobalMaximum)
			);
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 10, &payee()))),
				Ok(())
			);
		}
	});
}

/// The change rate only gets stricter (a larger increase or a shorter delay is refused),
/// and an increase larger than `max_increase` is throttled; decreases never are.
#[test]
fn the_change_rate_only_tightens_and_caps_each_increase() {
	with_validators(|| {
		for key in Key::each() {
			let id = create_pool(&key);
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 5, &payee()))),
				Ok(())
			);
			let change_rate = |r| PoolCall::set_commission_change_rate {
				pool_id: id,
				change_rate: r,
			};
			assert_eq!(dispatched(submit(&key, change_rate(rate(2, 0)))), Ok(()));
			for looser in [rate(3, 0), rate(3, 5)] {
				assert_eq!(
					dispatched(submit(&key, change_rate(looser))),
					refused(Error::<Runtime>::CommissionChangeRateNotAllowed)
				);
			}
			assert_eq!(commission(id).change_rate, Some(rate(2, 0)));
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 8, &payee()))),
				refused(Error::<Runtime>::CommissionChangeThrottled)
			);
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 7, &payee()))),
				Ok(())
			);
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 1, &payee()))),
				Ok(())
			);
			// Stricter is allowed; then a delay shorter than it is refused.
			assert_eq!(dispatched(submit(&key, change_rate(rate(1, 10)))), Ok(()));
			assert_eq!(
				dispatched(submit(&key, change_rate(rate(1, 9)))),
				refused(Error::<Runtime>::CommissionChangeRateNotAllowed)
			);
			assert_eq!(commission(id).change_rate, Some(rate(1, 10)));
		}
	});
}

/// An increase sooner than `min_delay` blocks after the last change is throttled.
/// Not under `runtime-benchmarks`, whose pools read block 0 as the current block.
#[cfg(not(feature = "runtime-benchmarks"))]
#[test]
fn the_change_rate_spaces_increases_by_min_delay() {
	with_validators(|| {
		for key in Key::each() {
			let id = create_pool(&key);
			let change_rate = |r| PoolCall::set_commission_change_rate {
				pool_id: id,
				change_rate: r,
			};
			assert_eq!(dispatched(submit(&key, change_rate(rate(5, 10)))), Ok(()));
			// Too soon after the change rate was set.
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 5, &payee()))),
				refused(Error::<Runtime>::CommissionChangeThrottled)
			);
			run_blocks(10);
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 5, &payee()))),
				Ok(())
			);
			// Too soon after the last change.
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 6, &payee()))),
				refused(Error::<Runtime>::CommissionChangeThrottled)
			);
			// Lowering is never throttled.
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 1, &payee()))),
				Ok(())
			);
			assert_eq!(dispatched(submit(&key, change_rate(rate(1, 20)))), Ok(()));
			run_blocks(20);
			assert_eq!(
				dispatched(submit(&key, set_commission(id, 2, &payee()))),
				Ok(())
			);
			assert_eq!(
				commission(id).current,
				Some((Perbill::from_percent(2), payee()))
			);
		}
	});
}

/// Only the accounts the claim permission allows claim: the root always; one named
/// account besides it; anyone when permissionless.
#[test]
fn only_the_accounts_the_permission_allows_claim() {
	with_validators(|| {
		let keys = Key::each();
		let ids: Vec<_> = keys.iter().map(create_pool).collect();
		let (named, other) = (Key::wrapped(0x91), Key::evm([0x92; 32]));
		fund(&named.account());
		fund(&other.account());
		for (key, id) in keys.iter().zip(&ids) {
			assert_eq!(
				dispatched(submit(key, set_commission(*id, 10, &payee()))),
				Ok(())
			);
		}
		run_to_era(3);
		run_blocks(50);

		let claim = |key: &Key, id: PoolId| {
			dispatched(submit(key, PoolCall::claim_commission { pool_id: id }))
		};
		let permission = |key: &Key, id: PoolId, permission| {
			dispatched(submit(
				key,
				PoolCall::set_commission_claim_permission {
					pool_id: id,
					permission,
				},
			))
		};
		let denied = refused(Error::<Runtime>::DoesNotHavePermission);

		// No permission: the root only.
		let id = ids[0];
		assert_eq!(claim(&named, id), denied);
		assert_eq!(claim(&keys[0], id), Ok(()));

		// One account: it, or the root; nobody else.
		let id = ids[1];
		assert_eq!(
			permission(
				&keys[1],
				id,
				Some(CommissionClaimPermission::Account(named.account()))
			),
			Ok(())
		);
		assert_eq!(claim(&other, id), denied);
		assert_eq!(claim(&named, id), Ok(()));

		// Permissionless, then withdrawn: back to the root only.
		let id = ids[2];
		assert_eq!(
			permission(
				&keys[2],
				id,
				Some(CommissionClaimPermission::Permissionless)
			),
			Ok(())
		);
		assert_eq!(permission(&keys[2], id, None), Ok(()));
		assert_eq!(claim(&other, id), denied);
		assert_eq!(claim(&keys[2], id), Ok(()));
		assert!(Balances::balance(&payee()) > 0);
	});
}
