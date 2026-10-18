use crate::{configs::consensus::ValidatorAuthor, AccountId, Runtime, RuntimeCall, RuntimeOrigin};
use frame_support::traits::FindAuthor;
use pallet_validator_set::NodeVersion;
use scale_codec::Encode;
use sp_consensus_aura::{sr25519::AuthorityId as AuraId, Slot, AURA_ENGINE_ID};
use sp_core::{crypto::key_types::AURA, sr25519, Pair};
use sp_runtime::{traits::Dispatchable, Digest, DigestItem};

fn aura_key(seed: &str) -> AuraId {
	sr25519::Pair::from_string(seed, None)
		.unwrap()
		.public()
		.into()
}

fn as_account(key: &AuraId) -> AccountId {
	let raw: &[u8] = key.as_ref();
	<[u8; 32]>::try_from(raw).unwrap().into()
}

/// Two validators: `alice` registered her Aura key as her own account (the
/// genesis case), `bob` set his from another account (the `setKeys` case).
struct Set {
	alice: AccountId,
	bob: AccountId,
	bob_aura: AuraId,
}

fn validator_set() -> Set {
	let alice_aura = aura_key("//Alice");
	let alice = as_account(&alice_aura);
	let bob_aura = aura_key("//BobAura");
	let bob: AccountId = [0xb0; 32].into();
	pallet_session::Validators::<Runtime>::put(vec![alice.clone(), bob.clone()]);
	pallet_aura::Authorities::<Runtime>::put(
		frame_support::BoundedVec::try_from(vec![alice_aura.clone(), bob_aura.clone()]).unwrap(),
	);
	for (key, owner) in [(&alice_aura, &alice), (&bob_aura, &bob)] {
		let raw: &[u8] = key.as_ref();
		pallet_session::KeyOwner::<Runtime>::insert((AURA, raw.to_vec()), owner);
	}
	pallet_validator_set::ApprovedValidators::<Runtime>::put(
		frame_support::BoundedVec::try_from(vec![alice.clone(), bob.clone()]).unwrap(),
	);
	Set {
		alice,
		bob,
		bob_aura,
	}
}

/// A pre-digest naming the authority at `index` of two.
fn digest(index: u64) -> Digest {
	Digest {
		logs: vec![DigestItem::PreRuntime(
			AURA_ENGINE_ID,
			Slot::from(index).encode(),
		)],
	}
}

#[test]
fn the_author_is_the_session_validator_not_its_aura_key() {
	super::with_ext(|| {
		let set = validator_set();
		let logs = digest(1);
		let found =
			ValidatorAuthor::find_author(logs.logs.iter().filter_map(|d| d.as_pre_runtime()));
		assert_eq!(found, Some(set.bob.clone()));
		assert_ne!(found, Some(as_account(&set.bob_aura)));
		let logs = digest(0);
		let found =
			ValidatorAuthor::find_author(logs.logs.iter().filter_map(|d| d.as_pre_runtime()));
		assert_eq!(found, Some(set.alice));
	});
}

#[test]
fn a_setkeys_validator_has_its_version_recorded() {
	super::with_ext(|| {
		let set = validator_set();
		frame_system::Pallet::<Runtime>::initialize(&1, &Default::default(), &digest(1));
		let version = NodeVersion::new(0, 4, 0);
		RuntimeCall::ValidatorSet(pallet_validator_set::Call::note_author_version { version })
			.dispatch(RuntimeOrigin::none())
			.expect("the declaration is accepted");
		assert_eq!(
			pallet_validator_set::LastAuthorVersion::<Runtime>::get(&set.bob),
			Some((version, 1))
		);
	});
}

#[test]
fn spend_fees_go_to_the_validator_account() {
	use frame_support::traits::Get;
	super::with_ext(|| {
		let set = validator_set();
		frame_system::Pallet::<Runtime>::initialize(&1, &Default::default(), &digest(1));
		assert_eq!(
			pallet_authorship::Pallet::<Runtime>::author(),
			Some(set.bob.clone())
		);
		assert_eq!(
			crate::configs::privacy::ValidatorAccountAuthor::get(),
			Some(set.bob)
		);
	});
}

#[test]
fn an_evm_tip_goes_to_the_validator_and_burns_without_one() {
	use frame_support::traits::fungible::{Balanced, Inspect};
	use pallet_evm::OnChargeEVMTransaction;
	type B = crate::Balances;
	type Tips = crate::configs::evm::TipToValidator;
	super::with_ext(|| {
		let set = validator_set();
		// No pre-digest: no author, so the tip is burned.
		let before = B::total_issuance();
		Tips::pay_priority_fee(Some(B::issue(6)));
		assert_eq!(B::total_issuance(), before);

		frame_system::Pallet::<Runtime>::initialize(&1, &Default::default(), &digest(1));
		Tips::pay_priority_fee(Some(B::issue(25)));
		assert_eq!(B::balance(&set.bob), 25);
	});
}
