//! Two session validators, one keyed from another account, and a pre-digest that
//! names a block's author.

use crate::{AccountId, Runtime};
use scale_codec::Encode;
use sp_consensus_aura::{sr25519::AuthorityId as AuraId, Slot, AURA_ENGINE_ID};
use sp_core::{crypto::key_types::AURA, sr25519, Pair};
use sp_runtime::{Digest, DigestItem};

pub(crate) fn aura_key(seed: &str) -> AuraId {
	sr25519::Pair::from_string(seed, None)
		.unwrap()
		.public()
		.into()
}

pub(crate) fn as_account(key: &AuraId) -> AccountId {
	let raw: &[u8] = key.as_ref();
	<[u8; 32]>::try_from(raw).unwrap().into()
}

/// Two validators: `alice` registered her Aura key as her own account (the
/// genesis case), `bob` set his from another account (the `setKeys` case).
pub(crate) struct Set {
	pub alice: AccountId,
	pub bob: AccountId,
	pub bob_aura: AuraId,
}

pub(crate) fn validator_set() -> Set {
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
pub(crate) fn digest(index: u64) -> Digest {
	Digest {
		logs: vec![DigestItem::PreRuntime(
			AURA_ENGINE_ID,
			Slot::from(index).encode(),
		)],
	}
}
