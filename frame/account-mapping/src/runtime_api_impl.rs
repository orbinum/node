use crate::pallet::{
	AccountAliases, AliasListings, Identities, PrivateChainLinks, ReverseChainLinks,
};
use crate::{Config, Pallet};
use alloc::vec::Vec;

pub struct RawPrivateLink {
	pub chain_id: u32,
	pub commitment: [u8; 32],
}

impl<T: Config> Pallet<T> {
	pub fn runtime_api_resolve_alias(alias: &[u8]) -> Option<crate::pallet::IdentityRecord<T>> {
		Self::resolve_alias(alias)
	}

	pub fn runtime_api_get_alias_of(account: T::AccountId) -> Option<Vec<u8>> {
		AccountAliases::<T>::get(account).map(|a| a.into_inner())
	}

	pub fn runtime_api_can_buy(alias: Vec<u8>, buyer: T::AccountId) -> bool {
		if AccountAliases::<T>::contains_key(&buyer) {
			return false;
		}
		let Ok(()) = crate::utils::validate_alias(&alias) else {
			return false;
		};
		let Ok(bounded) = crate::pallet::AliasOf::<T>::try_from(alias) else {
			return false;
		};
		let Some(listing) = AliasListings::<T>::get(&bounded) else {
			return false;
		};
		if let Some(whitelist) = &listing.allowed_buyers {
			whitelist.contains(&buyer)
		} else {
			true
		}
	}

	pub fn runtime_api_get_link_owner(chain_id: u32, address: Vec<u8>) -> Option<T::AccountId> {
		let bounded: crate::ExternalAddr = address.try_into().ok()?;
		ReverseChainLinks::<T>::get((chain_id, bounded))
	}

	pub fn runtime_api_get_private_links(alias: Vec<u8>) -> Option<Vec<RawPrivateLink>> {
		crate::utils::validate_alias(&alias).ok()?;
		let bounded: crate::pallet::AliasOf<T> = alias.try_into().ok()?;
		Identities::<T>::contains_key(&bounded).then(|| {
			PrivateChainLinks::<T>::get(&bounded)
				.iter()
				.map(|l| RawPrivateLink {
					chain_id: l.chain_id,
					commitment: l.commitment,
				})
				.collect()
		})
	}

	pub fn runtime_api_has_private_link(alias: Vec<u8>, commitment: [u8; 32]) -> bool {
		let Ok(()) = crate::utils::validate_alias(&alias) else {
			return false;
		};
		let Ok(bounded) = crate::pallet::AliasOf::<T>::try_from(alias) else {
			return false;
		};
		PrivateChainLinks::<T>::get(&bounded)
			.iter()
			.any(|l| l.commitment == commitment)
	}
}
