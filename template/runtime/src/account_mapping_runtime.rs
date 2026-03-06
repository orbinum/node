use core::marker::PhantomData;

use frame_support::sp_runtime::traits::Convert;
use sp_core::H160;

use crate::{AccountId, Runtime};

pub const EVM_ACCOUNT_MARKER: [u8; 12] = [0x00u8; 12];

pub fn evm_bytes_to_account_id_bytes(eth_address: [u8; 20]) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	bytes[..20].copy_from_slice(&eth_address);
	bytes[20..].copy_from_slice(&EVM_ACCOUNT_MARKER);
	bytes
}

pub fn evm_h160_to_account_id_bytes(address: H160) -> [u8; 32] {
	evm_bytes_to_account_id_bytes(*address.as_fixed_bytes())
}

pub fn evm_h160_to_account_id(address: H160) -> AccountId {
	AccountId::from(evm_h160_to_account_id_bytes(address))
}

pub fn try_evm_h160_from_account_id(account_id: &AccountId) -> Option<H160> {
	let bytes: &[u8; 32] = account_id.as_ref();
	if bytes[20..] == EVM_ACCOUNT_MARKER {
		Some(H160::from_slice(&bytes[0..20]))
	} else {
		None
	}
}

pub struct AccountIdToEvmAddress;
impl Convert<AccountId, Option<H160>> for AccountIdToEvmAddress {
	fn convert(account_id: AccountId) -> Option<H160> {
		try_evm_h160_from_account_id(&account_id)
	}
}

pub struct EeSuffixAddressMapping<T: pallet_evm::Config>(pub PhantomData<T>);

impl<T> pallet_evm::AddressMapping<T::AccountId> for EeSuffixAddressMapping<T>
where
	T: pallet_evm::Config + pallet_account_mapping::Config,
	T::AccountId: From<[u8; 32]>,
{
	fn into_account_id(address: H160) -> T::AccountId {
		if let Some(mapped) = pallet_account_mapping::Pallet::<T>::mapped_account(address) {
			return mapped;
		}
		T::AccountId::from(evm_h160_to_account_id_bytes(address))
	}
}

pub struct EnsureAddressMatches;

impl<OuterOrigin> pallet_evm::EnsureAddressOrigin<OuterOrigin> for EnsureAddressMatches
where
	OuterOrigin: Into<Result<frame_system::RawOrigin<AccountId>, OuterOrigin>>
		+ From<frame_system::RawOrigin<AccountId>>,
{
	type Success = AccountId;

	fn try_address_origin(address: &H160, origin: OuterOrigin) -> Result<AccountId, OuterOrigin> {
		let expected_account: AccountId =
			pallet_account_mapping::Pallet::<Runtime>::mapped_account(*address)
				.unwrap_or_else(|| evm_h160_to_account_id(*address));

		origin.into().and_then(|o| match o {
			frame_system::RawOrigin::Signed(who) if who == expected_account => Ok(who),
			r => Err(OuterOrigin::from(r)),
		})
	}
}
