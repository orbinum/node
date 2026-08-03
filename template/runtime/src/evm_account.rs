use core::marker::PhantomData;

use sp_core::H160;

use crate::AccountId;

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

/// Maps an EVM `H160` to its `AccountId32` as `[address | 0x00×12]`.
///
/// The mapping is purely structural: the same 20 bytes always produce the same
/// `AccountId32`, with no storage read. Secp256k1 accounts signing through
/// `OrbinumSignature` land on exactly this account, which is what makes the EVM
/// and Substrate views of a key one and the same account.
pub struct EeSuffixAddressMapping<T: pallet_evm::Config>(pub PhantomData<T>);

impl<T> pallet_evm::AddressMapping<T::AccountId> for EeSuffixAddressMapping<T>
where
	T: pallet_evm::Config,
	T::AccountId: From<[u8; 32]>,
{
	fn into_account_id(address: H160) -> T::AccountId {
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
		let expected_account: AccountId = evm_h160_to_account_id(*address);

		origin.into().and_then(|o| match o {
			frame_system::RawOrigin::Signed(who) if who == expected_account => Ok(who),
			r => Err(OuterOrigin::from(r)),
		})
	}
}
