#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{format, vec::Vec};
use core::marker::PhantomData;
use fp_evm::{
	ExitError, ExitSucceed, Precompile, PrecompileFailure, PrecompileHandle, PrecompileOutput,
	PrecompileResult,
};
use frame_support::dispatch::GetDispatchInfo;
use pallet_evm::{AddressMapping, GasWeightMapping};
use sp_core::U256;
use sp_runtime::traits::Dispatchable;

// ─────────────────────────────────────────────────────────────────────────────
// ABI Function Selectors
//
// Computed as: bytes4(keccak256("functionName(argTypes)"))
// Verify with: cast sig "functionName(argTypes)"  (Foundry)
//
// registerAlias(string)        → cast sig "registerAlias(string)"
// resolveAlias(string)          → cast sig "resolveAlias(string)"
// getAliasOf(address)           → cast sig "getAliasOf(address)"
// hasPrivateLink(string,bytes32)→ cast sig "hasPrivateLink(string,bytes32)"
// ─────────────────────────────────────────────────────────────────────────────
const SEL_REGISTER_ALIAS: [u8; 4] = [0x2f, 0x88, 0x39, 0xc3]; // registerAlias(string)
const SEL_RESOLVE_ALIAS: [u8; 4] = [0xd0, 0x31, 0x49, 0xab]; // resolveAlias(string)
const SEL_GET_ALIAS_OF: [u8; 4] = [0x7a, 0x0e, 0xd6, 0x2c]; // getAliasOf(address)
const SEL_HAS_PRIVATE_LINK: [u8; 4] = [0x47, 0xe0, 0x5c, 0x6c]; // hasPrivateLink(string,bytes32)

pub struct AccountMappingPrecompile<T>(PhantomData<T>);

impl<T> Precompile for AccountMappingPrecompile<T>
where
	T: pallet_evm::Config + pallet_account_mapping::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = frame_support::dispatch::PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_account_mapping::Call<T>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin:
		From<Option<<T as frame_system::Config>::AccountId>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
{
	fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
		let input = handle.input().to_vec();

		if input.len() < 4 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("input too short: missing selector".into()),
			});
		}

		let selector: [u8; 4] = input[0..4].try_into().unwrap();

		match selector {
			SEL_REGISTER_ALIAS => Self::register_alias(handle, &input),
			SEL_RESOLVE_ALIAS => Self::resolve_alias(&input),
			SEL_GET_ALIAS_OF => Self::get_alias_of(&input),
			SEL_HAS_PRIVATE_LINK => Self::has_private_link(&input),
			_ => Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("unknown selector".into()),
			}),
		}
	}
}

impl<T> AccountMappingPrecompile<T>
where
	T: pallet_evm::Config + pallet_account_mapping::Config,
	<T as frame_system::Config>::RuntimeCall: Dispatchable<PostInfo = frame_support::dispatch::PostDispatchInfo>
		+ GetDispatchInfo
		+ From<pallet_account_mapping::Call<T>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin:
		From<Option<<T as frame_system::Config>::AccountId>>,
	<<T as frame_system::Config>::RuntimeCall as Dispatchable>::PostInfo: core::fmt::Debug,
	pallet_evm::AccountIdOf<T>: Into<<T as frame_system::Config>::AccountId>,
{
	// ─── registerAlias(string alias) ─────────────────────────────────────────
	//
	// Dispatches the `register_alias` extrinsic on behalf of the EVM caller.
	// ABI calldata (after the 4-byte selector):
	//   [0..32]  = uint256 offset (relative to the start of params, typically 0x20)
	//   at offset: uint256 length + UTF-8 bytes of the alias
	fn register_alias(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let caller = handle.context().caller;
		let params = &input[4..]; // strip selector

		if params.len() < 64 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI input too short".into()),
			});
		}

		let offset = U256::from_big_endian(&params[0..32]).low_u32() as usize;
		let abs_len_pos = offset;

		if abs_len_pos + 32 > params.len() {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI offset out of bounds".into()),
			});
		}

		let length =
			U256::from_big_endian(&params[abs_len_pos..abs_len_pos + 32]).low_u32() as usize;
		let abs_data_start = abs_len_pos + 32;

		if abs_data_start + length > params.len() {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI string data out of bounds".into()),
			});
		}

		let alias_bytes = params[abs_data_start..abs_data_start + length].to_vec();

		let bounded_alias: pallet_account_mapping::AliasOf<T> =
			alias_bytes
				.try_into()
				.map_err(|_| PrecompileFailure::Error {
					exit_status: ExitError::Other("alias too long".into()),
				})?;

		let call = <<T as frame_system::Config>::RuntimeCall as From<
			pallet_account_mapping::Call<T>,
		>>::from(pallet_account_mapping::Call::<T>::register_alias {
			alias: bounded_alias,
		});
		let info = call.get_dispatch_info();
		let gas_cost = T::GasWeightMapping::weight_to_gas(info.total_weight());
		handle.record_cost(gas_cost)?;

		let origin: <T as frame_system::Config>::AccountId =
			T::AddressMapping::into_account_id(caller).into();
		let dispatch_origin =
			<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin::from(Some(
				origin,
			));

		match call.dispatch(dispatch_origin) {
			Ok(_) => Ok(PrecompileOutput {
				exit_status: ExitSucceed::Returned,
				output: Default::default(),
			}),
			Err(e) => Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(format!("dispatch failed: {e:?}").into()),
			}),
		}
	}

	// ─── resolveAlias(string alias) returns (address owner, address evmAddress) ─
	//
	// Read-only query. No state modification.
	// Returns ABI-encoded (address, address):
	//   bytes [0..32]:  owner (20 bytes right-justified, 12 leading zeros)
	//   bytes [32..64]: evmAddress (same encoding)
	// Returns 64 zero bytes if the alias does not exist.
	fn resolve_alias(input: &[u8]) -> PrecompileResult {
		let alias_bytes = Self::decode_abi_string(&input[4..])?;

		let (owner_h160, evm_h160) = if let Some(record) =
			pallet_account_mapping::Pallet::<T>::runtime_api_resolve_alias(&alias_bytes)
		{
			let owner_h160 = record.evm_address.unwrap_or(sp_core::H160::zero());
			(owner_h160, owner_h160)
		} else {
			(sp_core::H160::zero(), sp_core::H160::zero())
		};

		// ABI encode: two addresses (32 bytes each, address occupies the last 20 bytes)
		let mut output = alloc::vec![0u8; 64];
		output[12..32].copy_from_slice(owner_h160.as_bytes());
		output[44..64].copy_from_slice(evm_h160.as_bytes());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	// ─── getAliasOf(address evm) returns (bytes alias) ───────────────────────
	//
	// Read-only query. Returns the registered alias for an EVM address.
	// ABI return type `bytes` (dynamic):
	//   bytes [0..32]:   offset = 0x20
	//   bytes [32..64]:  alias length in bytes
	//   bytes [64..N]:   alias bytes, zero-padded to a 32-byte multiple
	// Returns empty bytes if the address has no alias.
	fn get_alias_of(input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 32 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("getAliasOf: input too short".into()),
			});
		}

		// ABI address: 32-byte slot, address occupies the last 20 bytes
		let evm_addr = sp_core::H160::from_slice(&params[12..32]);
		let account: <T as frame_system::Config>::AccountId =
			T::AddressMapping::into_account_id(evm_addr).into();

		let alias: Vec<u8> = pallet_account_mapping::Pallet::<T>::runtime_api_get_alias_of(account)
			.unwrap_or_default();

		// ABI encode `bytes`: offset (32) + length + data zero-padded to 32-byte multiple
		let padded_len = (alias.len() + 31) & !31;
		let mut output = alloc::vec![0u8; 64 + padded_len];
		// offset = 0x20
		output[31] = 0x20;
		// length
		let len_bytes = (alias.len() as u64).to_be_bytes();
		output[56..64].copy_from_slice(&len_bytes);
		// data
		output[64..64 + alias.len()].copy_from_slice(&alias);

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	// ─── hasPrivateLink(string alias, bytes32 commitment) returns (bool) ─────
	//
	// Read-only query. Checks whether the alias has the given commitment
	// registered in its private links list (`PrivateChainLinks` storage).
	//
	// ABI input for `(string, bytes32)` — params = input[4..]:
	//   [0..32]  : offset pointer to the string (dynamic), relative to the start of params
	//   [32..64] : bytes32 commitment (static, direct value)
	//   at offset: uint256 length + UTF-8 bytes of the alias
	//
	// ABI return `bool`:
	//   32-byte slot, last byte = 1 (true) or 0 (false)
	fn has_private_link(input: &[u8]) -> PrecompileResult {
		let params = &input[4..];

		// We need at least 2 header slots (64 bytes)
		if params.len() < 64 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("hasPrivateLink: input too short".into()),
			});
		}

		// bytes32 commitment is in the static slot [32..64]
		let commitment: [u8; 32] = params[32..64].try_into().unwrap();

		// string alias — decode from the dynamic area indicated by the offset in [0..32]
		let alias_bytes = Self::decode_abi_string(params)?;

		let found = pallet_account_mapping::Pallet::<T>::runtime_api_has_private_link(
			alias_bytes,
			commitment,
		);

		// ABI encode bool: 32-byte slot
		let mut output = alloc::vec![0u8; 32];
		if found {
			output[31] = 1;
		}

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	// ─── Helpers ─────────────────────────────────────────────────────────────

	/// Decodes an ABI-encoded `string` into a `Vec<u8>`.
	/// Expects the calldata WITHOUT the 4-byte selector.
	fn decode_abi_string(params: &[u8]) -> Result<Vec<u8>, PrecompileFailure> {
		if params.len() < 64 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI: params too short".into()),
			});
		}
		let offset = U256::from_big_endian(&params[0..32]).low_u32() as usize;
		if offset + 32 > params.len() {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI: offset out of bounds".into()),
			});
		}
		let length = U256::from_big_endian(&params[offset..offset + 32]).low_u32() as usize;
		let data_start = offset + 32;
		if data_start + length > params.len() {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI: string data out of bounds".into()),
			});
		}
		Ok(params[data_start..data_start + length].to_vec())
	}
}
