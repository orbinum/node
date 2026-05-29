#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

use alloc::{boxed::Box, format, vec, vec::Vec};
use core::marker::PhantomData;

use scale_codec::Decode;

use fp_evm::{
	ExitError, ExitSucceed, Precompile, PrecompileFailure, PrecompileHandle, PrecompileOutput,
	PrecompileResult,
};
use frame_support::{dispatch::GetDispatchInfo, traits::ConstU32, BoundedVec};
use pallet_evm::{AddressMapping, GasWeightMapping};
use sp_core::{H160, U256};
use sp_runtime::traits::{Convert, Dispatchable};

// ─────────────────────────────────────────────────────────────────────────────
// ABI Function Selectors
//
// Computed as: bytes4(keccak256("functionName(argTypes)"))
// Verify with: cast sig "functionName(argTypes)"  (Foundry)
//
// ─── Read-only ───────────────────────────────────────────────────────────────
// resolveAlias(string)                          → 0xd03149ab
const SEL_RESOLVE_ALIAS: [u8; 4] = [0xd0, 0x31, 0x49, 0xab];
// getAliasOf(address)                           → 0x7a0ed62c
const SEL_GET_ALIAS_OF: [u8; 4] = [0x7a, 0x0e, 0xd6, 0x2c];
// hasPrivateLink(string,bytes32)               → 0x47e05c6c
const SEL_HAS_PRIVATE_LINK: [u8; 4] = [0x47, 0xe0, 0x5c, 0x6c];
//
// ─── State-changing: no arguments ────────────────────────────────────────────
// mapAccount()                                  → 0xdca49d0e
const SEL_MAP_ACCOUNT: [u8; 4] = [0xdc, 0xa4, 0x9d, 0x0e];
// unmapAccount()                                → 0x08f57367
const SEL_UNMAP_ACCOUNT: [u8; 4] = [0x08, 0xf5, 0x73, 0x67];
// releaseAlias()                                → 0x7fac359e
const SEL_RELEASE_ALIAS: [u8; 4] = [0x7f, 0xac, 0x35, 0x9e];
// cancelSale()                                  → 0x4d023ab9
const SEL_CANCEL_SALE: [u8; 4] = [0x4d, 0x02, 0x3a, 0xb9];
//
// ─── State-changing: with arguments ──────────────────────────────────────────
// registerAlias(string)                         → 0x2f8839c3
const SEL_REGISTER_ALIAS: [u8; 4] = [0x2f, 0x88, 0x39, 0xc3];
// transferAlias(address)                        → 0x5ac998e7
const SEL_TRANSFER_ALIAS: [u8; 4] = [0x5a, 0xc9, 0x98, 0xe7];
// buyAlias(string)                              → 0x1625df3a
const SEL_BUY_ALIAS: [u8; 4] = [0x16, 0x25, 0xdf, 0x3a];
// putAliasOnSale(uint256,address[])             → 0x32091192
const SEL_PUT_ALIAS_ON_SALE: [u8; 4] = [0x32, 0x09, 0x11, 0x92];
// removeChainLink(uint32)                       → 0x6f579c0c
const SEL_REMOVE_CHAIN_LINK: [u8; 4] = [0x6f, 0x57, 0x9c, 0x0c];
// addChainLink(uint32,bytes,bytes)              → 0x5f3e837c
const SEL_ADD_CHAIN_LINK: [u8; 4] = [0x5f, 0x3e, 0x83, 0x7c];
// registerPrivateLink(uint32,bytes32)           → 0xc04e98f4
const SEL_REGISTER_PRIVATE_LINK: [u8; 4] = [0xc0, 0x4e, 0x98, 0xf4];
// removePrivateLink(bytes32)                    → 0xdfd8b57e
const SEL_REMOVE_PRIVATE_LINK: [u8; 4] = [0xdf, 0xd8, 0xb5, 0x7e];
// revealPrivateLink(bytes32,bytes,bytes32,bytes)→ 0x4df1f33d
const SEL_REVEAL_PRIVATE_LINK: [u8; 4] = [0x4d, 0xf1, 0xf3, 0x3d];
// setAccountMetadata(bytes,bytes,bytes)         → 0x776cf9ff
const SEL_SET_METADATA: [u8; 4] = [0x77, 0x6c, 0xf9, 0xff];
//
// ─── Phase 3 helpers — composability with BalancesPrecompile ─────────────────
// isEvmSuffixAccount(bytes32)                   → 0x96e69f8a
const SEL_IS_EVM_SUFFIX: [u8; 4] = [0x96, 0xe6, 0x9f, 0x8a];
// toEvmAddress(bytes32)                         → 0x0f5b3052
const SEL_TO_EVM_ADDRESS: [u8; 4] = [0x0f, 0x5b, 0x30, 0x52];
// resolveAliasFull(string)                      → 0x2e40772b
const SEL_RESOLVE_ALIAS_FULL: [u8; 4] = [0x2e, 0x40, 0x77, 0x2b];
//
// ─── Phase 4 (Unification Plan Fase 2) — relay via chain link ────────────────
// dispatchAsLinkedAccount(bytes32,uint32,bytes,bytes,bytes) → 0x0630cef9
const SEL_DISPATCH_AS_LINKED: [u8; 4] = [0x06, 0x30, 0xce, 0xf9];
// ─────────────────────────────────────────────────────────────────────────────

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
	pallet_account_mapping::BalanceOf<T>: TryFrom<u128>,
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
			// ─── Read-only ───────────────────────────────────────────────────
			SEL_RESOLVE_ALIAS => Self::resolve_alias(&input),
			SEL_GET_ALIAS_OF => Self::get_alias_of(&input),
			SEL_HAS_PRIVATE_LINK => Self::has_private_link(&input),

			// ─── No-arg dispatches ───────────────────────────────────────────
			SEL_MAP_ACCOUNT => {
				Self::dispatch_call(handle, pallet_account_mapping::Call::<T>::map_account {})
			}
			SEL_UNMAP_ACCOUNT => {
				Self::dispatch_call(handle, pallet_account_mapping::Call::<T>::unmap_account {})
			}
			SEL_RELEASE_ALIAS => {
				Self::dispatch_call(handle, pallet_account_mapping::Call::<T>::release_alias {})
			}
			SEL_CANCEL_SALE => {
				Self::dispatch_call(handle, pallet_account_mapping::Call::<T>::cancel_sale {})
			}

			// ─── With-arg dispatches ─────────────────────────────────────────
			SEL_REGISTER_ALIAS => Self::register_alias(handle, &input),
			SEL_TRANSFER_ALIAS => Self::transfer_alias(handle, &input),
			SEL_BUY_ALIAS => Self::buy_alias(handle, &input),
			SEL_PUT_ALIAS_ON_SALE => Self::put_alias_on_sale(handle, &input),
			SEL_REMOVE_CHAIN_LINK => Self::remove_chain_link(handle, &input),
			SEL_ADD_CHAIN_LINK => Self::add_chain_link(handle, &input),
			SEL_REGISTER_PRIVATE_LINK => Self::register_private_link(handle, &input),
			SEL_REMOVE_PRIVATE_LINK => Self::remove_private_link(handle, &input),
			SEL_REVEAL_PRIVATE_LINK => Self::reveal_private_link(handle, &input),
			SEL_SET_METADATA => Self::set_account_metadata(handle, &input),

			// ─── Phase 3: composability helpers ─────────────────────────────
			SEL_IS_EVM_SUFFIX => Self::is_evm_suffix_account(&input),
			SEL_TO_EVM_ADDRESS => Self::to_evm_address(&input),
			SEL_RESOLVE_ALIAS_FULL => Self::resolve_alias_full(&input),

			// ─── Phase 4: relay via chain link ───────────────────────────────
			SEL_DISPATCH_AS_LINKED => Self::dispatch_as_linked_account(handle, &input),

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
	pallet_account_mapping::BalanceOf<T>: TryFrom<u128>,
{
	// ─────────────────────────────────────────────────────────────────────────
	// Dispatch helper
	// ─────────────────────────────────────────────────────────────────────────

	/// Dispatches any `pallet_account_mapping::Call` on behalf of the EVM caller.
	/// Records gas cost from the call's weight info before dispatching.
	fn dispatch_call(
		handle: &mut impl PrecompileHandle,
		call: pallet_account_mapping::Call<T>,
	) -> PrecompileResult {
		let runtime_call = <<T as frame_system::Config>::RuntimeCall as From<
			pallet_account_mapping::Call<T>,
		>>::from(call);
		let info = runtime_call.get_dispatch_info();
		let gas_cost = T::GasWeightMapping::weight_to_gas(info.total_weight());
		handle.record_cost(gas_cost)?;

		let caller_account: <T as frame_system::Config>::AccountId =
			T::AddressMapping::into_account_id(handle.context().caller).into();
		let origin =
			<<T as frame_system::Config>::RuntimeCall as Dispatchable>::RuntimeOrigin::from(Some(
				caller_account,
			));

		match runtime_call.dispatch(origin) {
			Ok(_) => Ok(PrecompileOutput {
				exit_status: ExitSucceed::Stopped,
				output: Default::default(),
			}),
			Err(e) => Err(PrecompileFailure::Error {
				exit_status: ExitError::Other(format!("{e:?}").into()),
			}),
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// State-changing: with arguments
	// ─────────────────────────────────────────────────────────────────────────

	/// registerAlias(string alias)
	///
	/// ABI params (input[4..]):
	///   [0..32]  uint256 offset → string data (dynamic)
	///   at offset: uint256 length + UTF-8 bytes of the alias
	fn register_alias(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let alias_bytes = Self::decode_abi_string(&input[4..])?;
		let bounded: pallet_account_mapping::AliasOf<T> =
			alias_bytes
				.try_into()
				.map_err(|_| PrecompileFailure::Error {
					exit_status: ExitError::Other("alias too long".into()),
				})?;
		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::register_alias { alias: bounded },
		)
	}

	/// transferAlias(address newOwner)
	///
	/// ABI params (input[4..]):
	///   [0..32]  address (20 bytes, right-justified in 32-byte slot)
	fn transfer_alias(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 32 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("transferAlias: input too short".into()),
			});
		}
		let h160 = H160::from_slice(&params[12..32]);
		let new_owner: <T as frame_system::Config>::AccountId =
			T::AddressMapping::into_account_id(h160).into();
		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::transfer_alias { new_owner },
		)
	}

	/// buyAlias(string alias)
	///
	/// Same ABI layout as registerAlias(string).
	fn buy_alias(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let alias_bytes = Self::decode_abi_string(&input[4..])?;
		let bounded: pallet_account_mapping::AliasOf<T> =
			alias_bytes
				.try_into()
				.map_err(|_| PrecompileFailure::Error {
					exit_status: ExitError::Other("alias too long".into()),
				})?;
		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::buy_alias { alias: bounded },
		)
	}

	/// putAliasOnSale(uint256 price, address[] allowedBuyers)
	///
	/// ABI params (input[4..]):
	///   [0..32]  uint256 price (static)
	///   [32..64] uint256 offset → address[] (dynamic)
	///   at offset: uint256 array_length, then N × 32-byte address slots
	///
	/// Empty array → public listing (no whitelist, allowed_buyers = None).
	fn put_alias_on_sale(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 64 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("putAliasOnSale: input too short".into()),
			});
		}

		// price
		let price_u128 = U256::from_big_endian(&params[0..32]).low_u128();
		let price = pallet_account_mapping::BalanceOf::<T>::try_from(price_u128).map_err(|_| {
			PrecompileFailure::Error {
				exit_status: ExitError::Other("putAliasOnSale: price overflow".into()),
			}
		})?;

		// address[] whitelist
		let arr_offset = U256::from_big_endian(&params[32..64]).low_u32() as usize;
		let buyers: Option<Vec<<T as frame_system::Config>::AccountId>> =
			if arr_offset + 32 > params.len() {
				None
			} else {
				let arr_len =
					U256::from_big_endian(&params[arr_offset..arr_offset + 32]).low_u32() as usize;
				if arr_len == 0 {
					None
				} else {
					let data_start = arr_offset + 32;
					if data_start + arr_len * 32 > params.len() {
						return Err(PrecompileFailure::Error {
							exit_status: ExitError::Other(
								"putAliasOnSale: whitelist out of bounds".into(),
							),
						});
					}
					let mut list = vec![];
					for i in 0..arr_len {
						let slot = data_start + i * 32;
						let addr = H160::from_slice(&params[slot + 12..slot + 32]);
						let account: <T as frame_system::Config>::AccountId =
							T::AddressMapping::into_account_id(addr).into();
						list.push(account);
					}
					Some(list)
				}
			};

		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::put_alias_on_sale {
				price,
				allowed_buyers: buyers,
			},
		)
	}

	/// removeChainLink(uint32 chainId)
	///
	/// ABI params (input[4..]):
	///   [0..32]  uint32 (value in last 4 bytes of slot)
	fn remove_chain_link(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let chain_id = Self::decode_u32(&input[4..])?;
		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::remove_chain_link { chain_id },
		)
	}

	/// addChainLink(uint32 chainId, bytes externalAddr, bytes signature)
	///
	/// ABI params (input[4..]) — mixed static + dynamic:
	///   [0..32]   uint32 chainId (static)
	///   [32..64]  uint256 offset → bytes externalAddr (dynamic)
	///   [64..96]  uint256 offset → bytes signature (dynamic)
	///   at each offset: uint256 length + raw bytes (zero-padded to 32-byte multiple)
	///
	/// Note: the signature scheme (Eip191 / Ed25519) is NOT passed here;
	///       the pallet looks it up from `SupportedChains` storage by chain_id.
	fn add_chain_link(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 96 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("addChainLink: input too short".into()),
			});
		}
		let chain_id = U256::from_big_endian(&params[0..32]).low_u32();
		let address = Self::decode_bytes_at_slot(params, 32)?;
		let signature = Self::decode_bytes_at_slot(params, 64)?;
		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::add_chain_link {
				chain_id,
				address,
				signature,
			},
		)
	}

	/// registerPrivateLink(uint32 chainId, bytes32 commitment)
	///
	/// ABI params (input[4..]):
	///   [0..32]  uint32 chain_id (padded)
	///   [32..64] bytes32 commitment (static)
	fn register_private_link(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 64 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("registerPrivateLink: input too short".into()),
			});
		}
		let chain_id = U256::from_big_endian(&params[0..32]).low_u32();
		let commitment: [u8; 32] = params[32..64].try_into().unwrap();
		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::register_private_link {
				chain_id,
				commitment,
			},
		)
	}

	/// removePrivateLink(bytes32 commitment)
	///
	/// ABI params (input[4..]):
	///   [0..32]  bytes32 commitment (static)
	fn remove_private_link(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 32 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("removePrivateLink: input too short".into()),
			});
		}
		let commitment: [u8; 32] = params[0..32].try_into().unwrap();
		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::remove_private_link { commitment },
		)
	}

	/// revealPrivateLink(bytes32 commitment, bytes address, bytes32 blinding, bytes signature)
	///
	/// ABI params (input[4..]) — mixed static + dynamic:
	///   [0..32]    bytes32 commitment (static)
	///   [32..64]   uint256 offset → bytes address (dynamic)
	///   [64..96]   bytes32 blinding (static)
	///   [96..128]  uint256 offset → bytes signature (dynamic)
	///   at each offset: uint256 length + raw bytes
	fn reveal_private_link(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 128 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("revealPrivateLink: input too short".into()),
			});
		}
		let commitment: [u8; 32] = params[0..32].try_into().unwrap();
		let address = Self::decode_bytes_at_slot(params, 32)?;
		let blinding: [u8; 32] = params[64..96].try_into().unwrap();
		let signature = Self::decode_bytes_at_slot(params, 96)?;
		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::reveal_private_link {
				commitment,
				address,
				blinding,
				signature,
			},
		)
	}

	/// setAccountMetadata(bytes displayName, bytes bio, bytes avatar)
	///
	/// ABI params (input[4..]) — all dynamic:
	///   [0..32]  uint256 offset → bytes displayName
	///   [32..64] uint256 offset → bytes bio
	///   [64..96] uint256 offset → bytes avatar
	///   at each offset: uint256 length + UTF-8 bytes
	///
	/// Empty bytes → field not changed (None). Max 128 bytes each.
	fn set_account_metadata(handle: &mut impl PrecompileHandle, input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 96 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("setAccountMetadata: input too short".into()),
			});
		}

		let raw_display = Self::decode_bytes_at_slot(params, 0)?;
		let raw_bio = Self::decode_bytes_at_slot(params, 32)?;
		let raw_avatar = Self::decode_bytes_at_slot(params, 64)?;

		// Converts raw bytes → Option<BoundedVec<u8, ConstU32<128>>>
		// Empty bytes → None (field unchanged).
		let to_opt_bounded =
			|v: Vec<u8>| -> Result<Option<BoundedVec<u8, ConstU32<128>>>, PrecompileFailure> {
				if v.is_empty() {
					Ok(None)
				} else {
					v.try_into()
						.map(Some)
						.map_err(|_| PrecompileFailure::Error {
							exit_status: ExitError::Other(
								"metadata field too long (max 128 bytes)".into(),
							),
						})
				}
			};

		let display_name = to_opt_bounded(raw_display)?;
		let bio = to_opt_bounded(raw_bio)?;
		let avatar = to_opt_bounded(raw_avatar)?;

		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::set_account_metadata {
				display_name,
				bio,
				avatar,
			},
		)
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Read-only queries
	// ─────────────────────────────────────────────────────────────────────────

	/// resolveAlias(string alias) returns (address owner, address evmAddress)
	///
	/// ABI return: two 32-byte address slots.
	/// Returns 64 zero bytes if the alias does not exist.
	fn resolve_alias(input: &[u8]) -> PrecompileResult {
		let alias_bytes = Self::decode_abi_string(&input[4..])?;

		let (owner_h160, evm_h160) = if let Some(record) =
			pallet_account_mapping::Pallet::<T>::runtime_api_resolve_alias(&alias_bytes)
		{
			let h = record.evm_address.unwrap_or(H160::zero());
			(h, h)
		} else {
			(H160::zero(), H160::zero())
		};

		let mut output = vec![0u8; 64];
		output[12..32].copy_from_slice(owner_h160.as_bytes());
		output[44..64].copy_from_slice(evm_h160.as_bytes());

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	/// getAliasOf(address evm) returns (bytes alias)
	///
	/// ABI return: offset (0x20) + length + alias bytes, zero-padded.
	/// Returns empty bytes if no alias is registered for the address.
	fn get_alias_of(input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 32 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("getAliasOf: input too short".into()),
			});
		}

		let evm_addr = H160::from_slice(&params[12..32]);
		let account: <T as frame_system::Config>::AccountId =
			T::AddressMapping::into_account_id(evm_addr).into();

		let alias = pallet_account_mapping::Pallet::<T>::runtime_api_get_alias_of(account)
			.unwrap_or_default();

		// ABI bytes: offset(32) + length + data (zero-padded to 32-byte multiple)
		let padded_len = (alias.len() + 31) & !31;
		let mut output = vec![0u8; 64 + padded_len];
		output[31] = 0x20; // offset = 0x20
		let len_bytes = (alias.len() as u64).to_be_bytes();
		output[56..64].copy_from_slice(&len_bytes);
		output[64..64 + alias.len()].copy_from_slice(&alias);

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	/// hasPrivateLink(string alias, bytes32 commitment) returns (bool)
	///
	/// ABI params (input[4..]):
	///   [0..32]  uint256 offset → string alias (dynamic)
	///   [32..64] bytes32 commitment (static)
	///
	/// Returns ABI-encoded bool (32-byte slot, last byte = 1 or 0).
	fn has_private_link(input: &[u8]) -> PrecompileResult {
		let params = &input[4..];
		if params.len() < 64 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("hasPrivateLink: input too short".into()),
			});
		}

		let commitment: [u8; 32] = params[32..64].try_into().unwrap();
		let alias_bytes = Self::decode_abi_string(params)?;

		let found = pallet_account_mapping::Pallet::<T>::runtime_api_has_private_link(
			alias_bytes,
			commitment,
		);

		let mut output = vec![0u8; 32];
		if found {
			output[31] = 1;
		}
		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	// ─────────────────────────────────────────────────────────────────────────
	// ABI decode helpers
	// ─────────────────────────────────────────────────────────────────────────

	/// Decodes a `uint32` from the first 32-byte slot of `params`.
	fn decode_u32(params: &[u8]) -> Result<u32, PrecompileFailure> {
		if params.len() < 32 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI: uint32 slot too short".into()),
			});
		}
		Ok(U256::from_big_endian(&params[0..32]).low_u32())
	}

	/// Decodes an ABI `bytes` (or `string`) value whose **offset pointer** lives
	/// at `slot_start` bytes within `params`.
	///
	/// Layout:
	///   `params[slot_start..slot_start+32]` → absolute offset (relative to params start)
	///   `params[offset..offset+32]`          → uint256 byte length
	///   `params[offset+32..]`                → raw bytes (zero-padded to 32-byte multiple)
	fn decode_bytes_at_slot(
		params: &[u8],
		slot_start: usize,
	) -> Result<Vec<u8>, PrecompileFailure> {
		if slot_start + 32 > params.len() {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI: slot out of bounds".into()),
			});
		}
		let offset = U256::from_big_endian(&params[slot_start..slot_start + 32]).low_u32() as usize;
		if offset + 32 > params.len() {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI: dynamic offset out of bounds".into()),
			});
		}
		let length = U256::from_big_endian(&params[offset..offset + 32]).low_u32() as usize;
		let data_start = offset + 32;
		if data_start + length > params.len() {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("ABI: bytes data out of bounds".into()),
			});
		}
		Ok(params[data_start..data_start + length].to_vec())
	}

	/// Decodes a top-level ABI-encoded `string` (or `bytes`) value.
	/// The offset pointer lives at slot 0 of `params` (i.e. input stripped of selector).
	fn decode_abi_string(params: &[u8]) -> Result<Vec<u8>, PrecompileFailure> {
		Self::decode_bytes_at_slot(params, 0)
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Phase 3: composability helpers
	// ─────────────────────────────────────────────────────────────────────────

	/// isEvmSuffixAccount(bytes32 accountId) → bool
	///
	/// Returns `true` if the 32-byte AccountId follows the `[H160 | 0x00×12]`
	/// suffix pattern, indicating a secp256k1 account created with OrbinumSignature.
	/// Pure computation — no storage lookup.
	fn is_evm_suffix_account(input: &[u8]) -> PrecompileResult {
		if input.len() < 36 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("isEvmSuffixAccount: input too short".into()),
			});
		}
		let account_bytes = &input[4..36];
		let is_suffix = account_bytes[20..].iter().all(|&b| b == 0);

		let mut output = vec![0u8; 32];
		output[31] = is_suffix as u8;
		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	/// toEvmAddress(bytes32 accountId) → address
	///
	/// For secp256k1 accounts (`[H160 | 0x00×12]` pattern): derives the H160
	/// implicitly — pure O(1) computation, no storage lookup.
	///
	/// For Sr25519/Ed25519 accounts: returns `address(0)`. Their EVM address
	/// is registered via `map_account` and is not derivable from the bytes32
	/// alone. Use `getAliasOf` or native Substrate RPCs instead.
	fn to_evm_address(input: &[u8]) -> PrecompileResult {
		if input.len() < 36 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("toEvmAddress: input too short".into()),
			});
		}
		let raw = &input[4..36];
		let is_suffix = raw[20..].iter().all(|&b| b == 0);

		let h160 = if is_suffix {
			H160::from_slice(&raw[..20])
		} else {
			H160::zero()
		};

		let mut output = vec![0u8; 32];
		output[12..32].copy_from_slice(h160.as_bytes());
		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	/// resolveAliasFull(string alias) → (bytes32 accountId32, address evmAddress, bool isEvmSuffix)
	///
	/// Extended version of `resolveAlias` that exposes the full `AccountId32` (bytes32)
	/// required by `BalancesPrecompile.transfer(bytes32, uint256)`, plus a flag that
	/// indicates whether the account is a secp256k1 implicit-mapping account.
	///
	/// ABI return layout (96 bytes):
	///   [0..32]   bytes32  accountId32   — AccountId32 bytes (secp256k1 only; zeros for Sr25519)
	///   [32..64]  address  evmAddress    — H160 (derived for secp256k1; from storage or zero for Sr25519)
	///   [64..96]  bool     isEvmSuffix   — true for secp256k1 OrbinumSignature accounts
	///
	/// Returns 96 zero bytes if the alias does not exist.
	///
	/// Note: for Sr25519/Ed25519 accounts, `accountId32` is zero — the AccountId32 is
	/// not derivable from the alias record without a native Substrate API call.
	fn resolve_alias_full(input: &[u8]) -> PrecompileResult {
		let alias_bytes = Self::decode_abi_string(&input[4..])?;

		let Some(record) =
			pallet_account_mapping::Pallet::<T>::runtime_api_resolve_alias(&alias_bytes)
		else {
			return Ok(PrecompileOutput {
				exit_status: ExitSucceed::Returned,
				output: vec![0u8; 96],
			});
		};

		let is_suffix = T::is_implicit_evm_account(&record.owner);

		// For secp256k1: derive H160 implicitly (always correct for suffix accounts).
		// For Sr25519/Ed25519: use the mapped evm_address from storage, or zero.
		let evm_h160 = if is_suffix {
			T::AccountIdToEvmAddress::convert(record.owner).unwrap_or(H160::zero())
		} else {
			record.evm_address.unwrap_or(H160::zero())
		};

		let mut output = vec![0u8; 96];
		// bytes32 accountId32 [0..32]: reconstructed from H160 for secp256k1 ([H160|0x00×12]).
		// For Sr25519/Ed25519: left as zeros (not derivable without AsRef<[u8;32]>).
		if is_suffix && evm_h160 != H160::zero() {
			output[0..20].copy_from_slice(evm_h160.as_bytes()); // suffix [20..32] stays zero
		}
		output[44..64].copy_from_slice(evm_h160.as_bytes()); // address (slot [32..64])
		output[95] = is_suffix as u8; // bool    (slot [64..96])

		Ok(PrecompileOutput {
			exit_status: ExitSucceed::Returned,
			output,
		})
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Phase 4: relay via chain link
	// ─────────────────────────────────────────────────────────────────────────

	/// dispatchAsLinkedAccount(bytes32 owner, uint32 chainId, bytes address, bytes signature, bytes call)
	///
	/// Relayer proxy: dispatches `call` as `owner`, verified by the external wallet
	/// registered as chain link `(chainId, address)` for that owner. The EVM caller
	/// (relayer) pays gas — only the external wallet's signature over the
	/// SCALE-encoded `call` payload is verified.
	///
	/// `call` must be **SCALE-encoded** `RuntimeCall` bytes. Produce off-chain via
	/// Polkadot.js (`api.createType('Call', ...).toHex()`) or `@polkadot/api`.
	///
	/// Note: chain_id == NativeEvmChainId (e.g. 2700 on testnet, 270 on mainnet)
	/// is rejected by the pallet with `UseNativeSignatureForEvmAccounts`.
	///
	/// ABI params (input[4..]) — mixed static + dynamic:
	///   [0..32]    bytes32 owner    (static — raw AccountId32, SCALE-encoded as 32 flat bytes)
	///   [32..64]   uint32  chainId  (static — value in last 4 bytes of slot)
	///   [64..96]   uint256 offset → bytes address   (dynamic — external chain address)
	///   [96..128]  uint256 offset → bytes signature  (dynamic — external wallet sig over SCALE(call))
	///   [128..160] uint256 offset → bytes call       (dynamic — SCALE-encoded RuntimeCall)
	fn dispatch_as_linked_account(
		handle: &mut impl PrecompileHandle,
		input: &[u8],
	) -> PrecompileResult {
		let params = &input[4..];
		// Minimum: 5 slots × 32 = 160 bytes
		if params.len() < 160 {
			return Err(PrecompileFailure::Error {
				exit_status: ExitError::Other("dispatchAsLinkedAccount: input too short".into()),
			});
		}

		// bytes32 owner → AccountId32
		// AccountId32 SCALE-encodes as 32 flat bytes (no length prefix).
		let owner =
			<T as frame_system::Config>::AccountId::decode(&mut &params[0..32]).map_err(|_| {
				PrecompileFailure::Error {
					exit_status: ExitError::Other(
						"dispatchAsLinkedAccount: invalid owner AccountId".into(),
					),
				}
			})?;

		// uint32 chainId (value in last 4 bytes of 32-byte ABI slot)
		let chain_id = u32::from_be_bytes(params[60..64].try_into().unwrap());

		// bytes address, signature, call — dynamic args with offset pointers at slots 2, 3, 4
		let address = Self::decode_bytes_at_slot(params, 64)?;
		let signature = Self::decode_bytes_at_slot(params, 96)?;
		let call_bytes = Self::decode_bytes_at_slot(params, 128)?;

		// SCALE-decode the inner RuntimeCall
		let inner_call =
			<T as pallet_account_mapping::Config>::RuntimeCall::decode(&mut &call_bytes[..])
				.map_err(|_| PrecompileFailure::Error {
					exit_status: ExitError::Other(
						"dispatchAsLinkedAccount: invalid SCALE-encoded call".into(),
					),
				})?;

		Self::dispatch_call(
			handle,
			pallet_account_mapping::Call::<T>::dispatch_as_linked_account {
				owner,
				chain_id,
				address,
				signature,
				call: Box::new(inner_call),
			},
		)
	}
}
