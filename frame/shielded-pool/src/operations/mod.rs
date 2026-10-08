//! Business operations for the shielded pool.
//!
//! This is the single application entrypoint used by the pallet extrinsics.
//! Each module owns one workflow and coordinates domain logic, repositories,
//! and infrastructure services.

pub mod assets;
pub mod fees;
pub mod private_transfer;
pub mod shield;
pub mod statement;
pub mod unshield;

use crate::pallet::{Call, Config};
use frame_support::pallet_prelude::DispatchResult;
use private_transfer::TransferRequest;
use sp_std::vec::Vec;
use unshield::UnshieldRequest;

/// A spend call, unpacked. Built by everything that reads a spend from its call
/// rather than its arguments — pool admission and relay commits — so they all
/// see the same request the extrinsic executes.
pub enum SpendRequest<T: Config> {
	Transfer(TransferRequest<T>),
	Unshield(UnshieldRequest<T>),
}

impl<T: Config> SpendRequest<T> {
	/// The proof and request of a `private_transfer` or `unshield` call, `None`
	/// for any other call.
	pub fn from_call(call: &Call<T>) -> Option<(Vec<u8>, Self)> {
		Some(match call.clone() {
			Call::private_transfer {
				proof,
				merkle_roots,
				nullifiers,
				commitments,
				encrypted_memos,
				asset_id,
				fee,
				circuit_version,
			} => (
				proof.into_inner(),
				Self::Transfer(TransferRequest {
					merkle_roots,
					nullifiers,
					commitments,
					memos: encrypted_memos,
					asset_id,
					fee,
					circuit_version,
				}),
			),
			Call::unshield {
				proof,
				merkle_root,
				nullifier,
				asset_id,
				amount,
				recipient,
				fee,
				change_commitment,
				change_encrypted_memo,
				circuit_version,
			} => (
				proof.into_inner(),
				Self::Unshield(UnshieldRequest {
					merkle_root,
					nullifier,
					asset_id,
					amount,
					recipient,
					fee,
					change_commitment,
					change_memo: change_encrypted_memo,
					circuit_version,
				}),
			),
			_ => return None,
		})
	}
}

/// Require `check` to accept the proof. Compiled out under
/// `skip-proof-verification`, where every proof is taken as valid.
#[cfg_attr(
	feature = "skip-proof-verification",
	allow(clippy::extra_unused_type_parameters)
)]
pub(crate) fn ensure_valid_proof<T: Config>(
	check: impl FnOnce() -> Result<bool, sp_runtime::DispatchError>,
) -> DispatchResult {
	#[cfg(not(feature = "skip-proof-verification"))]
	frame_support::ensure!(check()?, crate::pallet::Error::<T>::ProofVerificationFailed);
	#[cfg(feature = "skip-proof-verification")]
	let _ = check;
	Ok(())
}
