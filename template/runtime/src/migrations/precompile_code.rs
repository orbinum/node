//! Code at the Orbinum precompile addresses, for a chain created before genesis
//! set it.

use super::db_weight;
use crate::Runtime;
use frame_support::{traits::OnRuntimeUpgrade, weights::Weight};

#[cfg(feature = "try-runtime")]
use alloc::vec::Vec;

/// Stores [`PRECOMPILE_CODE`](crate::precompiles::PRECOMPILE_CODE) at every
/// precompile that should carry it and has none, as genesis does for a new
/// chain. Idempotent: an address that already holds code is left alone.
pub struct PrecompileCode;

impl OnRuntimeUpgrade for PrecompileCode {
	fn on_runtime_upgrade() -> Weight {
		let mut reads = 0u64;
		let mut written = 0u64;
		for address in crate::precompiles::FrontierPrecompiles::<Runtime>::addresses_with_code() {
			reads += 1;
			if pallet_evm::AccountCodes::<Runtime>::contains_key(address) {
				continue;
			}
			// Only an inner-create origin check can fail, and none is passed.
			let _ = pallet_evm::Pallet::<Runtime>::create_account(
				address,
				crate::precompiles::PRECOMPILE_CODE.to_vec(),
				None,
			);
			written += 1;
		}
		log::info!(target: "runtime::migrations", "stored code at {written} precompile address(es)");
		// Per write: the account's providers read and write, the code and its metadata.
		db_weight(reads.saturating_add(written), written.saturating_mul(3))
	}

	#[cfg(feature = "try-runtime")]
	fn post_upgrade(_state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
		frame_support::ensure!(
			crate::precompiles::FrontierPrecompiles::<Runtime>::addresses_with_code()
				.all(|a| !pallet_evm::AccountCodes::<Runtime>::get(a).is_empty()),
			"a precompile address has no code"
		);
		Ok(())
	}
}
