//! Runtime-level storage migrations, run by `Executive` on upgrade (`Migrations`).

mod nominators_unslashable;
mod precompile_code;
#[cfg(test)]
mod tests;

pub use nominators_unslashable::NominatorsUnslashable;
pub use precompile_code::PrecompileCode;

/// Runs on upgrade, oldest first. Drop an entry once every live chain has passed its
/// version: a migration that can no longer run could be re-armed by mistake.
pub type Migrations = (PrecompileCode, NominatorsUnslashable);

use crate::Runtime;
use frame_support::weights::Weight;

fn db_weight(reads: u64, writes: u64) -> Weight {
	<Runtime as frame_system::Config>::DbWeight::get().reads_writes(reads, writes)
}
