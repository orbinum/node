//! Runtime-level storage migrations, run by `Executive` on upgrade (`Migrations`).

mod precompile_code;

pub use precompile_code::PrecompileCode;

use crate::Runtime;
use frame_support::weights::Weight;

fn db_weight(reads: u64, writes: u64) -> Weight {
	<Runtime as frame_system::Config>::DbWeight::get().reads_writes(reads, writes)
}
