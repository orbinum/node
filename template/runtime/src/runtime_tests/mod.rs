//! Runtime-level tests, one module per concern.

mod accounts;
mod block_author;
mod host_functions;
mod metadata_hash;
mod precompile_code;
mod weights;

use sp_io::TestExternalities;

fn with_ext<R>(run: impl FnOnce() -> R) -> R {
	TestExternalities::default().execute_with(run)
}
