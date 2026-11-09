//! Benchmarked weights for the runtime-local configurations that need their own:
//! `ismp-grandpa` and the curve25519 and SHA3-FIPS precompiles.

pub mod ismp_grandpa;
pub mod pallet_evm_precompile_curve25519;
pub mod pallet_evm_precompile_sha3fips;
