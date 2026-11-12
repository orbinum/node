// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Benchmarked weights for the runtime-local configurations that need their own:
//! `ismp-grandpa`, the curve25519 and SHA3-FIPS precompiles, and the upstream staking
//! pallets (staking-async, bags list, nomination pools) measured on this runtime.

pub mod ismp_grandpa;
pub mod pallet_bags_list;
pub mod pallet_evm_precompile_curve25519;
pub mod pallet_evm_precompile_sha3fips;
pub mod pallet_nomination_pools;
pub mod pallet_staking_async;
