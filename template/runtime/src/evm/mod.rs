// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The EVM's runtime-side pieces: its precompiles, how an H160 maps to an account, and
//! Ethereum transactions as self-contained extrinsics.

pub mod account;
pub mod precompiles;
pub mod self_contained;

#[cfg(test)]
mod tests;
