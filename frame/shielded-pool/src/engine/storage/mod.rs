// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Storage access — typed wrappers over every `StorageValue` / `StorageMap`.
//!
//! One module per logical domain, one repository struct in each. All functions
//! are static; no instance state. Keeping the raw storage items behind these
//! wrappers means the pallet body never names a `StorageMap` directly, so a
//! layout change stays contained here.

pub mod asset;
pub mod balance;
pub mod commitment;
pub mod merkle;
pub mod nullifier;
pub mod stats;

pub use asset::AssetRepository;
pub use balance::PoolBalanceRepository;
pub use commitment::CommitmentRepository;
pub use merkle::MerkleRepository;
pub use nullifier::NullifierRepository;
pub use stats::PoolStatsRepository;
