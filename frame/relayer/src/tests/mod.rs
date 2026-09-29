//! Tests for pallet-relayer.
//!
//! Modules:
//! - `config_tests`          — MinRelayFee and AllowedSelectors governance
//! - `dispatch_info_tests`   — Pays::Yes + DispatchClass::Normal on register_relayer
//! - `registry_tests`        — EVM address ↔ AccountId binding lifecycle
//! - `ownership_proof_tests` — proof of key control, and which addresses count
//! - `cleanup_tests`         — `clear_relayer`, the validator-exit hook
//! - `commit_tests`          — relay commits: recording, attribution, expiry
//! - `fees_tests`            — relay fee accrual and consumption via RelayerInterface

mod cleanup_tests;
mod commit_tests;
mod config_tests;
mod dispatch_info_tests;
mod fees_tests;
mod ownership_proof_tests;
mod registry_tests;
