//! Tests for pallet-relayer.
//!
//! Modules:
//! - `config_tests`          — MinRelayFee and AllowedSelectors governance
//! - `dispatch_info_tests`   — Pays::Yes + DispatchClass::Normal on register_relayer
//! - `registry_tests`        — EVM address ↔ AccountId binding lifecycle
//! - `ownership_proof_tests` — proof of key control, and which addresses count
//! - `cleanup_tests`         — `clear_relayer`, the validator-exit hook
//! - `fees_tests`            — relay fee accrual and consumption via RelayerInterface

#[cfg(test)]
pub mod cleanup_tests;
#[cfg(test)]
pub mod config_tests;
#[cfg(test)]
pub mod dispatch_info_tests;
#[cfg(test)]
pub mod fees_tests;
#[cfg(test)]
pub mod ownership_proof_tests;
#[cfg(test)]
pub mod registry_tests;
