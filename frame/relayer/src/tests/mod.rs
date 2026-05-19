//! Tests for pallet-relayer.
//!
//! Modules:
//! - `config_tests`   — MinRelayFee and AllowedSelectors governance
//! - `registry_tests` — EVM address ↔ AccountId binding
//! - `fees_tests`     — relay fee accumulation, querying, and consumption via RelayerInterface

#[cfg(test)]
pub mod config_tests;
#[cfg(test)]
pub mod fees_tests;
#[cfg(test)]
pub mod registry_tests;
