//! # Circuit Constants
//!
//! Immutable constants for ZK circuits and verification.
//!
//! These values are hardcoded because:
//! - Circuit IDs must be consistent across runtime and wallets
//! - Public input counts are circuit-specific and immutable
//! - Verification costs are estimated from on-chain benchmarks

/// Circuit identifier for transfer operations
/// Used to lookup the correct verification key at runtime
pub const CIRCUIT_ID_TRANSFER: u8 = 1;

/// Circuit identifier for unshield (withdraw) operations
/// Used to lookup the correct verification key at runtime
pub const CIRCUIT_ID_UNSHIELD: u8 = 2;

/// Number of public inputs for the transfer circuit
/// Public inputs: [merkle_root, nullifier1, nullifier2, commitment1, commitment2]
pub const TRANSFER_PUBLIC_INPUTS: usize = 5;

/// Number of public inputs for the unshield circuit
/// Public inputs: [merkle_root, nullifier, recipient, amount]
pub const UNSHIELD_PUBLIC_INPUTS: usize = 4;

/// Base cost for Groth16 verification (pairing operations)
/// This is a reasonable default that can be overridden in runtime configuration
pub const BASE_VERIFICATION_COST: u64 = 100_000;

/// Cost per public input (scalar multiplication)
pub const PER_INPUT_COST: u64 = 10_000;

/// Maximum number of public inputs supported
pub const MAX_PUBLIC_INPUTS: usize = 32;
