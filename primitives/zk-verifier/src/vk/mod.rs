//! # Verification Keys
//!
//! This module contains hardcoded verification keys for ZK circuits.
//! Keys are embedded at compile-time for no_std blockchain runtime.
//!
//! ## Available VKs
//!
//! - `transfer`: Private transfer circuit verification key
//! - `unshield`: Unshield circuit verification key
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_verifier::vk::{get_transfer_vk, get_unshield_vk};
//!
//! let vk = get_transfer_vk();
//! let vk_bytes = get_transfer_vk_bytes();
//! ```

pub mod registry;
pub mod transfer;
pub mod unshield;

// Re-export commonly used functions
pub use transfer::{get_vk as get_transfer_vk, get_vk_bytes as get_transfer_vk_bytes};
pub use unshield::{get_vk as get_unshield_vk, get_vk_bytes as get_unshield_vk_bytes};

// Re-export registry functions
pub use registry::{get_public_input_count, get_vk_by_circuit_id, validate_public_input_count};
