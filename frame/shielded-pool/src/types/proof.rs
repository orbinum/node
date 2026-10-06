//! The serialized Groth16 proof a pool call carries.

use frame_support::{BoundedVec, pallet_prelude::ConstU32};

/// Maximum byte length of a serialized proof. A compressed BN254 Groth16 proof
/// is 128 bytes; the bound leaves room without admitting unbounded input.
pub const MAX_PROOF_SIZE: u32 = 512;

/// A proof as a call carries it.
pub type Proof = BoundedVec<u8, ConstU32<MAX_PROOF_SIZE>>;
