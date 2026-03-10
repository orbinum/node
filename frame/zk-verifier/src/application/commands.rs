//! Application commands - DTOs for use case inputs

use crate::domain::value_objects::CircuitId;
use alloc::vec::Vec;

/// Command to verify a proof
#[derive(Clone, Debug)]
pub struct VerifyProofCommand {
	pub circuit_id: CircuitId,
	pub version: Option<u32>,
	pub proof: Vec<u8>,
	pub public_inputs: Vec<Vec<u8>>,
}
