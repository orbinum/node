//! Application commands - DTOs for use case inputs

use crate::domain::value_objects::{CircuitId, ProofSystem};
use alloc::vec::Vec;

/// Command to register a verification key
#[derive(Clone, Debug)]
pub struct RegisterVkCommand {
	pub circuit_id: CircuitId,
	pub version: u32,
	pub data: Vec<u8>,
	pub system: ProofSystem,
}

/// Command to remove a verification key
#[derive(Clone, Copy, Debug)]
pub struct RemoveVkCommand {
	pub circuit_id: CircuitId,
	pub version: Option<u32>, // None for all? or just one? Usually one.
}

/// Command to verify a proof
#[derive(Clone, Debug)]
pub struct VerifyProofCommand {
	pub circuit_id: CircuitId,
	pub version: Option<u32>,
	pub proof: Vec<u8>,
	pub public_inputs: Vec<Vec<u8>>,
}

/// Command to set the active version for a circuit
#[derive(Clone, Copy, Debug)]
pub struct SetActiveVersionCommand {
	pub circuit_id: CircuitId,
	pub version: u32,
}
