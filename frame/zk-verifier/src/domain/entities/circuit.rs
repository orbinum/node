//! Circuit entity

use crate::domain::value_objects::CircuitId;

/// ZK Circuit metadata
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Circuit {
	id: CircuitId,
	name: Option<&'static str>,
}

impl Circuit {
	/// Create a new circuit
	pub fn new(id: CircuitId) -> Self {
		let name = id.name();
		Self { id, name }
	}

	/// Get the circuit ID
	pub fn id(&self) -> CircuitId {
		self.id
	}

	/// Get the circuit name if available
	pub fn name(&self) -> Option<&'static str> {
		self.name
	}

	/// Check if this is a known circuit
	pub fn is_known(&self) -> bool {
		self.name.is_some()
	}
}
