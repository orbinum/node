//! Circuit ID value object

/// Circuit identifier - uniquely identifies a ZK circuit
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct CircuitId(u32);

impl CircuitId {
	/// Transfer circuit ID
	pub const TRANSFER: Self = Self(1);

	/// Unshield circuit ID
	pub const UNSHIELD: Self = Self(2);

	/// Shield circuit ID
	pub const SHIELD: Self = Self(3);

	/// Disclosure circuit ID (selective disclosure)
	pub const DISCLOSURE: Self = Self(4);

	/// Create a new circuit ID
	pub fn new(value: u32) -> Self {
		Self(value)
	}

	/// Get the numeric value
	pub fn value(&self) -> u32 {
		self.0
	}

	/// Get a human-readable name for known circuits
	pub fn name(&self) -> Option<&'static str> {
		match *self {
			Self::TRANSFER => Some("Transfer"),
			Self::UNSHIELD => Some("Unshield"),
			Self::SHIELD => Some("Shield"),
			Self::DISCLOSURE => Some("Disclosure"),
			_ => None,
		}
	}
}

impl From<u32> for CircuitId {
	fn from(value: u32) -> Self {
		Self(value)
	}
}

impl From<CircuitId> for u32 {
	fn from(id: CircuitId) -> u32 {
		id.0
	}
}

impl core::fmt::Display for CircuitId {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
		if let Some(name) = self.name() {
			write!(f, "{}({})", name, self.0)
		} else {
			write!(f, "Circuit({})", self.0)
		}
	}
}
