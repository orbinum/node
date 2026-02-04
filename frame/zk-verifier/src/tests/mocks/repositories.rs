//! Mock implementations for testing

use crate::{
	application::errors::ApplicationError,
	domain::{
		entities::{Proof, VerificationKey},
		errors::DomainError,
		repositories::{StatisticsRepository, VerificationKeyRepository},
		services::ProofValidator,
		value_objects::{CircuitId, PublicInputs},
	},
};
use alloc::vec::Vec;
use core::cell::RefCell;

/// Mock VK Repository for testing
pub struct MockVkRepository {
	storage: RefCell<Vec<(CircuitId, u32, VerificationKey)>>,
	active_versions: RefCell<Vec<(CircuitId, u32)>>,
}

impl MockVkRepository {
	pub fn new() -> Self {
		Self {
			storage: RefCell::new(Vec::new()),
			active_versions: RefCell::new(Vec::new()),
		}
	}

	pub fn with_vk(circuit_id: CircuitId, vk: VerificationKey) -> Self {
		let repo = Self::new();
		repo.storage.borrow_mut().push((circuit_id, 1, vk));
		repo.active_versions.borrow_mut().push((circuit_id, 1));
		repo
	}
}

impl VerificationKeyRepository for MockVkRepository {
	type Error = ApplicationError;

	fn find(
		&self,
		circuit_id: CircuitId,
		version: u32,
	) -> Result<Option<VerificationKey>, Self::Error> {
		Ok(self
			.storage
			.borrow()
			.iter()
			.find(|(id, v, _)| *id == circuit_id && *v == version)
			.map(|(_, _, vk)| vk.clone()))
	}

	fn save(
		&self,
		circuit_id: CircuitId,
		version: u32,
		vk: VerificationKey,
	) -> Result<(), Self::Error> {
		self.storage.borrow_mut().push((circuit_id, version, vk));
		Ok(())
	}

	fn delete(&self, circuit_id: CircuitId, version: u32) -> Result<(), Self::Error> {
		self.storage
			.borrow_mut()
			.retain(|(id, v, _)| *id != circuit_id || *v != version);
		Ok(())
	}

	fn exists(&self, circuit_id: CircuitId, version: u32) -> bool {
		self.storage
			.borrow()
			.iter()
			.any(|(id, v, _)| *id == circuit_id && *v == version)
	}

	fn list_all(&self) -> Result<Vec<(CircuitId, u32, VerificationKey)>, Self::Error> {
		Ok(self.storage.borrow().clone())
	}

	fn get_active_version(&self, id: CircuitId) -> Result<u32, Self::Error> {
		self.active_versions
			.borrow()
			.iter()
			.find(|(c_id, _)| *c_id == id)
			.map(|(_, v)| *v)
			.ok_or(ApplicationError::CircuitNotFound)
	}

	fn set_active_version(&self, id: CircuitId, version: u32) -> Result<(), Self::Error> {
		// Verify it exists first
		if !self.exists(id, version) {
			return Err(ApplicationError::CircuitNotFound);
		}

		let mut versions = self.active_versions.borrow_mut();
		if let Some(entry) = versions.iter_mut().find(|(c_id, _)| *c_id == id) {
			entry.1 = version;
		} else {
			versions.push((id, version));
		}
		Ok(())
	}
}

/// Mock Statistics Repository
pub struct MockStatisticsRepository {
	success_count: RefCell<u32>,
	failure_count: RefCell<u32>,
}

impl MockStatisticsRepository {
	pub fn new() -> Self {
		Self {
			success_count: RefCell::new(0),
			failure_count: RefCell::new(0),
		}
	}

	#[allow(dead_code)]
	pub fn success_count(&self) -> u32 {
		*self.success_count.borrow()
	}

	#[allow(dead_code)]
	pub fn failure_count(&self) -> u32 {
		*self.failure_count.borrow()
	}
}

impl StatisticsRepository for MockStatisticsRepository {
	type Error = ApplicationError;

	fn increment_verifications(
		&self,
		_circuit_id: CircuitId,
		_version: u32,
	) -> Result<(), Self::Error> {
		Ok(())
	}

	fn increment_successes(
		&self,
		_circuit_id: CircuitId,
		_version: u32,
	) -> Result<(), Self::Error> {
		*self.success_count.borrow_mut() += 1;
		Ok(())
	}

	fn increment_failures(&self, _circuit_id: CircuitId, _version: u32) -> Result<(), Self::Error> {
		*self.failure_count.borrow_mut() += 1;
		Ok(())
	}

	fn get_stats(
		&self,
		_circuit_id: CircuitId,
		_version: u32,
	) -> Result<crate::domain::Statistics, Self::Error> {
		Ok(crate::domain::Statistics {
			total_verifications: 0,
			successful_verifications: *self.success_count.borrow() as u64,
			failed_verifications: *self.failure_count.borrow() as u64,
		})
	}
}

/// Mock Proof Validator
pub struct MockProofValidator {
	should_succeed: bool,
}

impl MockProofValidator {
	pub fn always_valid() -> Self {
		Self {
			should_succeed: true,
		}
	}

	pub fn always_invalid() -> Self {
		Self {
			should_succeed: false,
		}
	}
}

impl ProofValidator for MockProofValidator {
	fn verify(
		&self,
		_vk: &VerificationKey,
		_proof: &Proof,
		_public_inputs: &PublicInputs,
	) -> Result<bool, DomainError> {
		Ok(self.should_succeed)
	}
}
