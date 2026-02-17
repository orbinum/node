//! Tests module
//!
//! Organizes all tests following Clean Architecture principles.
//!
//! ## Structure
//!
//! - `helpers/`: Common test utilities and sample data generators
//! - `unit/`: Unit tests for individual components and types
//! - `integration/`: Integration tests for full use case flows
//!
//! ## Test Categories
//!
//! ### Integration Tests
//! - Shield operations (deposits)
//! - Private transfers
//! - Unshield operations (withdrawals)
//! - Audit and disclosure workflows
//! - Multi-asset support
//!
//! ### Unit Tests
//! - Merkle tree operations
//! - Type definitions and conversions
//! - Encrypted memo handling
//! - Pool account management
//! - Historic root tracking

// Test helpers and utilities
pub mod helpers;

// Unit tests
pub mod unit {
	// Domain tests
	pub mod domain;

	// Application tests
	pub mod application;

	// Infrastructure tests
	pub mod infrastructure;
}

// Integration tests
pub mod integration {
	pub mod audit_tests;
	pub mod invalid_proof_tests;
	pub mod multi_asset_tests;
	pub mod private_transfer_tests;
	pub mod shield_batch_tests;
	pub mod shield_tests;
	pub mod unshield_tests;
}
