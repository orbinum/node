//! # orbinum-zk-circuits
//!
//! Zero-Knowledge R1CS circuits and gadgets following Clean Architecture + DDD.
//!
//! This crate provides R1CS circuits for Zero-Knowledge proofs in the Orbinum blockchain,
//! organized in layers that separate concerns and dependencies following Domain-Driven Design principles.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   Application Layer                         │
//! │  Use Cases: TransferCircuit, UnshieldCircuit                │
//! │  DTOs: PublicInputs, WitnessData                            │
//! │  - Orchestrates domain + infrastructure                     │
//! └────────────────────────┬────────────────────────────────────┘
//!                          │ depends on
//! ┌────────────────────────▼────────────────────────────────────┐
//! │                   Domain Layer                              │
//! │  Value Objects: WitnessValue, PublicInput, TreeDepth        │
//! │  Services: CircuitValidator                                 │
//! │  Ports: ConstraintSystem, HashGadget                        │
//! │  - Pure business logic, no external dependencies            │
//! └────────────────────────┬────────────────────────────────────┘
//!                          │ implemented by
//! ┌────────────────────────▼────────────────────────────────────┐
//! │                   Infrastructure Layer                      │
//! │  Gadgets: Poseidon, Merkle, Commitment, Nullifier           │
//! │  Adapters: native_crypto (zk-core bridge)                   │
//! │  - Concrete R1CS implementations using arkworks             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## DDD Strategic Design
//!
//! This crate represents the **Circuit Bounded Context** within the ZK domain.
//!
//! - **Ubiquitous Language**: Witness, PublicInput, Commitment, Nullifier, Merkle Path
//! - **Aggregates**: Circuit (maintains constraint system invariants)
//! - **Value Objects**: Immutable primitives (WitnessValue, TreeDepth)
//! - **Domain Services**: CircuitValidator (stateless validation logic)
//! - **Ports**: Abstract interfaces for external dependencies
//!
//! ## Use Cases
//!
//! - **Circuit Development**: Build and test ZK circuits off-chain
//! - **Proof Generation**: Generate proofs for private transactions
//! - **Testing**: Integration tests with full constraint systems
//!
//! The runtime only needs `orbinum-zk-verifier` for proof verification.
//!
//! ## Modules
//!
//! ### Domain Layer
//! - [`domain::value_objects`]: Core immutable types (WitnessValue, TreeDepth)
//! - [`domain::services`]: Business logic (CircuitValidator)
//! - [`domain::ports`]: Abstract interfaces (ConstraintSystem, HashGadget)
//!
//! ### Infrastructure Layer
//! - [`infrastructure::gadgets::poseidon`]: Poseidon hash gadget
//! - [`infrastructure::gadgets::merkle`]: Merkle tree verification gadget
//! - [`infrastructure::gadgets::commitment`]: Commitment/nullifier gadgets
//! - [`infrastructure::native_crypto`]: Bridge to native crypto operations
//!
//! ### Application Layer
//! - [`application::circuits::note`]: Note commitment circuits
//! - [`application::circuits::transfer`]: Private transfer circuit (use case)
//! - [`application::dto`]: Data Transfer Objects (PublicInputs, WitnessData)
//!
//! ## Example
//!
//! ```rust,ignore
//! use orbinum_zk_circuits::application::dto::{TransferWitness, TransferPublicInputs};
//! use orbinum_zk_circuits::application::circuits::transfer::TransferCircuit;
//! use orbinum_zk_circuits::domain::services::CircuitValidator;
//!
//! // Validate witness data (domain service)
//! witness.validate()?;
//! CircuitValidator::validate_value_balance(&input_vals, &output_vals)?;
//!
//! // Create circuit (application use case)
//! let circuit = TransferCircuit::new(witness, public_inputs);
//!
//! // Generate proof
//! let proof = generate_proof(&proving_key, circuit)?;
//! ```
//!
//! ## Features
//!
//! - `std` (default): Standard library support

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ============================================================================
// Type Aliases
// ============================================================================

/// BN254 base field element (used throughout circuits)
pub use ark_bn254::Fr as Bn254Fr;

// ============================================================================
// Clean Architecture Layers
// ============================================================================

pub mod application;
pub mod domain;
pub mod infrastructure;
