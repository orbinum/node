//! # ZK Primitives
//!
//! Native cryptographic primitives for Zero-Knowledge proofs.
//!
//! This crate provides the fundamental building blocks for privacy-preserving
//! transactions, without the heavy R1CS constraint system dependencies.
//!
//! ## Overview
//!
//! The primitives in this crate are used by:
//! - **Wallets**: Create notes, compute commitments, verify Merkle proofs
//! - **Runtime**: Validate public inputs, check Merkle roots
//! - **Tests**: Unit testing without full circuit dependencies
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    ZK PRIMITIVES                            │
//! │                    (3-Layer Architecture)                   │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  Layer 1: CORE (Foundational Types)                         │
//! │  ───────────────────────────────────                        │
//! │  • Bn254Fr - Base field element                             │
//! │  • Commitment - Strong type (prevents confusion)            │
//! │  • Nullifier - Strong type (prevents confusion)             │
//! │  • SpendingKey - Strong type with security semantics        │
//! │  • Constants: DEFAULT_TREE_DEPTH, MAX_TREE_DEPTH            │
//! │  • PrimitiveError - Error types                             │
//! │                                                             │
//! │  Layer 2: CRYPTO (Cryptographic Operations)                 │
//! │  ───────────────────────────────────────                    │
//! │  • hash: poseidon_hash_2, poseidon_hash_4                   │
//! │  • commitment: create_commitment, compute_nullifier         │
//! │  • merkle: compute_merkle_root, verify_merkle_proof         │
//! │                                                             │
//! │  Layer 3: MODELS (High-Level Abstractions)                  │
//! │  ──────────────────────────────────────                     │
//! │  • Note { value, asset_id, owner_pubkey, blinding }         │
//! │    - note.commitment() → Commitment                         │
//! │    - note.nullifier(&key) → Nullifier                       │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use fp_zk_primitives::models::note::Note;
//! use fp_zk_primitives::core::types::{Commitment, Nullifier, SpendingKey};
//! use fp_zk_primitives::crypto::commitment::{create_commitment, compute_nullifier};
//! use fp_zk_primitives::crypto::merkle::verify_merkle_proof;
//!
//! // Create a note
//! let note = Note::new(100, 0, owner_pubkey, blinding);
//!
//! // Get commitment (stored in Merkle tree)
//! let commitment = note.commitment();
//!
//! // When spending, compute nullifier
//! let nullifier = note.nullifier(&spending_key);
//!
//! // Verify Merkle proof
//! let is_valid = verify_merkle_proof(&commitment, &path, &indices, &root);
//! ```
//!
//! ## Features
//!
//! - `std` (default): Enables standard library features
//! - `substrate`: Enables parity_scale_codec and scale_info derives
//!
//! ## Compatibility
//!
//! All hash functions are compatible with circomlib/iden3, ensuring that
//! values computed here match those from Circom circuits.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// ============================================================================
// Modules (3-Layer Architecture)
// ============================================================================

/// Layer 1: Core types, constants, and errors
pub mod core;

/// Layer 2: Cryptographic operations
pub mod crypto;

/// Layer 3: High-level models
pub mod models;
