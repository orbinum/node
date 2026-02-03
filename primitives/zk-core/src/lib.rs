//! # Orbinum ZK Core
//!
//! Zero-Knowledge cryptographic primitives for privacy-preserving transactions.
//!

//!
//! - **Domain**: Value objects, entities, services, ports
//! - **Application**: Use cases, DTOs
//! - **Infrastructure**: Crypto adapters, repositories

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod application;
pub mod domain;
pub mod infrastructure;
