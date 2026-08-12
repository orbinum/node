// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Tests for the relay's admission gate.
//!
//! Split by intent: [`validation`] covers the branches a well-formed request
//! takes, [`adversarial`] covers what a hostile caller can send over the
//! unauthenticated RPC and asserts the relay rejects rather than panics.

mod adversarial;
mod validation;
