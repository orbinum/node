// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The keys behind an `OrbinumSignature`: each scheme's verification ([`sr25519`],
//! [`ed25519`], [`ecdsa`]) and the signer that names the account ([`signer`]).

pub(super) mod ecdsa;
pub(super) mod ed25519;
pub(super) mod signer;
pub(super) mod sr25519;
