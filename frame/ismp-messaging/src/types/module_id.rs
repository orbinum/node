// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The module id counterparties address this pallet by.

use frame_support::PalletId;
use pallet_ismp::pallet::ModuleId;

/// This pallet's ISMP module identifier — how counterparties address messages to us.
///
/// `ModuleId::from_bytes` infers the variant **from the length alone**: 8 bytes is a
/// pallet, 20 an EVM contract, 32 an account, anything else an error — so this must stay
/// exactly 8 bytes.
///
/// Wire format: changing it once messages are in flight orphans them.
pub const PALLET_ID: ModuleId = ModuleId::Pallet(PalletId(*b"orb/msgs"));

/// [`PALLET_ID`] as raw bytes, for the router's comparison and for `DispatchPost.from`.
pub const PALLET_ID_BYTES: &[u8] = b"orb/msgs";
