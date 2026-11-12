// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pallet's work, one concern per module: validating, charging for and
//! dispatching outgoing POSTs and GETs ([`outbound`]), the ISMP callbacks that
//! receive messages, GET responses and timeouts ([`inbound`]), and the
//! delivery-receipt keys a confirmation reads ([`receipts`]).

pub mod inbound;
pub mod outbound;
pub mod receipts;
