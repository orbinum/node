// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Who may validate: the admission rule ([`admission`]), the transaction extension
//! that refuses an inadmissible `staking.validate` before it costs a fee
//! ([`candidacy`]), the commission ceiling's clamp ([`commission`]), and the ban
//! an offence brings ([`offences`]).

// Benchmarks leave the snapshot filter out of staking's `TargetList`.
#[cfg_attr(feature = "runtime-benchmarks", allow(dead_code))]
pub(crate) mod admission;
pub mod candidacy;
pub(crate) mod commission;
pub(crate) mod offences;
