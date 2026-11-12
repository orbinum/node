// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The chain itself: FRAME's system, fees and sudo ([`system`]), block production and
//! finality ([`consensus`]), and who may perform each privileged action
//! ([`governance`]).

pub mod consensus;
pub mod governance;
pub mod system;
