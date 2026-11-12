// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pallet's logic, one concern per module: who may validate
//! ([`admission`]: the rules, the allowlist and bans), the node version each
//! block author declares and the minimum it must meet ([`author_version`]),
//! and the invariants (`invariants`, for `try_state` and tests).

pub mod admission;
pub mod author_version;
#[cfg(any(feature = "try-runtime", test))]
mod invariants;
