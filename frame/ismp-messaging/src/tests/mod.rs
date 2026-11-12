// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mock runtime ([`mock`]), the fixtures the tests share ([`util`]) and the
//! tests, grouped by concern as `engine` is.

mod inbound;
pub(crate) mod mock;
mod outbound;
mod pallet;
pub(crate) mod util;
