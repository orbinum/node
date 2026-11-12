// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests by concern, grouped as `engine` is: admission (the rules, the
//! allowlist, bans) and the author version (declarations, the minimum and the
//! node version).

pub(crate) use crate::{ApprovedValidators, Error, Event};
pub(crate) use frame_support::{assert_noop, assert_ok};
pub(crate) use mock::*;

mod admission;
mod author_version;
pub(crate) mod mock;
