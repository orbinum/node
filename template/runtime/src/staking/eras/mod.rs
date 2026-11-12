// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Each era's course: the session and staking sides' direct calls ([`local_relay`]),
//! recovery from a plan that cannot start ([`recovery`]), automatic payment of the
//! closed eras ([`payouts`]) and the removal of their data ([`pruning`]).

pub(crate) mod local_relay;
pub(crate) mod payouts;
pub(crate) mod pruning;
pub(crate) mod recovery;
