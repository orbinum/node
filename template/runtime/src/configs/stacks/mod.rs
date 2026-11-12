// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! What Orbinum runs on top of the chain: the EVM ([`evm`]), the privacy stack
//! ([`privacy`]) and cross-chain messaging over ISMP ([`ismp`]).

pub mod evm;
pub mod ismp;
pub mod privacy;
