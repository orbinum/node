// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The upgrade migrations, run on the presets.
//!
//! - `precompile_code`: code stored at Orbinum's precompile addresses.
//! - `nominators_unslashable`: spec 22 stops slashing nominators.

mod nominators_unslashable;
mod precompile_code;
