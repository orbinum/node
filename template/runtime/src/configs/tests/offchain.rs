// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Unsigned transactions built by offchain code (GRANDPA equivocation reports)
//! must survive the wire as bare extrinsics carrying the same call.

use crate::{Runtime, RuntimeCall, UncheckedExtrinsic};
use frame_system::offchain::CreateBare;
use scale_codec::{Decode, Encode};
use sp_runtime::traits::ExtrinsicLike;

#[test]
fn bare_extrinsic_round_trips() {
	let call = RuntimeCall::System(frame_system::Call::remark {
		remark: vec![1, 2, 3],
	});
	let xt = <Runtime as CreateBare<frame_system::Call<Runtime>>>::create_bare(call.clone());

	let decoded = UncheckedExtrinsic::decode(&mut &xt.encode()[..]).expect("decodes");
	assert!(decoded.is_bare());
	assert_eq!(decoded.0.function, call);
}
