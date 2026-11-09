//! The session side's record of each session's validators, and offence reports.

use crate::{AccountId, AhClient, Balance, Runtime, RuntimeEvent};

// Session history

impl pallet_session::historical::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	/// What ah-client records per validator: an empty exposure. Slashing reads
	/// the real one on the staking side.
	type FullIdentification = sp_staking::Exposure<AccountId, Balance>;
	type FullIdentificationOf = pallet_staking_async_ah_client::DefaultExposureOf<Self>;
}

// Offences

impl pallet_offences::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type IdentificationTuple = pallet_session::historical::IdentificationTuple<Self>;
	/// Bans each offender from validating, then hands the offence to ah-client,
	/// which disables the offender for the session and sends it to staking.
	type OnOffenceHandler = crate::staking::offences::BanOffenders<AhClient>;
}
