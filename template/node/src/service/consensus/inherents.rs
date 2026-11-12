// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Inherent data providers, for every path that builds or checks a block.
//!
//! Import and authoring must provide the same inherents: a block authored with data the
//! importer does not provide (or the other way round) fails its inherent check on every
//! other node. Each path gets its providers here:
//!
//! - [`AuraInherents::now`]: Aura import and authoring, at the current slot;
//! - [`AuraInherents::next_slot`]: the RPC's pending block, at the slot after the current
//!   one, the earliest the next block can be authored;
//! - [`ManualSealInherents`]: manual seal, with a timestamp that advances one slot per
//!   block.

use std::cell::RefCell;

use sp_consensus_aura::{inherents::InherentDataProvider as SlotProvider, SlotDuration};
use sp_inherents::{
	CreateInherentDataProviders, InherentData, InherentDataProvider, InherentIdentifier,
};
use sp_timestamp::InherentDataProvider as TimestampProvider;

use crate::author_version;
use orbinum_runtime::{opaque::Block, Hash};
use pallet_validator_set::author_version::InherentDataProvider as AuthorVersionProvider;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Which slot Aura's providers stand at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Clock {
	Now,
	NextSlot,
}

/// Providers for blocks under Aura.
#[derive(Clone, Copy, Debug)]
pub struct AuraInherents {
	slot_duration: SlotDuration,
	clock: Clock,
}

impl AuraInherents {
	/// At the current time and slot: import and authoring.
	pub fn now(slot_duration: SlotDuration) -> Self {
		Self {
			slot_duration,
			clock: Clock::Now,
		}
	}

	/// At the start of the next slot: the RPC's pending block.
	pub fn next_slot(slot_duration: SlotDuration) -> Self {
		Self {
			slot_duration,
			clock: Clock::NextSlot,
		}
	}

	fn timestamp(&self) -> TimestampProvider {
		let now = TimestampProvider::from_system_time();
		match self.clock {
			Clock::Now => now,
			Clock::NextSlot => TimestampProvider::new(
				(now.timestamp().as_millis() + self.slot_duration.as_millis()).into(),
			),
		}
	}
}

#[async_trait::async_trait]
impl CreateInherentDataProviders<Block, ()> for AuraInherents {
	type InherentDataProviders = (SlotProvider, TimestampProvider, AuthorVersionProvider);

	async fn create_inherent_data_providers(
		&self,
		_parent: Hash,
		_: (),
	) -> Result<Self::InherentDataProviders, Error> {
		let timestamp = self.timestamp();
		let slot = SlotProvider::from_timestamp_and_slot_duration(*timestamp, self.slot_duration);
		Ok((slot, timestamp, author_version::inherent_data_provider()))
	}
}

/// Providers for manual seal: no slot, and a timestamp one slot past the previous
/// block's, so the runtime sees time pass however fast blocks are sealed.
#[derive(Clone, Copy, Debug)]
pub struct ManualSealInherents;

#[async_trait::async_trait]
impl CreateInherentDataProviders<Block, ()> for ManualSealInherents {
	type InherentDataProviders = (MockTimestampProvider, AuthorVersionProvider);

	async fn create_inherent_data_providers(
		&self,
		_parent: Hash,
		_: (),
	) -> Result<Self::InherentDataProviders, Error> {
		Ok((
			MockTimestampProvider,
			author_version::inherent_data_provider(),
		))
	}
}

thread_local!(static TIMESTAMP: RefCell<u64> = const { RefCell::new(0) });

/// A timestamp that starts at 0 and advances one slot each time it is provided. Per
/// thread: manual seal runs on its own blocking thread.
pub struct MockTimestampProvider;

#[async_trait::async_trait]
impl InherentDataProvider for MockTimestampProvider {
	async fn provide_inherent_data(
		&self,
		inherent_data: &mut InherentData,
	) -> Result<(), sp_inherents::Error> {
		TIMESTAMP.with(|x| {
			*x.borrow_mut() += orbinum_runtime::SLOT_DURATION;
			inherent_data.put_data(sp_timestamp::INHERENT_IDENTIFIER, &*x.borrow())
		})
	}

	async fn try_handle_error(
		&self,
		_identifier: &InherentIdentifier,
		_error: &[u8],
	) -> Option<Result<(), sp_inherents::Error>> {
		// The timestamp pallet never reports an error.
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_timestamp::Timestamp;

	const SLOT: SlotDuration = SlotDuration::from_millis(6_000);

	async fn data(providers: impl InherentDataProvider) -> InherentData {
		let mut data = InherentData::new();
		providers.provide_inherent_data(&mut data).await.unwrap();
		data
	}

	fn timestamp(data: &InherentData) -> u64 {
		data.get_data::<Timestamp>(&sp_timestamp::INHERENT_IDENTIFIER)
			.unwrap()
			.unwrap()
			.into()
	}

	fn slot(data: &InherentData) -> u64 {
		data.get_data::<sp_consensus_aura::Slot>(&sp_consensus_aura::inherents::INHERENT_IDENTIFIER)
			.unwrap()
			.unwrap()
			.into()
	}

	#[test]
	fn aura_providers_carry_slot_timestamp_and_author_version() {
		futures::executor::block_on(async {
			let providers = AuraInherents::now(SLOT)
				.create_inherent_data_providers(Default::default(), ())
				.await
				.unwrap();
			let data = data(providers).await;
			assert_eq!(slot(&data), timestamp(&data) / SLOT.as_millis());
			assert_eq!(
				data.get_data(&pallet_validator_set::author_version::INHERENT_IDENTIFIER)
					.unwrap(),
				Some(author_version::AUTHOR_VERSION)
			);
		});
	}

	#[test]
	fn pending_providers_stand_one_slot_ahead() {
		futures::executor::block_on(async {
			let now = data(
				AuraInherents::now(SLOT)
					.create_inherent_data_providers(Default::default(), ())
					.await
					.unwrap(),
			)
			.await;
			let next = data(
				AuraInherents::next_slot(SLOT)
					.create_inherent_data_providers(Default::default(), ())
					.await
					.unwrap(),
			)
			.await;
			let ahead = timestamp(&next) - timestamp(&now);
			assert!(
				(SLOT.as_millis()..SLOT.as_millis() + 1_000).contains(&ahead),
				"{ahead}"
			);
			assert!(slot(&next) > slot(&now));
		});
	}

	#[test]
	fn manual_seal_timestamp_advances_one_slot_per_block_without_a_slot() {
		futures::executor::block_on(async {
			let first = data(
				ManualSealInherents
					.create_inherent_data_providers(Default::default(), ())
					.await
					.unwrap(),
			)
			.await;
			let second = data(
				ManualSealInherents
					.create_inherent_data_providers(Default::default(), ())
					.await
					.unwrap(),
			)
			.await;
			assert_eq!(
				timestamp(&second) - timestamp(&first),
				orbinum_runtime::SLOT_DURATION
			);
			assert!(first
				.get_data::<sp_consensus_aura::Slot>(
					&sp_consensus_aura::inherents::INHERENT_IDENTIFIER
				)
				.unwrap()
				.is_none());
		});
	}
}
