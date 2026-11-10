//! Runs blocks as `frame-executive` does, and the chain to a session or era.

use crate::{
	configs::{consensus::Period, system::BlockWeights},
	AllPalletsWithSystem, BlockNumber, Runtime, RuntimeCall, RuntimeOrigin, Session, System,
	SLOT_DURATION,
};
use frame_executive::OnInitializeWithWeightRegistration;
use frame_support::{
	dispatch::{DispatchClass, GetDispatchInfo},
	traits::{DisabledValidators, OnFinalize, OnIdle, OnPoll},
	weights::WeightMeter,
};
use scale_codec::Encode;
use sp_runtime::{traits::Dispatchable, Digest, DigestItem};

/// The first slot from block `n` on that is later than the current one and
/// whose author is not disabled: Aura refuses blocks from disabled authors.
fn next_slot(n: BlockNumber) -> Option<u64> {
	let authorities = pallet_aura::Authorities::<Runtime>::decode_len().unwrap_or(0) as u64;
	if authorities == 0 {
		return None;
	}
	let mut slot = u64::from(n).max(u64::from(pallet_aura::CurrentSlot::<Runtime>::get()) + 1);
	while <Session as DisabledValidators>::is_disabled((slot % authorities) as u32) {
		slot += 1;
	}
	Some(slot)
}

/// Runs block `n` as `frame-executive` does: `on_initialize` (an Aura
/// pre-digest makes the slot's validator its author, which earns era points),
/// the timestamp inherent, `on_poll` with the weight left, `extrinsics`,
/// `on_idle` and `on_finalize`. Blocks may be skipped; events accumulate.
pub(crate) fn run_block_with(n: BlockNumber, extrinsics: impl FnOnce()) {
	let max = BlockWeights::get().max_block;
	let slot = next_slot(n);
	let digest = Digest {
		logs: slot
			.map(|slot| {
				DigestItem::PreRuntime(
					sp_consensus_aura::AURA_ENGINE_ID,
					sp_consensus_aura::Slot::from(slot).encode(),
				)
			})
			.into_iter()
			.collect(),
	};
	System::set_block_number(n - 1);
	System::initialize(&n, &Default::default(), &digest);
	System::register_extra_weight_unchecked(
		BlockWeights::get().base_block,
		DispatchClass::Mandatory,
	);
	<AllPalletsWithSystem as OnInitializeWithWeightRegistration<Runtime>>::on_initialize_with_weight_registration(n);
	System::note_finished_initialize();

	let now = slot.unwrap_or(u64::from(n)) * SLOT_DURATION;
	let timestamp = RuntimeCall::Timestamp(pallet_timestamp::Call::set { now });
	let info = timestamp.get_dispatch_info();
	timestamp
		.dispatch(RuntimeOrigin::none())
		.expect("timestamp inherent");
	System::register_extra_weight_unchecked(info.total_weight(), DispatchClass::Mandatory);
	System::note_inherents_applied();

	let mut meter = WeightMeter::with_limit(max.saturating_sub(System::block_weight().total()));
	<AllPalletsWithSystem as OnPoll<BlockNumber>>::on_poll(n, &mut meter);
	System::register_extra_weight_unchecked(meter.consumed(), DispatchClass::Mandatory);

	extrinsics();

	let idle = <AllPalletsWithSystem as OnIdle<BlockNumber>>::on_idle(
		n,
		max.saturating_sub(System::block_weight().total()),
	);
	System::register_extra_weight_unchecked(idle, DispatchClass::Mandatory);
	<AllPalletsWithSystem as OnFinalize<BlockNumber>>::on_finalize(n);
}

pub(crate) fn run_block(n: BlockNumber) {
	run_block_with(n, || {});
}

/// Whether the staking machinery has work that runs block by block: the
/// election or staking's fetch of it, offences on their way to staking, or
/// slashes due in the active era.
fn staking_busy() -> bool {
	let active = pallet_staking_async::ActiveEra::<Runtime>::get().map_or(0, |era| era.index);
	pallet_paged_election::CurrentPhase::<Runtime>::get() != pallet_paged_election::Phase::Off
		|| pallet_staking_async::NextElectionPage::<Runtime>::exists()
		|| pallet_staking_async_ah_client::OffenceSendQueue::<Runtime>::count() > 0
		|| pallet_staking_async::OffenceQueueEras::<Runtime>::exists()
		|| pallet_staking_async::ProcessingOffence::<Runtime>::exists()
		|| pallet_staking_async::UnappliedSlashes::<Runtime>::iter_prefix(active)
			.next()
			.is_some()
}

/// Runs the chain to the end of the current session, as it would run: block
/// by block while staking has work (see [`staking_busy`]); otherwise only the
/// block before the boundary, where rc-client hands over a set it holds, and
/// the boundary, where the session rotates and its report reaches staking.
pub(crate) fn next_session() {
	let boundary = (Session::current_index() + 1) * Period::get();
	while System::block_number() < boundary {
		let now = System::block_number();
		let next = if staking_busy() {
			now + 1
		} else if pallet_staking_async_rc_client::OutgoingValidatorSet::<Runtime>::exists()
			&& now + 1 < boundary
		{
			boundary - 1
		} else {
			boundary
		};
		run_block(next);
	}
}

/// Runs blocks while staking has block-by-block work (see [`staking_busy`]).
pub(crate) fn settle() {
	for _ in 0..1_000 {
		if !staking_busy() {
			return;
		}
		run_block(System::block_number() + 1);
	}
	panic!("staking still has work after 1000 blocks");
}

pub(crate) fn active_era() -> u32 {
	pallet_staking_async::ActiveEra::<Runtime>::get().map_or(0, |era| era.index)
}

/// Runs sessions until staking's active era is `era`.
pub(crate) fn run_to_era(era: u32) {
	use crate::staking::params::SESSIONS_PER_ERA;
	let start = active_era();
	for _ in 0..(era.saturating_sub(start) + 2) * SESSIONS_PER_ERA {
		if active_era() >= era {
			return;
		}
		next_session();
	}
	assert!(
		active_era() >= era,
		"era {era} not reached: active {:?}, planned {:?}",
		pallet_staking_async::ActiveEra::<Runtime>::get(),
		pallet_staking_async::CurrentEra::<Runtime>::get()
	);
}
