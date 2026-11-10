//! What a reported offence does beyond staking's slash: the offender is banned
//! from validating at once, permanently, and what staking may slash it for is
//! bounded across eras.
//!
//! Staking defers a slash `SLASH_DEFER_DURATION` eras so governance can cancel
//! it. Banning only when the slash lands would leave the offender electable
//! all that time; banning on the report keeps it out of every election whose
//! target snapshot is taken after the report; an election whose snapshot is
//! already taken is unaffected. The ban has no end: a term in blocks could run
//! out before the slash lands if eras stall, so governance reviews the offence
//! and lifts it (`validatorSet.unbanValidator`).
//!
//! Staking slashes each era on its own exposure, with no memory of the
//! offender's other eras, and a key holder can sign an equivocation for any
//! round of any session still provable. [`BanOffenders`] keeps, per offender,
//! the fraction it handed staking for each era staking still accepts
//! ([`Slashed`]), and caps what it hands so their sum never passes
//! [`MAX_SLASH_FRACTION`]: an offender and its nominators keep a sliver of
//! what was exposed however many eras it is reported in.
//!
//! [`OncePerEra`] keeps reports that change nothing out of storage, where each
//! would stay for good at no cost (a successful report pays no fee):
//! - an offender already reported in the era is heard again only in a time slot
//!   that other offenders share, or from the block's author (the unsigned path
//!   a validator's node reports what it saw through), where the slot's
//!   correlated fraction may raise its slash;
//! - an offence staking would not slash (too old, or no exposure, as in era 0)
//!   is heard once, for the ban: only while the offender is not banned.
//!
//! `pallet_offences` ignores the weight this handler returns, so the ban and
//! chill go uncharged in the report. A report of another offender in the same
//! time slot hands it every offender of that slot again, re-banning one that
//! governance has unbanned since.

use crate::{
	staking::params::{MAX_SLASH_FRACTION, SLASH_DEFER_DURATION},
	AccountId, Runtime, ValidatorSet,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use frame_support::{pallet_prelude::ConstU32, weights::Weight, BoundedVec, Twox64Concat};
use pallet_session::historical::IdentificationTuple;
use pallet_validator_set::{BanTerm, WeightInfo as _};
use scale_codec::Encode;
use sp_runtime::{traits::Saturating, Perbill};
use sp_staking::{
	offence::{Offence, OffenceDetails, OffenceError, OnOffenceHandler, ReportOffence},
	EraIndex, SessionIndex,
};

/// Per offender, the fraction handed to staking for each era it still accepts.
/// Entries of eras staking no longer accepts are dropped on the offender's next
/// report; one entry per offender ever reported stays, small and bounded by
/// the keys that can be reported.
#[frame_support::storage_alias(verbatim)]
pub type Slashed = StorageMap<
	OrbinumOffences,
	Twox64Concat,
	AccountId,
	BoundedVec<(EraIndex, Perbill), ConstU32<SLASH_DEFER_DURATION>>,
	frame_support::pallet_prelude::ValueQuery,
>;

/// `pallet_offences::Config::OnOffenceHandler`: bans every offender, then hands
/// the offence to `Inner` (ah-client, which disables the offender and sends the
/// offence to staking) with each fraction capped so an offender's fractions
/// across the eras staking accepts sum to at most [`MAX_SLASH_FRACTION`].
pub struct BanOffenders<Inner>(PhantomData<Inner>);

impl<Inner> OnOffenceHandler<AccountId, IdentificationTuple<Runtime>, Weight>
	for BanOffenders<Inner>
where
	Inner: OnOffenceHandler<AccountId, IdentificationTuple<Runtime>, Weight>,
{
	fn on_offence(
		offenders: &[OffenceDetails<AccountId, IdentificationTuple<Runtime>>],
		slash_fraction: &[Perbill],
		session: SessionIndex,
	) -> Weight {
		for details in offenders {
			ValidatorSet::ban_offender(&details.offender.0, BanTerm::Permanent);
		}
		let era = offence_era(session);
		let capped: Vec<Perbill> = offenders
			.iter()
			.zip(slash_fraction)
			.map(|(details, fraction)| {
				let who = &details.offender.0;
				match era {
					Some(era) if staking_accepts(era, who) => cap_across_eras(who, era, *fraction),
					_ => (*fraction).min(MAX_SLASH_FRACTION),
				}
			})
			.collect();
		let weight = <<Runtime as pallet_validator_set::Config>::WeightInfo>::ban_validator()
			.saturating_add(<Runtime as frame_system::Config>::DbWeight::get().reads_writes(3, 1))
			.saturating_mul(offenders.len() as u64);
		Inner::on_offence(offenders, &capped, session).saturating_add(weight)
	}
}

/// The fraction to hand staking for `who` in `era`: `fraction`, cut so the sum
/// over every era staking accepts stays within [`MAX_SLASH_FRACTION`], and never
/// below what `era` already holds (staking keeps the higher of an era's two).
fn cap_across_eras(who: &AccountId, era: EraIndex, fraction: Perbill) -> Perbill {
	let oldest = oldest_accepted_era();
	Slashed::mutate(who, |eras| {
		eras.retain(|(e, _)| *e >= oldest);
		let held = eras
			.iter()
			.find_map(|(e, f)| (*e == era).then_some(*f))
			.unwrap_or_default();
		let others = eras
			.iter()
			.filter(|(e, _)| *e != era)
			.fold(Perbill::zero(), |sum, (_, f)| sum.saturating_add(*f));
		let allowed = fraction
			.min(MAX_SLASH_FRACTION.saturating_sub(others))
			.max(held);
		match eras.iter_mut().find(|(e, _)| *e == era) {
			Some(entry) => entry.1 = allowed,
			// At most one entry per accepted era, and the bound is their count.
			None => {
				let _ = eras.try_push((era, allowed));
			}
		}
		allowed
	})
}

/// The era staking files an offence in `session` under: the latest bonded era
/// that started at or before it, as staking maps it.
fn offence_era(session: SessionIndex) -> Option<EraIndex> {
	pallet_staking_async::BondedEras::<Runtime>::get()
		.iter()
		.rev()
		.find_map(|&(era, start)| (start <= session).then_some(era))
}

/// The oldest era staking takes offences for (`SlashDeferDuration - 1` back).
fn oldest_accepted_era() -> EraIndex {
	pallet_staking_async::ActiveEra::<Runtime>::get()
		.map_or(0, |active| active.index)
		.saturating_sub(SLASH_DEFER_DURATION.saturating_sub(1))
}

/// Whether staking would slash `who` for an offence in `era`: not too old, and
/// exposed in it.
fn staking_accepts(era: EraIndex, who: &AccountId) -> bool {
	era >= oldest_accepted_era()
		&& pallet_staking_async::ErasStakersOverview::<Runtime>::contains_key(era, who)
}

/// Whether `who` was already handed to staking for an offence in `era`.
fn reported_in(who: &AccountId, era: EraIndex) -> bool {
	Slashed::get(who).iter().any(|(e, _)| *e == era)
}

/// `pallet_grandpa`'s offence sink: `Inner` (`pallet_offences`), refusing a
/// report that cannot change any slash or ban (see the module docs). The
/// refusal is a failed report, so a signed one pays its fee.
pub struct OncePerEra<Inner>(PhantomData<Inner>);

impl<Inner, O> ReportOffence<AccountId, IdentificationTuple<Runtime>, O> for OncePerEra<Inner>
where
	Inner: ReportOffence<AccountId, IdentificationTuple<Runtime>, O>,
	O: Offence<IdentificationTuple<Runtime>>,
{
	fn report_offence(reporters: Vec<AccountId>, offence: O) -> Result<(), OffenceError> {
		let era = offence_era(offence.session_index());
		let shared_slot = pallet_offences::ConcurrentReportsIndex::<Runtime>::decode_len(
			O::ID,
			offence.time_slot().encode(),
		)
		.is_some_and(|reports| reports > 0);
		let by_author = pallet_authorship::Pallet::<Runtime>::author()
			.is_some_and(|author| reporters.contains(&author));
		let heard = offence.offenders().iter().any(|(who, _)| match era {
			Some(era) if staking_accepts(era, who) => {
				!reported_in(who, era) || shared_slot || by_author
			}
			_ => !ValidatorSet::is_banned(who),
		});
		if !heard {
			return Err(OffenceError::DuplicateReport);
		}
		Inner::report_offence(reporters, offence)
	}

	fn is_known_offence(
		offenders: &[IdentificationTuple<Runtime>],
		time_slot: &O::TimeSlot,
	) -> bool {
		Inner::is_known_offence(offenders, time_slot)
	}
}
