//! The staking side (`pallet-staking-async` + `rc-client`) and the session side
//! (`pallet-session` + `ah-client`) live in one runtime, so their messages are
//! direct calls instead of XCM.
//!
//! | From | Message | Adapter |
//! |---|---|---|
//! | staking | elected set | [`DirectToRelay`] → `ah_client::validator_set` |
//! | session | session report, offences | [`DirectToAssetHub`] → `rc_client::relay_*` |
//!
//! Upstream's send traits return `Result<(), ()>`, so the weight of the work a
//! message triggers (staking's session report, era rotation and offence
//! processing, historical pruning) never reaches the block. The adapters
//! register it as mandatory weight, counted by hand where upstream declares
//! none, until a benchmark replaces it.
//!
//! The clients' message calls accept origin `None` only while an adapter
//! delivers a message ([`EnsureLocalRelay`]); root also passes (upstream checks
//! `ensure_origin_or_root`). A block author can include a bare extrinsic the
//! pool would refuse (neither pallet validates unsigned transactions), and it
//! is dispatched with origin `None`: the call filter ([`LocalRelayFilter`])
//! refuses every call of both clients, and `EnsureLocalRelay` that `None`. The
//! adapters call the pallets' functions directly, past the filter.
//!
//! Session keys are set on `pallet-session` itself: rc-client's `set_keys` and
//! `purge_keys` are meant for keys forwarded to a relay chain, and ah-client's
//! `*_keys_from_ah` for keys forwarded from Asset Hub.

use super::recovery;
use crate::staking::commission;
use crate::{AccountId, Balance, BlockNumber, Runtime, RuntimeCall, RuntimeOrigin};
use alloc::vec::Vec;
use frame_support::{
	dispatch::DispatchClass,
	traits::{Contains, EnsureOrigin},
	weights::Weight,
};
use pallet_staking_async_ah_client as ah_client;
use pallet_staking_async_rc_client as rc_client;
use sp_runtime::Perbill;
use sp_staking::{offence::OffenceDetails, Exposure, SessionIndex};

fn register(weight: Weight) {
	frame_system::Pallet::<Runtime>::register_extra_weight_unchecked(
		weight,
		DispatchClass::Mandatory,
	);
}

fn db() -> frame_support::weights::RuntimeDbWeight {
	<Runtime as frame_system::Config>::DbWeight::get()
}

// Set while an adapter delivers a message.
environmental::environmental!(delivering: ());

/// Runs `deliver` as an adapter's delivery, which [`EnsureLocalRelay`] accepts.
fn as_local_relay<R>(deliver: impl FnOnce() -> R) -> R {
	delivering::using(&mut (), deliver)
}

/// The clients' message origin (`RelayChainOrigin`, `AssetHubOrigin`): `None`,
/// and only while an adapter delivers a message. A bare extrinsic's `None` is
/// refused.
pub struct EnsureLocalRelay;

impl EnsureOrigin<RuntimeOrigin> for EnsureLocalRelay {
	type Success = ();

	fn try_origin(o: RuntimeOrigin) -> Result<(), RuntimeOrigin> {
		if delivering::with(|_| ()).is_none() {
			return Err(o);
		}
		frame_system::EnsureNone::<AccountId>::try_origin(o)
	}

	/// No benchmark dispatches the clients' messages, and no origin passes
	/// outside an adapter.
	#[cfg(feature = "runtime-benchmarks")]
	fn try_successful_origin() -> Result<RuntimeOrigin, ()> {
		Err(())
	}
}

/// Historical session roots `pallet_session::historical::prune_up_to(up_to)`
/// removes: those from the stored range's start up to `up_to`, capped at its end.
fn historical_roots_pruned(up_to: SessionIndex) -> u32 {
	pallet_session::historical::StoredRange::<Runtime>::get()
		.map_or(0, |(start, end)| up_to.min(end).saturating_sub(start))
}

/// Historical session roots a validator set prunes at most; the rest go with
/// the next one. Bounds the mandatory work after an era held long.
pub(crate) const MAX_ROOTS_PRUNED: u32 = 1_000;

/// `up_to`, lowered so that at most [`MAX_ROOTS_PRUNED`] roots go at once.
fn capped_prune(up_to: SessionIndex) -> SessionIndex {
	pallet_session::historical::StoredRange::<Runtime>::get().map_or(up_to, |(start, _)| {
		up_to.min(start.saturating_add(MAX_ROOTS_PRUNED))
	})
}

/// Staking → session: the elected set, queued in ah-client until the session
/// rotation that applies it.
pub struct DirectToRelay;

impl rc_client::SendToRelayChain for DirectToRelay {
	type AccountId = AccountId;
	type Balance = Balance;

	fn validator_set(mut report: rc_client::ValidatorSetReport<AccountId>) -> Result<(), ()> {
		report.prune_up_to = report.prune_up_to.map(capped_prune);
		let pruned = report.prune_up_to.map(historical_roots_pruned);
		as_local_relay(|| {
			ah_client::Pallet::<Runtime>::validator_set(RuntimeOrigin::none(), report)
		})
		.map_err(|e| {
			log::error!(target: "runtime::staking", "validator set not delivered: {e:?}");
		})?;
		// `validator_set`'s declared weight, plus the historical roots it prunes,
		// which upstream does not price.
		let mut weight = db().reads_writes(2, 1);
		if let Some(roots) = pruned {
			weight.saturating_accrue(db().reads_writes(1, u64::from(roots) + 1));
		}
		register(weight);
		Ok(())
	}

	fn set_keys(
		_: AccountId,
		_: Vec<u8>,
		_: Option<Balance>,
	) -> Result<Balance, rc_client::SendKeysError<Balance>> {
		Err(rc_client::SendKeysError::Send(
			rc_client::SendOperationError::DeliveryFailed,
		))
	}

	fn purge_keys(
		_: AccountId,
		_: Option<Balance>,
	) -> Result<Balance, rc_client::SendKeysError<Balance>> {
		Err(rc_client::SendKeysError::Send(
			rc_client::SendOperationError::DeliveryFailed,
		))
	}
}

/// Session → staking: each session's report (era points, and the activation of
/// a new set) and the offences reported in it.
pub struct DirectToAssetHub;

impl ah_client::SendToAssetHub for DirectToAssetHub {
	type AccountId = AccountId;

	/// Before staking reads the report, an era plan that can no longer start is
	/// reset ([`recovery`]), so staking plans it again in this same report, and
	/// commissions above the ceiling are clamped to it ([`commission`]). Both
	/// must precede staking's read, so they run only for a report rc-client
	/// will pass on: the first, or one past the last it took. A stale or
	/// duplicated report is dropped by rc-client and changes nothing here.
	fn relay_session_report(report: rc_client::SessionReport<AccountId>) -> Result<(), ()> {
		let accepted = rc_client::LastSessionReportEndingIndex::<Runtime>::get()
			.is_none_or(|last| report.end_index > last);
		// `LastSessionReportEndingIndex`.
		register(db().reads(1));
		if accepted {
			register(recovery::reset_stalled_plan(&report));
			register(commission::clamp_to_ceiling());
		}
		match as_local_relay(|| {
			rc_client::Pallet::<Runtime>::relay_session_report(RuntimeOrigin::none(), report)
		}) {
			Ok(post) => {
				register(post.actual_weight.unwrap_or_default());
				Ok(())
			}
			Err(e) => {
				log::error!(target: "runtime::staking", "session report not delivered: {e:?}");
				Err(())
			}
		}
	}

	fn relay_new_offence_paged(
		offences: Vec<(SessionIndex, rc_client::Offence<AccountId>)>,
	) -> Result<(), ()> {
		match as_local_relay(|| {
			rc_client::Pallet::<Runtime>::relay_new_offence_paged(RuntimeOrigin::none(), offences)
		}) {
			Ok(post) => {
				register(post.actual_weight.unwrap_or_default());
				Ok(())
			}
			Err(e) => {
				log::error!(target: "runtime::staking", "offences not delivered: {e:?}");
				Err(())
			}
		}
	}
}

/// `frame_system::Config::BaseCallFilter`: everything but the clients' calls.
/// Their messages come from the adapters; keys are set with `session.set_keys`;
/// ah-client's admin calls are root's, which skips the filter.
pub struct LocalRelayFilter;

impl Contains<RuntimeCall> for LocalRelayFilter {
	fn contains(call: &RuntimeCall) -> bool {
		!matches!(call, RuntimeCall::RcClient(_) | RuntimeCall::AhClient(_))
	}
}

/// ah-client's stand-in for its `Passive` mode, which this runtime never uses:
/// ah-client starts `Active` and stays so.
pub struct NoFallback;

impl pallet_session::SessionManager<AccountId> for NoFallback {
	fn new_session(_: SessionIndex) -> Option<Vec<AccountId>> {
		None
	}
	fn end_session(_: SessionIndex) {}
	fn start_session(_: SessionIndex) {}
}

impl
	sp_staking::offence::OnOffenceHandler<
		AccountId,
		(AccountId, Exposure<AccountId, Balance>),
		Weight,
	> for NoFallback
{
	/// Reached only if root moved ah-client out of `Active`: the offence is not
	/// slashed, so it is logged as an error (KL-19).
	fn on_offence(
		offenders: &[OffenceDetails<AccountId, (AccountId, Exposure<AccountId, Balance>)>],
		_: &[Perbill],
		session: SessionIndex,
	) -> Weight {
		for details in offenders {
			log::error!(
				target: "runtime::staking",
				"offence by {:?} in session {session} dropped: ah-client is not active",
				details.offender.0,
			);
		}
		Weight::zero()
	}
}

impl frame_support::traits::RewardsReporter<AccountId> for NoFallback {
	fn reward_by_ids(_: impl IntoIterator<Item = (AccountId, u32)>) {}
}

impl pallet_authorship::EventHandler<AccountId, BlockNumber> for NoFallback {
	fn note_author(_: AccountId) {}
}
