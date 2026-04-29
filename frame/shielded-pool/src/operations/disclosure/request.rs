use crate::{
	pallet::{Config, Error, Event, Pallet},
	storage::AuditRepository,
	types::{Auditor, DisclosureRequest},
};
use frame_support::{BoundedVec, ensure, pallet_prelude::*};

pub fn request_disclosure<T: Config>(
	auditor: &T::AccountId,
	target: &T::AccountId,
	reason: BoundedVec<u8, ConstU32<256>>,
) -> DispatchResult {
	ensure!(
		!AuditRepository::has_disclosure_request::<T>(target, auditor),
		Error::<T>::DisclosureRequestAlreadyExists
	);

	let policy = AuditRepository::get_policy::<T>(target).ok_or(Error::<T>::AuditPolicyNotFound)?;

	let is_authorized = policy
		.auditors
		.iter()
		.any(|auditor_type| matches!(auditor_type, Auditor::Account(acc) if acc == auditor));
	ensure!(is_authorized, Error::<T>::AuditorNotAuthorized);

	if let Some(max_freq) = policy.max_frequency {
		let counter = AuditRepository::get_disclosure_counter::<T>(target, auditor);
		let max_freq_u32: u32 = TryInto::<u32>::try_into(max_freq).unwrap_or(u32::MAX);
		ensure!(
			counter < max_freq_u32,
			Error::<T>::TooManyDisclosureRequests
		);
	}

	let reason_clone = reason.clone();
	let current_block = frame_system::Pallet::<T>::block_number();
	let request = DisclosureRequest {
		auditor: auditor.clone(),
		target: target.clone(),
		requested_at: current_block,
		expires_at: current_block + T::RequestExpiration::get(),
		reason,
	};

	AuditRepository::store_disclosure_request::<T>(target.clone(), auditor.clone(), request);
	Pallet::<T>::deposit_event(Event::DisclosureRequested {
		target: target.clone(),
		auditor: auditor.clone(),
		reason: reason_clone,
	});
	Ok(())
}

pub fn reject_disclosure<T: Config>(
	target: &T::AccountId,
	auditor: &T::AccountId,
	reason: BoundedVec<u8, ConstU32<256>>,
) -> DispatchResult {
	ensure!(
		AuditRepository::has_disclosure_request::<T>(target, auditor),
		Error::<T>::DisclosureRequestNotFound
	);

	AuditRepository::remove_disclosure_request::<T>(target, auditor);
	Pallet::<T>::deposit_event(Event::DisclosureRejected {
		target: target.clone(),
		auditor: auditor.clone(),
		reason,
	});
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		operations::disclosure::policy,
		pallet::Event as PalletEvent,
		storage::AuditRepository,
		types::{Auditor, DisclosureCondition},
	};
	use frame_support::{assert_noop, assert_ok};

	// ── helpers ──────────────────────────────────────────────────────────────

	fn set_policy_with_auditor(owner: u64, auditor: u64) {
		let auditors = BoundedVec::try_from(vec![Auditor::Account(auditor)]).unwrap();
		let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
			BoundedVec::default();
		policy::set_audit_policy::<Test>(&owner, auditors, conditions, None, None).unwrap();
	}

	fn reason(text: &[u8]) -> BoundedVec<u8, ConstU32<256>> {
		BoundedVec::try_from(text.to_vec()).unwrap()
	}

	// ── request_disclosure ───────────────────────────────────────────────────

	#[test]
	fn request_disclosure_works() {
		new_test_ext().execute_with(|| {
			let target: u64 = 1;
			let auditor: u64 = 2;
			set_policy_with_auditor(target, auditor);

			assert_ok!(request_disclosure::<Test>(
				&auditor,
				&target,
				reason(b"audit required"),
			));

			assert!(AuditRepository::has_disclosure_request::<Test>(
				&target, &auditor
			));
		});
	}

	#[test]
	fn request_disclosure_no_policy_fails() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				request_disclosure::<Test>(&2u64, &1u64, reason(b"no policy")),
				crate::pallet::Error::<Test>::AuditPolicyNotFound
			);
		});
	}

	#[test]
	fn request_disclosure_auditor_not_in_policy_fails() {
		new_test_ext().execute_with(|| {
			let target: u64 = 1;
			// Policy authorizes auditor 2, not 3
			set_policy_with_auditor(target, 2u64);

			assert_noop!(
				request_disclosure::<Test>(&3u64, &target, reason(b"unauthorized")),
				crate::pallet::Error::<Test>::AuditorNotAuthorized
			);
		});
	}

	#[test]
	fn request_disclosure_already_exists_fails() {
		new_test_ext().execute_with(|| {
			let target: u64 = 1;
			let auditor: u64 = 2;
			set_policy_with_auditor(target, auditor);

			assert_ok!(request_disclosure::<Test>(
				&auditor,
				&target,
				reason(b"first")
			));
			assert_noop!(
				request_disclosure::<Test>(&auditor, &target, reason(b"second")),
				crate::pallet::Error::<Test>::DisclosureRequestAlreadyExists
			);
		});
	}

	#[test]
	fn request_disclosure_stores_request_fields() {
		new_test_ext().execute_with(|| {
			let target: u64 = 1;
			let auditor: u64 = 2;
			set_policy_with_auditor(target, auditor);

			assert_ok!(request_disclosure::<Test>(
				&auditor,
				&target,
				reason(b"check")
			));

			let req = AuditRepository::get_disclosure_request::<Test>(&target, &auditor).unwrap();
			assert_eq!(req.auditor, auditor);
			assert_eq!(req.target, target);
			// requested_at == current block (1)
			assert_eq!(req.requested_at, 1u64);
			// expires_at == requested_at + RequestExpiration (1000 in mock)
			assert_eq!(req.expires_at, 1001u64);
		});
	}

	#[test]
	fn request_disclosure_emits_event() {
		new_test_ext().execute_with(|| {
			let target: u64 = 1;
			let auditor: u64 = 2;
			set_policy_with_auditor(target, auditor);

			assert_ok!(request_disclosure::<Test>(
				&auditor,
				&target,
				reason(b"audit")
			));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(
						PalletEvent::DisclosureRequested { target: t, auditor: a, .. }
					) if t == target && a == auditor
				)
			});
			assert!(found, "DisclosureRequested event not emitted");
		});
	}

	// ── reject_disclosure ────────────────────────────────────────────────────

	#[test]
	fn reject_disclosure_works() {
		new_test_ext().execute_with(|| {
			let target: u64 = 1;
			let auditor: u64 = 2;
			set_policy_with_auditor(target, auditor);
			assert_ok!(request_disclosure::<Test>(
				&auditor,
				&target,
				reason(b"audit")
			));

			assert_ok!(reject_disclosure::<Test>(&target, &auditor, reason(b"no")));

			assert!(!AuditRepository::has_disclosure_request::<Test>(
				&target, &auditor
			));
		});
	}

	#[test]
	fn reject_disclosure_not_found_fails() {
		new_test_ext().execute_with(|| {
			assert_noop!(
				reject_disclosure::<Test>(&1u64, &2u64, reason(b"nope")),
				crate::pallet::Error::<Test>::DisclosureRequestNotFound
			);
		});
	}

	#[test]
	fn reject_disclosure_emits_event() {
		new_test_ext().execute_with(|| {
			let target: u64 = 1;
			let auditor: u64 = 2;
			set_policy_with_auditor(target, auditor);
			assert_ok!(request_disclosure::<Test>(&auditor, &target, reason(b"r")));

			assert_ok!(reject_disclosure::<Test>(
				&target,
				&auditor,
				reason(b"denied")
			));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(
						PalletEvent::DisclosureRejected { target: t, auditor: a, .. }
					) if t == target && a == auditor
				)
			});
			assert!(found, "DisclosureRejected event not emitted");
		});
	}
}
