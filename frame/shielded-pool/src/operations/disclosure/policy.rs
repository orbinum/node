use crate::{
	pallet::{BalanceOf, Config, Error, Event, Pallet},
	storage::AuditRepository,
	types::{AuditPolicy, Auditor, DisclosureCondition},
};
use frame_support::{BoundedVec, ensure, pallet_prelude::*};
use frame_system::pallet_prelude::BlockNumberFor;

pub fn set_audit_policy<T: Config>(
	who: &T::AccountId,
	auditors: BoundedVec<Auditor<T::AccountId>, ConstU32<10>>,
	conditions: BoundedVec<DisclosureCondition<BalanceOf<T>, BlockNumberFor<T>>, ConstU32<10>>,
	max_frequency: Option<BlockNumberFor<T>>,
	valid_until: Option<BlockNumberFor<T>>,
) -> DispatchResult {
	ensure!(!auditors.is_empty(), Error::<T>::NoAuditorsProvided);
	ensure!(auditors.len() <= 10, Error::<T>::TooManyAuditors);
	ensure!(conditions.len() <= 10, Error::<T>::TooManyConditions);

	for i in 0..auditors.len() {
		ensure!(
			!auditors[i + 1..].contains(&auditors[i]),
			Error::<T>::DuplicateAuditor
		);
	}

	let current_version = AuditRepository::get_policy::<T>(who)
		.map(|policy| policy.version)
		.unwrap_or(0);

	let policy = AuditPolicy {
		auditors,
		conditions,
		max_frequency,
		valid_until,
		version: current_version.saturating_add(1),
	};

	AuditRepository::store_policy::<T>(who, policy.clone());
	Pallet::<T>::deposit_event(Event::AuditPolicySet {
		account: who.clone(),
		version: policy.version,
	});
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		pallet::Event as PalletEvent,
		storage::AuditRepository,
		types::{Auditor, DisclosureCondition},
	};
	use frame_support::pallet_prelude::{BoundedVec, ConstU32};
	use frame_support::{assert_noop, assert_ok};

	// ── helpers ──────────────────────────────────────────────────────────────

	fn auditors_one(account: u64) -> BoundedVec<Auditor<u64>, ConstU32<10>> {
		BoundedVec::try_from(vec![Auditor::Account(account)]).unwrap()
	}

	fn no_conditions() -> BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> {
		BoundedVec::default()
	}

	// ── set_audit_policy ─────────────────────────────────────────────────────

	#[test]
	fn set_audit_policy_works() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			assert_ok!(set_audit_policy::<Test>(
				&owner,
				auditors_one(auditor),
				no_conditions(),
				None,
				None,
			));

			let policy = AuditRepository::get_policy::<Test>(&owner).unwrap();
			assert_eq!(policy.version, 1);
			assert_eq!(policy.auditors.len(), 1);
			assert_eq!(policy.auditors[0], Auditor::Account(auditor));
		});
	}

	#[test]
	fn set_audit_policy_empty_auditors_fails() {
		new_test_ext().execute_with(|| {
			let empty: BoundedVec<Auditor<u64>, ConstU32<10>> = BoundedVec::default();
			assert_noop!(
				set_audit_policy::<Test>(&1u64, empty, no_conditions(), None, None),
				crate::pallet::Error::<Test>::NoAuditorsProvided
			);
		});
	}

	#[test]
	fn set_audit_policy_duplicate_auditor_fails() {
		new_test_ext().execute_with(|| {
			let auditors =
				BoundedVec::try_from(vec![Auditor::Account(2u64), Auditor::Account(2u64)]).unwrap();
			assert_noop!(
				set_audit_policy::<Test>(&1u64, auditors, no_conditions(), None, None),
				crate::pallet::Error::<Test>::DuplicateAuditor
			);
		});
	}

	#[test]
	fn set_audit_policy_increments_version_on_update() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			assert_ok!(set_audit_policy::<Test>(
				&owner,
				auditors_one(2),
				no_conditions(),
				None,
				None,
			));
			assert_ok!(set_audit_policy::<Test>(
				&owner,
				auditors_one(3),
				no_conditions(),
				None,
				None,
			));

			let policy = AuditRepository::get_policy::<Test>(&owner).unwrap();
			assert_eq!(policy.version, 2);
		});
	}

	#[test]
	fn set_audit_policy_with_conditions_works() {
		new_test_ext().execute_with(|| {
			let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
				BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();
			assert_ok!(set_audit_policy::<Test>(
				&1u64,
				auditors_one(2),
				conditions.clone(),
				Some(100u64),
				Some(9999u64),
			));

			let policy = AuditRepository::get_policy::<Test>(&1u64).unwrap();
			assert_eq!(policy.conditions.len(), 1);
			assert_eq!(policy.max_frequency, Some(100u64));
			assert_eq!(policy.valid_until, Some(9999u64));
		});
	}

	#[test]
	fn set_audit_policy_emits_event() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			assert_ok!(set_audit_policy::<Test>(
				&owner,
				auditors_one(2),
				no_conditions(),
				None,
				None,
			));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|record| {
				matches!(
					record.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::AuditPolicySet {
						account,
						version: 1,
					}) if account == owner
				)
			});
			assert!(found, "AuditPolicySet event not emitted");
		});
	}

	#[test]
	fn set_audit_policy_multiple_auditors_works() {
		new_test_ext().execute_with(|| {
			let auditors = BoundedVec::try_from(vec![
				Auditor::Account(2u64),
				Auditor::Account(3u64),
				Auditor::Account(4u64),
			])
			.unwrap();
			assert_ok!(set_audit_policy::<Test>(
				&1u64,
				auditors,
				no_conditions(),
				None,
				None,
			));
			let policy = AuditRepository::get_policy::<Test>(&1u64).unwrap();
			assert_eq!(policy.auditors.len(), 3);
		});
	}
}
