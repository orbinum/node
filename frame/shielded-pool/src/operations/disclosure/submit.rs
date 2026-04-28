use crate::{
	operations::disclosure::record::ParsedDisclosureSignals,
	operations::disclosure::validation::DisclosureValidationService,
	pallet::{Config, Error, Event, Pallet},
	storage::{AuditRepository, CommitmentRepository},
	types::{Commitment, DisclosureCondition},
};
use frame_support::{BoundedVec, ensure, pallet_prelude::*};
use sp_runtime::traits::SaturatedConversion;

pub fn disclose<T: Config>(
	who: &T::AccountId,
	commitment: Commitment,
	proof_bytes: BoundedVec<u8, ConstU32<256>>,
	public_signals: BoundedVec<u8, ConstU32<76>>,
	auditor: Option<&T::AccountId>,
) -> DispatchResult {
	ensure!(
		CommitmentRepository::exists::<T>(&commitment),
		Error::<T>::CommitmentNotFound
	);

	let current_block = frame_system::Pallet::<T>::block_number();

	if let Some(auditor_account) = auditor {
		disclose_with_auditor::<T>(
			who,
			auditor_account,
			commitment,
			proof_bytes.as_slice(),
			public_signals.as_slice(),
			current_block,
		)?;
	} else {
		disclose_self::<T>(
			who,
			commitment,
			proof_bytes.as_slice(),
			public_signals.as_slice(),
			current_block,
		)?;
	}

	Pallet::<T>::deposit_event(Event::Disclosed {
		who: who.clone(),
		commitment,
		auditor: auditor.cloned(),
	});

	Ok(())
}

fn disclose_self<T: Config>(
	who: &T::AccountId,
	commitment: Commitment,
	proof_bytes: &[u8],
	public_signals: &[u8],
	current_block: frame_system::pallet_prelude::BlockNumberFor<T>,
) -> DispatchResult {
	DisclosureValidationService::validate_disclosure_access::<T>(who, &commitment, None)?;
	DisclosureValidationService::verify_proof_internal::<T>(proof_bytes, public_signals)?;
	DisclosureValidationService::validate_public_signals::<T>(&commitment, public_signals)?;

	let record = ParsedDisclosureSignals::from_public_signals(public_signals)
		.into_record(who.clone(), current_block);
	AuditRepository::store_disclosure_record::<T>(commitment, who, record)?;
	AuditRepository::update_disclosure_timestamp::<T>(who, commitment, current_block);
	Ok(())
}

fn disclose_with_auditor<T: Config>(
	who: &T::AccountId,
	auditor: &T::AccountId,
	commitment: Commitment,
	proof_bytes: &[u8],
	public_signals: &[u8],
	current_block: frame_system::pallet_prelude::BlockNumberFor<T>,
) -> DispatchResult {
	let request = AuditRepository::get_disclosure_request::<T>(who, auditor)
		.ok_or(Error::<T>::DisclosureRequestNotFound)?;
	ensure!(
		current_block <= request.expires_at,
		Error::<T>::DisclosureRequestExpired
	);

	let policy = AuditRepository::get_policy::<T>(who).ok_or(Error::<T>::AuditPolicyNotFound)?;
	if let Some(valid_until) = policy.valid_until {
		ensure!(current_block <= valid_until, Error::<T>::AuditPolicyExpired);
	}

	let revealed_value_u64 = if public_signals.len() >= 40 {
		u64::from_le_bytes(public_signals[32..40].try_into().unwrap_or([0u8; 8]))
	} else {
		0u64
	};

	let conditions_met = policy.conditions.iter().any(|cond| match cond {
		DisclosureCondition::Always => true,
		DisclosureCondition::TimeDelay { after_block } => current_block >= *after_block,
		DisclosureCondition::AmountThreshold { min_amount } => {
			let min_u64: u64 = (*min_amount).saturated_into::<u64>();
			revealed_value_u64 >= min_u64
		}
	});
	ensure!(conditions_met, Error::<T>::DisclosureConditionsNotMet);

	DisclosureValidationService::verify_disclosure_proof::<T>(
		proof_bytes,
		public_signals,
		&commitment,
	)?;

	let record = ParsedDisclosureSignals::from_public_signals(public_signals)
		.into_record(who.clone(), current_block);
	AuditRepository::store_disclosure_record::<T>(commitment, auditor, record)?;
	AuditRepository::update_disclosure_timestamp::<T>(who, commitment, current_block);
	AuditRepository::increment_disclosure_counter::<T>(who, auditor);
	AuditRepository::remove_disclosure_request::<T>(who, auditor);
	let _ = AuditRepository::create_audit_trail::<T>(
		who,
		auditor,
		commitment,
		b"selective_disclosure",
	)?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		operations::disclosure::policy,
		pallet::{CommitmentMemos, Event as PalletEvent},
		storage::AuditRepository,
		types::{Auditor, Commitment, DisclosureCondition, DisclosureRequest, EncryptedMemo},
	};
	use frame_support::{BoundedVec, assert_noop, assert_ok, pallet_prelude::ConstU32};

	// ── helpers ──────────────────────────────────────────────────────────────

	fn commitment(seed: u8) -> Commitment {
		Commitment::new([seed; 32])
	}

	fn register_commitment(c: Commitment) {
		CommitmentMemos::<Test>::insert(c, EncryptedMemo::default());
	}

	fn proof() -> BoundedVec<u8, ConstU32<256>> {
		BoundedVec::try_from([0x01u8; 128].to_vec()).unwrap()
	}

	/// 76-byte signals: commitment (32) | value_le (8) | asset_id_le (4) | owner_hash (32)
	fn signals_for(c: &Commitment) -> BoundedVec<u8, ConstU32<76>> {
		let mut buf = [0u8; 76];
		buf[0..32].copy_from_slice(&c.0);
		buf[32..40].copy_from_slice(&100u64.to_le_bytes());
		buf[40..44].copy_from_slice(&1u32.to_le_bytes());
		BoundedVec::try_from(buf.to_vec()).unwrap()
	}

	fn set_policy_always(owner: u64, auditor: u64) {
		let auditors = BoundedVec::try_from(vec![Auditor::Account(auditor)]).unwrap();
		let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
			BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();
		policy::set_audit_policy::<Test>(&owner, auditors, conditions, None, None).unwrap();
	}

	fn make_request(target: u64, auditor: u64, expires_at: u64) {
		use frame_support::BoundedVec;
		let req = DisclosureRequest {
			auditor,
			target,
			requested_at: 1u64,
			expires_at,
			reason: BoundedVec::default(),
		};
		crate::pallet::DisclosureRequests::<Test>::insert(target, auditor, req);
	}

	// ── disclose (self) ───────────────────────────────────────────────────────

	#[test]
	fn disclose_self_works() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c = commitment(0x01);
			register_commitment(c);

			assert_ok!(disclose::<Test>(&owner, c, proof(), signals_for(&c), None));

			// Record stored under caller key
			assert!(AuditRepository::has_disclosure_record::<Test>(c, &owner));
		});
	}

	#[test]
	fn disclose_commitment_not_found_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(0x02);
			// Not registered
			assert_noop!(
				disclose::<Test>(&1u64, c, proof(), signals_for(&c), None),
				crate::pallet::Error::<Test>::CommitmentNotFound
			);
		});
	}

	#[test]
	fn disclose_self_emits_event() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c = commitment(0x03);
			register_commitment(c);

			assert_ok!(disclose::<Test>(&owner, c, proof(), signals_for(&c), None));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Disclosed {
						who,
						commitment: ec,
						auditor: None,
					}) if who == owner && ec == c
				)
			});
			assert!(found, "Disclosed event not emitted");
		});
	}

	#[test]
	fn disclose_self_updates_timestamp() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c = commitment(0x04);
			register_commitment(c);

			assert_ok!(disclose::<Test>(&owner, c, proof(), signals_for(&c), None));

			let ts = crate::pallet::LastDisclosureTimestamp::<Test>::get(owner, c);
			assert_eq!(ts, Some(1u64));
		});
	}

	#[test]
	fn disclose_self_twice_fails_duplicate_record() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c = commitment(0x05);
			register_commitment(c);

			assert_ok!(disclose::<Test>(&owner, c, proof(), signals_for(&c), None));
			assert_noop!(
				disclose::<Test>(&owner, c, proof(), signals_for(&c), None),
				crate::pallet::Error::<Test>::DisclosureRecordAlreadyExists
			);
		});
	}

	// ── disclose (with auditor) ───────────────────────────────────────────────

	#[test]
	fn disclose_with_auditor_works() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			let c = commitment(0x10);
			register_commitment(c);
			set_policy_always(owner, auditor);
			make_request(owner, auditor, 9999u64);

			assert_ok!(disclose::<Test>(
				&owner,
				c,
				proof(),
				signals_for(&c),
				Some(&auditor),
			));

			// Record stored under auditor key
			assert!(AuditRepository::has_disclosure_record::<Test>(c, &auditor));
		});
	}

	#[test]
	fn disclose_with_auditor_request_not_found_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			let c = commitment(0x11);
			register_commitment(c);
			// Policy but no request
			set_policy_always(owner, auditor);

			assert_noop!(
				disclose::<Test>(&owner, c, proof(), signals_for(&c), Some(&auditor)),
				crate::pallet::Error::<Test>::DisclosureRequestNotFound
			);
		});
	}

	#[test]
	fn disclose_with_auditor_request_expired_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			let c = commitment(0x12);
			register_commitment(c);
			set_policy_always(owner, auditor);
			make_request(owner, auditor, 0u64); // expires at block 0, current = 1

			assert_noop!(
				disclose::<Test>(&owner, c, proof(), signals_for(&c), Some(&auditor)),
				crate::pallet::Error::<Test>::DisclosureRequestExpired
			);
		});
	}

	#[test]
	fn disclose_with_auditor_policy_expired_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			let c = commitment(0x13);
			register_commitment(c);

			// Policy expired (valid_until = 0)
			let auditors = BoundedVec::try_from(vec![Auditor::Account(auditor)]).unwrap();
			let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
				BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();
			policy::set_audit_policy::<Test>(&owner, auditors, conditions, None, Some(0u64))
				.unwrap();
			make_request(owner, auditor, 9999u64);

			assert_noop!(
				disclose::<Test>(&owner, c, proof(), signals_for(&c), Some(&auditor)),
				crate::pallet::Error::<Test>::AuditPolicyExpired
			);
		});
	}

	#[test]
	fn disclose_with_auditor_conditions_not_met_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			let c = commitment(0x14);
			register_commitment(c);

			// Condition: AmountThreshold(min=99999) but signals encode value=100
			let auditors = BoundedVec::try_from(vec![Auditor::Account(auditor)]).unwrap();
			let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
				BoundedVec::try_from(vec![DisclosureCondition::AmountThreshold {
					min_amount: 99_999u128,
				}])
				.unwrap();
			policy::set_audit_policy::<Test>(&owner, auditors, conditions, None, None).unwrap();
			make_request(owner, auditor, 9999u64);

			assert_noop!(
				disclose::<Test>(&owner, c, proof(), signals_for(&c), Some(&auditor)),
				crate::pallet::Error::<Test>::DisclosureConditionsNotMet
			);
		});
	}

	#[test]
	fn disclose_with_auditor_removes_request_after_success() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			let c = commitment(0x15);
			register_commitment(c);
			set_policy_always(owner, auditor);
			make_request(owner, auditor, 9999u64);

			assert_ok!(disclose::<Test>(
				&owner,
				c,
				proof(),
				signals_for(&c),
				Some(&auditor),
			));

			assert!(
				!AuditRepository::has_disclosure_request::<Test>(&owner, &auditor),
				"Request should be removed after successful disclosure"
			);
		});
	}

	#[test]
	fn disclose_with_auditor_emits_event() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			let c = commitment(0x16);
			register_commitment(c);
			set_policy_always(owner, auditor);
			make_request(owner, auditor, 9999u64);

			assert_ok!(disclose::<Test>(
				&owner,
				c,
				proof(),
				signals_for(&c),
				Some(&auditor),
			));

			let events = frame_system::Pallet::<Test>::events();
			let found = events.iter().any(|r| {
				matches!(
					r.event,
					crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Disclosed {
						who,
						commitment: ec,
						auditor: Some(a),
					}) if who == owner && ec == c && a == auditor
				)
			});
			assert!(found, "Disclosed (with auditor) event not emitted");
		});
	}
}
