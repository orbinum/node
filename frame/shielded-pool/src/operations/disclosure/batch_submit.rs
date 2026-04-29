use crate::{
	operations::disclosure::record::ParsedDisclosureSignals,
	operations::disclosure::validation::DisclosureValidationService,
	pallet::{BatchDisclosureSubmission, Config, Error, Event, Pallet},
	storage::{AuditRepository, CommitmentRepository},
};
use frame_support::{BoundedVec, ensure, pallet_prelude::*};
use pallet_zk_verifier::ZkVerifierPort;

pub fn batch_submit_proofs<T: Config>(
	who: &T::AccountId,
	submissions: BoundedVec<BatchDisclosureSubmission<T::AccountId>, ConstU32<10>>,
) -> DispatchResult {
	if submissions.is_empty() {
		return Ok(());
	}

	let mut proofs_raw = alloc::vec::Vec::with_capacity(submissions.len());
	let mut signals_raw = alloc::vec::Vec::with_capacity(submissions.len());

	for sub in submissions.iter() {
		ensure!(
			CommitmentRepository::exists::<T>(&sub.commitment),
			Error::<T>::CommitmentNotFound
		);
		DisclosureValidationService::validate_disclosure_access::<T>(
			who,
			&sub.commitment,
			sub.auditor.as_ref(),
		)?;
		DisclosureValidationService::validate_public_signals::<T>(
			&sub.commitment,
			&sub.public_signals,
		)?;

		proofs_raw.push(sub.proof.to_vec());
		signals_raw.push(sub.public_signals.to_vec());
	}

	let all_valid = T::ZkVerifier::batch_verify_disclosure_proofs(&proofs_raw, &signals_raw, None)?;
	ensure!(all_valid, Error::<T>::InvalidDisclosureRecord);

	let current_block = frame_system::Pallet::<T>::block_number();

	for sub in submissions {
		let record = ParsedDisclosureSignals::from_public_signals(&sub.public_signals)
			.into_record(who.clone(), current_block);

		// Preserve current semantics: batch records are stored under the caller key.
		AuditRepository::store_disclosure_record::<T>(sub.commitment, who, record)?;
		AuditRepository::update_disclosure_timestamp::<T>(who, sub.commitment, current_block);

		let effective_auditor = sub.auditor.as_ref().unwrap_or(who);
		let disclosure_type = if sub.auditor.is_some() {
			b"batch_audited_disclosure" as &[u8]
		} else {
			b"batch_disclosure" as &[u8]
		};
		let _ = AuditRepository::create_audit_trail::<T>(
			who,
			effective_auditor,
			sub.commitment,
			disclosure_type,
		)?;

		if let Some(ref auditor_account) = sub.auditor {
			AuditRepository::increment_disclosure_counter::<T>(who, auditor_account);
			AuditRepository::remove_disclosure_request::<T>(who, auditor_account);
		}

		Pallet::<T>::deposit_event(Event::Disclosed {
			who: who.clone(),
			commitment: sub.commitment,
			auditor: sub.auditor,
		});
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		mock::{Test, new_test_ext},
		operations::disclosure::policy,
		pallet::{BatchDisclosureSubmission, CommitmentMemos, Event as PalletEvent},
		storage::AuditRepository,
		types::{Auditor, Commitment, DisclosureCondition, DisclosureRequest, EncryptedMemo},
	};
	use frame_support::{assert_noop, assert_ok};

	// ── helpers ──────────────────────────────────────────────────────────────

	fn commitment(seed: u8) -> Commitment {
		Commitment::new([seed; 32])
	}

	fn register_commitment(c: Commitment) {
		CommitmentMemos::<Test>::insert(c, EncryptedMemo::default());
	}

	fn proof_vec() -> BoundedVec<u8, ConstU32<256>> {
		BoundedVec::try_from([0x01u8; 128].to_vec()).unwrap()
	}

	fn signals_vec(c: &Commitment) -> BoundedVec<u8, ConstU32<76>> {
		let mut buf = [0u8; 76];
		buf[0..32].copy_from_slice(&c.0);
		buf[32..40].copy_from_slice(&100u64.to_le_bytes());
		buf[40..44].copy_from_slice(&1u32.to_le_bytes());
		BoundedVec::try_from(buf.to_vec()).unwrap()
	}

	fn submission(c: Commitment) -> BatchDisclosureSubmission<u64> {
		BatchDisclosureSubmission {
			commitment: c,
			proof: proof_vec(),
			public_signals: signals_vec(&c),
			auditor: None,
		}
	}

	fn submission_with_auditor(c: Commitment, auditor: u64) -> BatchDisclosureSubmission<u64> {
		BatchDisclosureSubmission {
			commitment: c,
			proof: proof_vec(),
			public_signals: signals_vec(&c),
			auditor: Some(auditor),
		}
	}

	fn set_policy_simple(owner: u64, auditor: u64) {
		let auditors = BoundedVec::try_from(vec![Auditor::Account(auditor)]).unwrap();
		let conditions: BoundedVec<DisclosureCondition<u128, u64>, ConstU32<10>> =
			BoundedVec::default();
		policy::set_audit_policy::<Test>(&owner, auditors, conditions, None, None).unwrap();
	}

	fn make_request(target: u64, auditor: u64) {
		let req = DisclosureRequest {
			auditor,
			target,
			requested_at: 1u64,
			expires_at: 9999u64,
			reason: BoundedVec::default(),
		};
		crate::pallet::DisclosureRequests::<Test>::insert(target, auditor, req);
	}

	// ── batch_submit_proofs ───────────────────────────────────────────────────

	#[test]
	fn empty_batch_returns_ok() {
		new_test_ext().execute_with(|| {
			let submissions: BoundedVec<BatchDisclosureSubmission<u64>, ConstU32<10>> =
				BoundedVec::default();
			assert_ok!(batch_submit_proofs::<Test>(&1u64, submissions));
		});
	}

	#[test]
	fn single_submission_works() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c = commitment(0x20);
			register_commitment(c);

			let submissions = BoundedVec::try_from(vec![submission(c)]).unwrap();
			assert_ok!(batch_submit_proofs::<Test>(&owner, submissions));

			assert!(AuditRepository::has_disclosure_record::<Test>(c, &owner));
		});
	}

	#[test]
	fn multiple_submissions_work() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c1 = commitment(0x21);
			let c2 = commitment(0x22);
			let c3 = commitment(0x23);
			register_commitment(c1);
			register_commitment(c2);
			register_commitment(c3);

			let submissions =
				BoundedVec::try_from(vec![submission(c1), submission(c2), submission(c3)]).unwrap();
			assert_ok!(batch_submit_proofs::<Test>(&owner, submissions));

			assert!(AuditRepository::has_disclosure_record::<Test>(c1, &owner));
			assert!(AuditRepository::has_disclosure_record::<Test>(c2, &owner));
			assert!(AuditRepository::has_disclosure_record::<Test>(c3, &owner));
		});
	}

	#[test]
	fn commitment_not_found_fails() {
		new_test_ext().execute_with(|| {
			let c = commitment(0x30);
			// Not registered
			let submissions = BoundedVec::try_from(vec![submission(c)]).unwrap();
			assert_noop!(
				batch_submit_proofs::<Test>(&1u64, submissions),
				crate::pallet::Error::<Test>::CommitmentNotFound
			);
		});
	}

	#[test]
	fn second_submission_commitment_not_found_fails() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c1 = commitment(0x31);
			let c2 = commitment(0x32); // not registered
			register_commitment(c1);

			let submissions = BoundedVec::try_from(vec![submission(c1), submission(c2)]).unwrap();
			assert_noop!(
				batch_submit_proofs::<Test>(&owner, submissions),
				crate::pallet::Error::<Test>::CommitmentNotFound
			);
		});
	}

	#[test]
	fn batch_emits_disclosed_events() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c1 = commitment(0x40);
			let c2 = commitment(0x41);
			register_commitment(c1);
			register_commitment(c2);

			let submissions = BoundedVec::try_from(vec![submission(c1), submission(c2)]).unwrap();
			assert_ok!(batch_submit_proofs::<Test>(&owner, submissions));

			let events = frame_system::Pallet::<Test>::events();
			let disclosed_events: Vec<_> = events
				.iter()
				.filter(|r| {
					matches!(
						r.event,
						crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Disclosed {
							who,
							auditor: None,
							..
						}) if who == owner
					)
				})
				.collect();
			assert_eq!(disclosed_events.len(), 2, "Expected 2 Disclosed events");
		});
	}

	#[test]
	fn batch_with_auditor_submission_works() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;
			let c = commitment(0x50);
			register_commitment(c);
			set_policy_simple(owner, auditor);
			make_request(owner, auditor);

			let submissions =
				BoundedVec::try_from(vec![submission_with_auditor(c, auditor)]).unwrap();
			assert_ok!(batch_submit_proofs::<Test>(&owner, submissions));

			// Record stored under caller (owner) key per current semantics
			assert!(AuditRepository::has_disclosure_record::<Test>(c, &owner));
		});
	}

	#[test]
	fn batch_updates_disclosure_timestamp() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let c = commitment(0x60);
			register_commitment(c);

			let submissions = BoundedVec::try_from(vec![submission(c)]).unwrap();
			assert_ok!(batch_submit_proofs::<Test>(&owner, submissions));

			let ts = crate::pallet::LastDisclosureTimestamp::<Test>::get(owner, c);
			assert_eq!(ts, Some(1u64));
		});
	}

	// ── Flujo A + Flujo B mixed batch ─────────────────────────────────────────
	//
	// Mixing self-disclosure (auditor: None) and audited disclosure
	// (auditor: Some(...)) in the same batch is intentional: each submission is
	// processed independently inside `batch_submit_proofs`. Mixing is valid as
	// long as every individual entry satisfies its own access policy.
	// These tests document and pin that behaviour.

	#[test]
	fn mixed_batch_flujo_a_and_flujo_b_both_succeed() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;

			// Flujo A commitment — no auditor required
			let c_a = commitment(0x70);
			register_commitment(c_a);

			// Flujo B commitment — requires policy + pending request
			let c_b = commitment(0x71);
			register_commitment(c_b);
			set_policy_simple(owner, auditor);
			make_request(owner, auditor);

			let submissions = BoundedVec::try_from(vec![
				submission(c_a),                       // Flujo A
				submission_with_auditor(c_b, auditor), // Flujo B
			])
			.unwrap();

			assert_ok!(batch_submit_proofs::<Test>(&owner, submissions));

			// Both records stored under the owner key
			assert!(AuditRepository::has_disclosure_record::<Test>(c_a, &owner));
			assert!(AuditRepository::has_disclosure_record::<Test>(c_b, &owner));
		});
	}

	#[test]
	fn mixed_batch_emits_correct_events_per_entry() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 2;

			let c_a = commitment(0x72);
			register_commitment(c_a);

			let c_b = commitment(0x73);
			register_commitment(c_b);
			set_policy_simple(owner, auditor);
			make_request(owner, auditor);

			let submissions =
				BoundedVec::try_from(vec![submission(c_a), submission_with_auditor(c_b, auditor)])
					.unwrap();
			assert_ok!(batch_submit_proofs::<Test>(&owner, submissions));

			let events = frame_system::Pallet::<Test>::events();
			let disclosed: Vec<_> = events
				.iter()
				.filter_map(|r| {
					if let crate::mock::RuntimeEvent::ShieldedPool(PalletEvent::Disclosed {
						who,
						commitment,
						auditor: aud,
					}) = &r.event
					{
						Some((*who, *commitment, aud.clone()))
					} else {
						None
					}
				})
				.collect();

			assert_eq!(disclosed.len(), 2);

			// Flujo A: auditor field must be None
			assert!(
				disclosed
					.iter()
					.any(|(who, c, aud)| *who == owner && *c == c_a && aud.is_none()),
				"Expected Disclosed event with auditor=None for Flujo A"
			);
			// Flujo B: auditor field must be Some(auditor)
			assert!(
				disclosed
					.iter()
					.any(|(who, c, aud)| *who == owner && *c == c_b && *aud == Some(auditor)),
				"Expected Disclosed event with auditor=Some({auditor}) for Flujo B"
			);
		});
	}

	#[test]
	fn mixed_batch_fails_when_flujo_b_entry_has_no_policy() {
		new_test_ext().execute_with(|| {
			let owner: u64 = 1;
			let auditor: u64 = 3; // no policy set for this auditor

			let c_a = commitment(0x74);
			register_commitment(c_a);
			let c_b = commitment(0x75);
			register_commitment(c_b);
			// Deliberately NOT calling set_policy_simple / make_request

			let submissions =
				BoundedVec::try_from(vec![submission(c_a), submission_with_auditor(c_b, auditor)])
					.unwrap();

			// The whole batch must be rejected — atomicity guarantees no partial state.
			assert_noop!(
				batch_submit_proofs::<Test>(&owner, submissions),
				crate::pallet::Error::<Test>::UnauthorizedAuditor
			);

			// Neither record should have been stored
			assert!(!AuditRepository::has_disclosure_record::<Test>(c_a, &owner));
			assert!(!AuditRepository::has_disclosure_record::<Test>(c_b, &owner));
		});
	}
}
