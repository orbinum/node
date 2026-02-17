//! Audit and disclosure tests
//!
//! Tests for audit policies, disclosure requests, and compliance.

use crate::{
	Commitment, Error, Event,
	domain::{
		entities::audit::AuditPolicy,
		value_objects::audit::{Auditor, DisclosureCondition},
	},
	infrastructure::frame_types::{EncryptedMemo, MAX_ENCRYPTED_MEMO_SIZE},
	mock::*,
};
use frame_support::{BoundedVec, assert_noop, assert_ok};

// ============================================================================

#[test]
fn set_audit_policy_works() {
	new_test_ext().execute_with(|| {
		let account = 1;
		let auditor = Auditor::Account(2);

		let conditions = vec![DisclosureCondition::Always];
		let conditions_bounded = BoundedVec::try_from(conditions).unwrap();

		let auditors = vec![auditor.clone()];
		let auditors_bounded = BoundedVec::try_from(auditors).unwrap();

		let _policy = AuditPolicy {
			auditors: auditors_bounded.clone(),
			conditions: conditions_bounded.clone(),
			max_frequency: Some(100),
			version: 1,
		};

		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(account),
			auditors_bounded.clone(),
			conditions_bounded.clone(),
			Some(100),
		));

		// Verify policy is stored
		let expected_policy = AuditPolicy {
			auditors: auditors_bounded,
			conditions: conditions_bounded,
			max_frequency: Some(100),
			version: 1,
		};
		assert_eq!(
			crate::AuditPolicies::<Test>::get(account),
			Some(expected_policy)
		);

		// Verify event
		System::assert_last_event(
			Event::AuditPolicySet {
				account,
				version: 1,
			}
			.into(),
		);
	});
}

#[test]
fn request_disclosure_works() {
	new_test_ext().execute_with(|| {
		let target = 1;
		let auditor = 2;

		// First set an audit policy
		let auditor_enum = Auditor::Account(auditor);
		let conditions = vec![DisclosureCondition::Always];
		let conditions_bounded = BoundedVec::try_from(conditions).unwrap();
		let auditors = vec![auditor_enum];
		let auditors_bounded = BoundedVec::try_from(auditors).unwrap();

		let _policy = AuditPolicy {
			auditors: auditors_bounded.clone(),
			conditions: conditions_bounded.clone(),
			max_frequency: Some(100),
			version: 1,
		};

		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(target),
			auditors_bounded,
			conditions_bounded,
			Some(100),
		));

		// Request disclosure
		let reason = b"Regulatory compliance".to_vec();
		let reason_bounded = BoundedVec::try_from(reason.clone()).unwrap();

		assert_ok!(ShieldedPool::request_disclosure(
			RuntimeOrigin::signed(auditor),
			target,
			reason_bounded,
			None,
		));

		// Verify request is stored
		let request = crate::DisclosureRequests::<Test>::get(target, auditor);
		assert!(request.is_some());

		// Verify event
		System::assert_last_event(
			Event::DisclosureRequested {
				target,
				auditor,
				reason: reason.try_into().unwrap(),
			}
			.into(),
		);
	});
}

#[test]
fn request_disclosure_fails_unauthorized_auditor() {
	new_test_ext().execute_with(|| {
		let target = 1;
		let unauthorized_auditor = 3;
		let authorized_auditor = 2;

		// Set policy with only authorized auditor
		let auditor_enum = Auditor::Account(authorized_auditor);
		let conditions = vec![DisclosureCondition::Always];
		let conditions_bounded = BoundedVec::try_from(conditions).unwrap();
		let auditors = vec![auditor_enum];
		let auditors_bounded = BoundedVec::try_from(auditors).unwrap();

		let _policy = AuditPolicy {
			auditors: auditors_bounded.clone(),
			conditions: conditions_bounded.clone(),
			max_frequency: Some(100),
			version: 1,
		};

		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(target),
			auditors_bounded,
			conditions_bounded,
			Some(100),
		));

		// Try to request disclosure with unauthorized auditor
		let reason = b"Unauthorized request".to_vec();
		let reason_bounded = BoundedVec::try_from(reason).unwrap();

		assert_noop!(
			ShieldedPool::request_disclosure(
				RuntimeOrigin::signed(unauthorized_auditor),
				target,
				reason_bounded,
				None,
			),
			Error::<Test>::AuditorNotAuthorized
		);
	});
}

#[test]
fn approve_disclosure_works() {
	new_test_ext().execute_with(|| {
		let target = 1;
		let auditor = 2;
		let commitment = Commitment([42u8; 32]);

		// Configure verifying key (required for production)
		let vk = vec![1u8; 100];
		let vk_bounded = BoundedVec::try_from(vk).unwrap();
		crate::DisclosureVerifyingKey::<Test>::put(vk_bounded);

		// First, create a shield transaction to insert the commitment with a memo
		let amount = 200u128;
		let memo = vec![1u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
		let encrypted_memo = EncryptedMemo::new(memo).unwrap();

		assert_ok!(ShieldedPool::shield(
			RuntimeOrigin::signed(target),
			0, // native asset
			amount,
			commitment,
			encrypted_memo,
		));

		// Set up audit policy and request
		let auditor_enum = Auditor::Account(auditor);
		let conditions = vec![DisclosureCondition::Always];
		let conditions_bounded = BoundedVec::try_from(conditions).unwrap();
		let auditors = vec![auditor_enum];
		let auditors_bounded = BoundedVec::try_from(auditors).unwrap();

		let _policy = AuditPolicy {
			auditors: auditors_bounded.clone(),
			conditions: conditions_bounded.clone(),
			max_frequency: Some(100),
			version: 1,
		};

		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(target),
			auditors_bounded,
			conditions_bounded,
			Some(100),
		));

		let reason = b"Test disclosure".to_vec();
		let reason_bounded = BoundedVec::try_from(reason).unwrap();

		assert_ok!(ShieldedPool::request_disclosure(
			RuntimeOrigin::signed(auditor),
			target,
			reason_bounded,
			None,
		));

		// Approve disclosure with valid proof size (256+ bytes for Groth16)
		let zk_proof = vec![1u8; 256];
		let zk_proof_bounded = BoundedVec::try_from(zk_proof).unwrap();
		let disclosed_data = vec![2u8; 50];
		let disclosed_data_bounded = BoundedVec::try_from(disclosed_data).unwrap();

		assert_ok!(ShieldedPool::approve_disclosure(
			RuntimeOrigin::signed(target),
			auditor,
			commitment,
			zk_proof_bounded,
			disclosed_data_bounded,
		));

		// Verify proof is stored
		let proof = crate::DisclosureProofs::<Test>::get(commitment);
		assert!(proof.is_some());

		// Verify request is removed
		let request = crate::DisclosureRequests::<Test>::get(target, auditor);
		assert!(request.is_none());

		// Verify audit trail is created
		let trail_count = crate::NextAuditTrailId::<Test>::get();
		assert_eq!(trail_count, 1);

		// Verify event (we need to get the trail_hash from storage)
		let trail_hash = crate::AuditTrailStorage::<Test>::iter().next().unwrap().0;
		System::assert_last_event(
			Event::DisclosureApproved {
				target,
				auditor,
				commitment,
				trail_hash,
			}
			.into(),
		);
	});
}

#[test]
fn reject_disclosure_works() {
	new_test_ext().execute_with(|| {
		let target = 1;
		let auditor = 2;

		// Set up audit policy and request
		let auditor_enum = Auditor::Account(auditor);
		let conditions = vec![DisclosureCondition::Always];
		let conditions_bounded = BoundedVec::try_from(conditions).unwrap();
		let auditors = vec![auditor_enum];
		let auditors_bounded = BoundedVec::try_from(auditors).unwrap();

		let _policy = AuditPolicy {
			auditors: auditors_bounded.clone(),
			conditions: conditions_bounded.clone(),
			max_frequency: Some(100),
			version: 1,
		};

		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(target),
			auditors_bounded,
			conditions_bounded,
			Some(100),
		));

		let reason = b"Test disclosure".to_vec();
		let reason_bounded = BoundedVec::try_from(reason).unwrap();

		assert_ok!(ShieldedPool::request_disclosure(
			RuntimeOrigin::signed(auditor),
			target,
			reason_bounded,
			None,
		));

		// Reject disclosure
		let reject_reason = b"Insufficient evidence".to_vec();
		let reject_reason_bounded = BoundedVec::try_from(reject_reason.clone()).unwrap();

		assert_ok!(ShieldedPool::reject_disclosure(
			RuntimeOrigin::signed(target),
			auditor,
			reject_reason_bounded,
		));

		// Verify request is removed
		let request = crate::DisclosureRequests::<Test>::get(target, auditor);
		assert!(request.is_none());

		// Verify event
		System::assert_last_event(
			Event::DisclosureRejected {
				target,
				auditor,
				reason: reject_reason.try_into().unwrap(),
			}
			.into(),
		);
	});
}

// ============================================================================

#[test]
fn batch_submit_disclosure_proofs_works() {
	new_test_ext().execute_with(|| {
		let who = 1;

		// 1. Setup VK
		let vk = vec![1u8; 100];
		let vk_bounded = BoundedVec::try_from(vk).unwrap();
		crate::DisclosureVerifyingKey::<Test>::put(vk_bounded);

		// 2. Prepare 3 submissions
		let mut submissions = vec![];
		for i in 0..3 {
			let commitment = Commitment([i as u8; 32]);

			// Setup required states for each (commitment memo exists)
			let memo = vec![1u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
			crate::CommitmentMemos::<Test>::insert(commitment, EncryptedMemo::new(memo).unwrap());

			// Construct valid 76-byte public signals
			let mut signals = vec![0u8; 76];
			signals[0..32].copy_from_slice(&commitment.0); // 1. Commitment (32 bytes)
			signals[32..40].copy_from_slice(&100u64.to_le_bytes()); // 2. revealed_value (8 bytes u64)
			signals[40..44].copy_from_slice(&0u32.to_le_bytes()); // 3. revealed_asset_id (4 bytes u32)
			signals[44..76].copy_from_slice(&[1u8; 32]); // 4. revealed_owner_hash (32 bytes)

			submissions.push(crate::BatchDisclosureSubmission {
				commitment,
				proof: BoundedVec::try_from(vec![1u8; 256]).unwrap(),
				public_signals: BoundedVec::try_from(signals).unwrap(),
				disclosed_data: BoundedVec::try_from(vec![3u8; 50]).unwrap(),
			});
		}
		let submissions_bounded = BoundedVec::try_from(submissions).unwrap();

		// 3. Execute batch submit
		assert_ok!(ShieldedPool::batch_submit_disclosure_proofs(
			RuntimeOrigin::signed(who),
			submissions_bounded,
		));

		// 4. Verify all proofs are stored
		for i in 0..3 {
			let commitment = Commitment([i as u8; 32]);
			assert!(crate::DisclosureProofs::<Test>::contains_key(commitment));

			// Verify events
			System::assert_has_event(
				Event::DisclosureVerified {
					who,
					commitment,
					verified: true,
				}
				.into(),
			);
		}
	});
}

#[test]
fn batch_submit_disclosure_stress_test() {
	new_test_ext().execute_with(|| {
		let who = 1;
		let vk = vec![1u8; 100];
		crate::DisclosureVerifyingKey::<Test>::put(BoundedVec::try_from(vk).unwrap());

		// Stress test: maximum batch size (10)
		let mut submissions = vec![];
		for i in 0..10 {
			let commitment = Commitment([i as u8; 32]);
			let memo = vec![1u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
			crate::CommitmentMemos::<Test>::insert(commitment, EncryptedMemo::new(memo).unwrap());

			// Construct valid 76-byte public signals
			let mut signals = vec![0u8; 76];
			signals[0..32].copy_from_slice(&commitment.0); // 1. Commitment (32 bytes)
			signals[32..40].copy_from_slice(&100u64.to_le_bytes()); // 2. revealed_value (8 bytes u64)
			signals[40..44].copy_from_slice(&0u32.to_le_bytes()); // 3. revealed_asset_id (4 bytes u32)
			signals[44..76].copy_from_slice(&[1u8; 32]); // 4. revealed_owner_hash (32 bytes)

			submissions.push(crate::BatchDisclosureSubmission {
				commitment,
				proof: BoundedVec::try_from(vec![1u8; 256]).unwrap(),
				public_signals: BoundedVec::try_from(signals).unwrap(),
				disclosed_data: BoundedVec::try_from(vec![3u8; 50]).unwrap(),
			});
		}
		let submissions_bounded = BoundedVec::try_from(submissions).unwrap();

		// Measuring performance in terms of dispatch success
		assert_ok!(ShieldedPool::batch_submit_disclosure_proofs(
			RuntimeOrigin::signed(who),
			submissions_bounded,
		));

		// Verify atomicity (all 10 processed)
		let stored_count = crate::DisclosureProofs::<Test>::iter().count();
		assert_eq!(stored_count, 10);
	});
}
