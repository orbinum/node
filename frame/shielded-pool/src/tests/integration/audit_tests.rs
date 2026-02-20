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

// ============================================================================
// Helpers
// ============================================================================

/// Build valid 76-byte public signals where signals[0..32] matches commitment.
fn make_signals(commitment: &Commitment) -> Vec<u8> {
	let mut signals = vec![0u8; 76];
	signals[0..32].copy_from_slice(&commitment.0); // commitment
	signals[32..40].copy_from_slice(&0u64.to_le_bytes()); // revealed_value (0 = not disclosed)
	signals[40..44].copy_from_slice(&0u32.to_le_bytes()); // revealed_asset_id (0 = not disclosed)
	// signals[44..76] = all zeros (revealed_owner_hash not disclosed)
	signals
}

/// Shield a commitment so it exists in CommitmentMemos.
fn shield_commitment(who: u64, commitment: Commitment) {
	let memo = vec![1u8; MAX_ENCRYPTED_MEMO_SIZE as usize];
	let encrypted_memo = EncryptedMemo::new(memo).unwrap();
	assert_ok!(ShieldedPool::shield(
		RuntimeOrigin::signed(who),
		0, // native asset
		200u128,
		commitment,
		encrypted_memo,
	));
}

/// Set the disclosure VK (bypasses extrinsic; simulates governance setup).
fn set_vk() {
	let vk = vec![1u8; 100];
	crate::DisclosureVerifyingKey::<Test>::put(BoundedVec::try_from(vk).unwrap());
}

// ============================================================================
// set_disclosure_verifying_key
// ============================================================================

#[test]
fn set_disclosure_verifying_key_works() {
	new_test_ext().execute_with(|| {
		let vk = vec![1u8; 200];
		let vk_bounded = BoundedVec::try_from(vk).unwrap();

		assert_ok!(ShieldedPool::set_disclosure_verifying_key(
			RuntimeOrigin::root(),
			vk_bounded,
		));

		// VK is stored
		assert!(crate::DisclosureVerifyingKey::<Test>::get().is_some());

		// Event emitted
		System::assert_last_event(Event::DisclosureVerifyingKeyUpdated { vk_size: 200 }.into());
	});
}

#[test]
fn set_disclosure_verifying_key_fails_not_root() {
	new_test_ext().execute_with(|| {
		let vk = vec![1u8; 200];
		let vk_bounded = BoundedVec::try_from(vk).unwrap();

		assert_noop!(
			ShieldedPool::set_disclosure_verifying_key(RuntimeOrigin::signed(1), vk_bounded,),
			frame_support::error::BadOrigin
		);
	});
}

// ============================================================================
// submit_disclosure – happy paths
// ============================================================================

#[test]
fn submit_disclosure_works_no_policy_no_auditor() {
	new_test_ext().execute_with(|| {
		let who = 1u64;
		let commitment = Commitment([10u8; 32]);

		shield_commitment(who, commitment);
		set_vk();

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(make_signals(&commitment)).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_ok!(ShieldedPool::submit_disclosure(
			RuntimeOrigin::signed(who),
			commitment,
			proof,
			signals,
			partial,
			None, // no auditor
		));

		// Proof is stored
		assert!(crate::DisclosureProofs::<Test>::contains_key(commitment));

		// DisclosureVerified event
		System::assert_has_event(
			Event::DisclosureVerified {
				who,
				commitment,
				verified: true,
			}
			.into(),
		);
	});
}

#[test]
fn submit_disclosure_stores_rate_limit_timestamp() {
	new_test_ext().execute_with(|| {
		let who = 1u64;
		let commitment = Commitment([20u8; 32]);

		shield_commitment(who, commitment);
		set_vk();

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(make_signals(&commitment)).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_ok!(ShieldedPool::submit_disclosure(
			RuntimeOrigin::signed(who),
			commitment,
			proof,
			signals,
			partial,
			None,
		));

		// Rate-limiting timestamp stored
		assert!(crate::LastDisclosureTimestamp::<Test>::get(who, commitment).is_some());
	});
}

#[test]
fn submit_disclosure_with_auditor_works() {
	new_test_ext().execute_with(|| {
		let owner = 1u64;
		let auditor = 2u64;
		let commitment = Commitment([30u8; 32]);

		// Setup: shield, VK, policy, request
		shield_commitment(owner, commitment);
		set_vk();

		let auditor_enum = Auditor::Account(auditor);
		let conds = BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();
		let auds = BoundedVec::try_from(vec![auditor_enum]).unwrap();
		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(owner),
			auds,
			conds,
			None,
		));
		let reason = BoundedVec::try_from(b"Tax audit".to_vec()).unwrap();
		assert_ok!(ShieldedPool::request_disclosure(
			RuntimeOrigin::signed(auditor),
			owner,
			reason,
			None,
		));

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(make_signals(&commitment)).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_ok!(ShieldedPool::submit_disclosure(
			RuntimeOrigin::signed(owner),
			commitment,
			proof,
			signals,
			partial,
			Some(auditor),
		));

		// Proof stored and audit trail created
		assert!(crate::DisclosureProofs::<Test>::contains_key(commitment));
		assert_eq!(crate::NextAuditTrailId::<Test>::get(), 1);
	});
}

// ============================================================================
// submit_disclosure – error paths
// ============================================================================

#[test]
fn submit_disclosure_fails_commitment_not_found() {
	new_test_ext().execute_with(|| {
		let who = 1u64;
		let commitment = Commitment([99u8; 32]); // never shielded

		set_vk();

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(make_signals(&commitment)).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_noop!(
			ShieldedPool::submit_disclosure(
				RuntimeOrigin::signed(who),
				commitment,
				proof,
				signals,
				partial,
				None,
			),
			Error::<Test>::CommitmentNotFound
		);
	});
}

#[test]
fn submit_disclosure_fails_verifying_key_not_set() {
	new_test_ext().execute_with(|| {
		let who = 1u64;
		let commitment = Commitment([11u8; 32]);

		shield_commitment(who, commitment);
		// intentionally skip set_vk()

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(make_signals(&commitment)).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_noop!(
			ShieldedPool::submit_disclosure(
				RuntimeOrigin::signed(who),
				commitment,
				proof,
				signals,
				partial,
				None,
			),
			Error::<Test>::VerifyingKeyNotSet
		);
	});
}

#[test]
fn submit_disclosure_fails_invalid_proof_size() {
	new_test_ext().execute_with(|| {
		let who = 1u64;
		let commitment = Commitment([12u8; 32]);

		shield_commitment(who, commitment);
		set_vk();

		// Proof too short (not 256 bytes)
		let proof = BoundedVec::try_from(vec![1u8; 100]).unwrap();
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(make_signals(&commitment)).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_noop!(
			ShieldedPool::submit_disclosure(
				RuntimeOrigin::signed(who),
				commitment,
				proof,
				signals,
				partial,
				None,
			),
			Error::<Test>::InvalidProof
		);
	});
}

#[test]
fn submit_disclosure_fails_invalid_signals_length() {
	new_test_ext().execute_with(|| {
		let who = 1u64;
		let commitment = Commitment([13u8; 32]);

		shield_commitment(who, commitment);
		set_vk();

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		// Wrong length (not 76 bytes)
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(vec![0u8; 32]).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_noop!(
			ShieldedPool::submit_disclosure(
				RuntimeOrigin::signed(who),
				commitment,
				proof,
				signals,
				partial,
				None,
			),
			Error::<Test>::InvalidPublicSignals
		);
	});
}

#[test]
fn submit_disclosure_fails_signals_commitment_mismatch() {
	new_test_ext().execute_with(|| {
		let who = 1u64;
		let commitment = Commitment([14u8; 32]);

		shield_commitment(who, commitment);
		set_vk();

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		// Signals with wrong commitment (all zeros vs [14u8; 32])
		let mut signals_raw = vec![0u8; 76];
		signals_raw[0..32].copy_from_slice(&[99u8; 32]); // mismatch!
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(signals_raw).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_noop!(
			ShieldedPool::submit_disclosure(
				RuntimeOrigin::signed(who),
				commitment,
				proof,
				signals,
				partial,
				None,
			),
			Error::<Test>::InvalidPublicSignals
		);
	});
}

#[test]
fn submit_disclosure_fails_no_policy_with_auditor() {
	new_test_ext().execute_with(|| {
		let who = 1u64;
		let auditor = 2u64;
		let commitment = Commitment([15u8; 32]);

		shield_commitment(who, commitment);
		set_vk();
		// No audit policy set for `who`

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(make_signals(&commitment)).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		assert_noop!(
			ShieldedPool::submit_disclosure(
				RuntimeOrigin::signed(who),
				commitment,
				proof,
				signals,
				partial,
				Some(auditor), // auditor specified but no policy
			),
			Error::<Test>::UnauthorizedAuditor
		);
	});
}

#[test]
fn submit_disclosure_fails_unauthorized_auditor_in_policy() {
	new_test_ext().execute_with(|| {
		let owner = 1u64;
		let authorized_auditor = 2u64;
		let unauthorized_auditor = 3u64;
		let commitment = Commitment([16u8; 32]);

		shield_commitment(owner, commitment);
		set_vk();

		// Policy only authorizes auditor 2
		let auds = BoundedVec::try_from(vec![Auditor::Account(authorized_auditor)]).unwrap();
		let conds = BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();
		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(owner),
			auds,
			conds,
			None,
		));

		let proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let signals: BoundedVec<u8, _> = BoundedVec::try_from(make_signals(&commitment)).unwrap();
		let partial = BoundedVec::try_from(vec![0u8; 10]).unwrap();

		// Auditor 3 is not in the policy
		assert_noop!(
			ShieldedPool::submit_disclosure(
				RuntimeOrigin::signed(owner),
				commitment,
				proof,
				signals,
				partial,
				Some(unauthorized_auditor),
			),
			Error::<Test>::UnauthorizedAuditor
		);
	});
}

// ============================================================================
// reject_disclosure – error paths
// ============================================================================

#[test]
fn reject_disclosure_fails_request_not_found() {
	new_test_ext().execute_with(|| {
		let target = 1u64;
		let auditor = 2u64;

		// No request active → reject should fail
		let reason = BoundedVec::try_from(b"No request".to_vec()).unwrap();
		assert_noop!(
			ShieldedPool::reject_disclosure(RuntimeOrigin::signed(target), auditor, reason,),
			Error::<Test>::DisclosureRequestNotFound
		);
	});
}

// ============================================================================
// approve_disclosure – error paths
// ============================================================================

#[test]
fn approve_disclosure_fails_request_not_found() {
	new_test_ext().execute_with(|| {
		let target = 1u64;
		let auditor = 2u64;
		let commitment = Commitment([50u8; 32]);

		// Shield so commitment exists, but never request disclosure
		shield_commitment(target, commitment);
		set_vk();

		let zk_proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let disclosed_data = BoundedVec::try_from(vec![2u8; 50]).unwrap();

		assert_noop!(
			ShieldedPool::approve_disclosure(
				RuntimeOrigin::signed(target),
				auditor,
				commitment,
				zk_proof,
				disclosed_data,
			),
			Error::<Test>::DisclosureRequestNotFound
		);
	});
}

#[test]
fn approve_disclosure_fails_invalid_proof_when_commitment_not_shielded() {
	new_test_ext().execute_with(|| {
		let target = 1u64;
		let auditor = 2u64;
		let commitment = Commitment([51u8; 32]); // never shielded

		// Setup policy + request (without shielding)
		let auds = BoundedVec::try_from(vec![Auditor::Account(auditor)]).unwrap();
		let conds = BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();
		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(target),
			auds,
			conds,
			None,
		));
		let reason = BoundedVec::try_from(b"audit".to_vec()).unwrap();
		assert_ok!(ShieldedPool::request_disclosure(
			RuntimeOrigin::signed(auditor),
			target,
			reason,
			None,
		));

		let zk_proof = BoundedVec::try_from(vec![1u8; 256]).unwrap();
		let disclosed_data = BoundedVec::try_from(vec![2u8; 50]).unwrap();

		assert_noop!(
			ShieldedPool::approve_disclosure(
				RuntimeOrigin::signed(target),
				auditor,
				commitment,
				zk_proof,
				disclosed_data,
			),
			Error::<Test>::InvalidDisclosureProof
		);
	});
}

// ============================================================================
// request_disclosure – additional error paths
// ============================================================================

#[test]
fn request_disclosure_fails_no_audit_policy() {
	new_test_ext().execute_with(|| {
		let target = 1u64;
		let auditor = 2u64;

		// target never called set_audit_policy
		let reason = BoundedVec::try_from(b"Regulatory".to_vec()).unwrap();
		assert_noop!(
			ShieldedPool::request_disclosure(RuntimeOrigin::signed(auditor), target, reason, None,),
			Error::<Test>::AuditPolicyNotFound
		);
	});
}

#[test]
fn request_disclosure_fails_duplicate_request() {
	new_test_ext().execute_with(|| {
		let target = 1u64;
		let auditor = 2u64;

		let auds = BoundedVec::try_from(vec![Auditor::Account(auditor)]).unwrap();
		let conds = BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();
		assert_ok!(ShieldedPool::set_audit_policy(
			RuntimeOrigin::signed(target),
			auds,
			conds,
			None,
		));

		let reason = BoundedVec::try_from(b"First request".to_vec()).unwrap();
		assert_ok!(ShieldedPool::request_disclosure(
			RuntimeOrigin::signed(auditor),
			target,
			reason,
			None,
		));

		// Second request from same auditor → duplicate
		let reason2 = BoundedVec::try_from(b"Second request".to_vec()).unwrap();
		assert_noop!(
			ShieldedPool::request_disclosure(RuntimeOrigin::signed(auditor), target, reason2, None,),
			Error::<Test>::DisclosureRequestAlreadyExists
		);
	});
}
