//! Tests for disclosure_request

use crate::domain::entities::audit::DisclosureRequest;

use frame_support::BoundedVec;

type AccountId = u64;
type BlockNumber = u64;

#[test]
fn new_request_has_no_evidence() {
	let reason = BoundedVec::try_from(b"AML investigation".to_vec()).unwrap();
	let request = DisclosureRequest::<AccountId, BlockNumber>::new(1, 2, 100, reason);

	assert!(!request.has_evidence());
}

#[test]
fn can_add_evidence() {
	let reason = BoundedVec::try_from(b"AML investigation".to_vec()).unwrap();
	let evidence = BoundedVec::try_from(b"Court order #12345".to_vec()).unwrap();

	let request =
		DisclosureRequest::<AccountId, BlockNumber>::new(1, 2, 100, reason).with_evidence(evidence);

	assert!(request.has_evidence());
}

#[test]
fn getters_work() {
	let reason = BoundedVec::try_from(b"Test".to_vec()).unwrap();
	let request = DisclosureRequest::<AccountId, BlockNumber>::new(1, 2, 100, reason);

	assert_eq!(*request.auditor(), 1);
	assert_eq!(*request.target(), 2);
	assert_eq!(*request.timestamp(), 100);
}
