//! Tests for audit_trail

use crate::domain::entities::audit::AuditTrail;

use frame_support::BoundedVec;

type AccountId = u64;
type BlockNumber = u64;

#[test]
fn new_audit_trail_works() {
	let disclosure_type = BoundedVec::try_from(b"balance".to_vec()).unwrap();
	let trail_hash = [1u8; 32];

	let trail = AuditTrail::<AccountId, BlockNumber>::new(1, 2, 100, disclosure_type, trail_hash);

	assert_eq!(*trail.account(), 1);
	assert_eq!(*trail.auditor(), 2);
	assert_eq!(*trail.timestamp(), 100);
	assert_eq!(*trail.trail_hash(), trail_hash);
}

#[test]
fn verify_hash_works() {
	let disclosure_type = BoundedVec::try_from(b"balance".to_vec()).unwrap();
	let trail_hash = [1u8; 32];

	let trail = AuditTrail::<AccountId, BlockNumber>::new(1, 2, 100, disclosure_type, trail_hash);

	assert!(trail.verify_hash(&trail_hash));
	assert!(!trail.verify_hash(&[2u8; 32]));
}
