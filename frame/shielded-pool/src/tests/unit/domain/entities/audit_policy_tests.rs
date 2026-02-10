//! Tests for audit_policy

use crate::domain::{
	entities::audit::AuditPolicy,
	value_objects::audit::{Auditor, DisclosureCondition},
};
use frame_support::BoundedVec;

type AccountId = u64;
type Balance = u128;
type BlockNumber = u64;

#[test]
fn new_policy_has_version_1() {
	let auditors = BoundedVec::try_from(vec![Auditor::account(1)]).unwrap();
	let conditions = BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();

	let policy = AuditPolicy::<AccountId, Balance, BlockNumber>::new(auditors, conditions);
	assert_eq!(policy.version(), 1);
}

#[test]
fn can_increment_version() {
	let auditors = BoundedVec::try_from(vec![Auditor::account(1)]).unwrap();
	let conditions = BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();

	let mut policy = AuditPolicy::<AccountId, Balance, BlockNumber>::new(auditors, conditions);
	policy.increment_version();
	assert_eq!(policy.version(), 2);
}

#[test]
fn can_set_max_frequency() {
	let auditors = BoundedVec::try_from(vec![Auditor::account(1)]).unwrap();
	let conditions = BoundedVec::try_from(vec![DisclosureCondition::Always]).unwrap();

	let policy = AuditPolicy::<AccountId, Balance, BlockNumber>::new(auditors, conditions)
		.with_max_frequency(100);

	assert_eq!(policy.max_frequency, Some(100));
}
