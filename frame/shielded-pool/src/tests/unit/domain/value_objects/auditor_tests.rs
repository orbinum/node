//! Tests for auditor

use crate::domain::value_objects::audit::Auditor;

type AccountId = u64;

#[test]
fn can_create_account_auditor() {
	let auditor = Auditor::<AccountId>::account(1);
	assert_eq!(auditor, Auditor::Account(1));
}

#[test]
fn can_create_role_auditor() {
	let role = [1u8; 32];
	let auditor = Auditor::<AccountId>::role(role);
	assert_eq!(auditor, Auditor::Role { role });
}

#[test]
fn can_create_credential_auditor() {
	let credential = [2u8; 32];
	let auditor = Auditor::<AccountId>::credential(credential);
	assert_eq!(auditor, Auditor::CredentialHolder { credential });
}
