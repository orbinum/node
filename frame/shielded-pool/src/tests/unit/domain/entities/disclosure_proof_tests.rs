//! Tests for disclosure_proof

use crate::domain::entities::{Commitment, audit::DisclosureProof};
use frame_support::BoundedVec;

#[test]
fn new_disclosure_proof_works() {
	let commitment = Commitment::from([1u8; 32]);
	let zk_proof = BoundedVec::try_from(vec![1, 2, 3]).unwrap();
	let disclosed_data = BoundedVec::try_from(vec![4, 5, 6]).unwrap();

	let proof = DisclosureProof::new(commitment, zk_proof, disclosed_data, 12345);

	assert_eq!(*proof.commitment(), commitment);
	assert_eq!(proof.proof_size(), 3);
	assert_eq!(proof.data_size(), 3);
	assert_eq!(proof.timestamp(), 12345);
}
