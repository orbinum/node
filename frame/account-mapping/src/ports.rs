pub trait PrivateLinkVerifierPort {
	fn verify(commitment: &[u8; 32], call_hash: &[u8; 32], proof: &[u8]) -> bool;
}

pub struct DisabledPrivateLinkVerifier;

impl PrivateLinkVerifierPort for DisabledPrivateLinkVerifier {
	fn verify(_commitment: &[u8; 32], _call_hash: &[u8; 32], _proof: &[u8]) -> bool {
		false
	}
}
