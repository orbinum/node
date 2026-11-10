//! The interface other pallets verify through: [`ZkVerifierPort`] and the
//! statements it takes.
//!
//! A caller (e.g. `pallet-shielded-pool`) depends only on this trait, never on
//! the pallet's internals. It describes a spend as a statement of domain values;
//! turning it into field elements is [`crate::encoding`]'s job.

use alloc::vec::Vec;

/// What a private-transfer proof attests to, as the pallet submits it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransferStatement {
	/// The root each input note is proven against. Equal unless the notes come
	/// from different trees, which only a cross-tree key can attest to.
	pub merkle_roots: [[u8; 32]; 2],
	/// One per input note.
	pub nullifiers: Vec<[u8; 32]>,
	/// One per output note, in the order their memos are submitted.
	pub commitments: Vec<[u8; 32]>,
	/// The asset of every note.
	pub asset_id: u32,
	/// Relay fee, taken from the inputs.
	pub fee: u128,
	/// `blake2_256` of the SCALE-encoded output memos; every transfer key binds it.
	pub memo_digest: [u8; 32],
}

/// What an unshield proof attests to, as the pallet submits it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UnshieldStatement {
	/// The root the spent note is proven against.
	pub merkle_root: [u8; 32],
	/// The spent note's nullifier.
	pub nullifier: [u8; 32],
	/// What the recipient receives.
	pub amount: u128,
	/// The recipient account's raw 32 bytes. See [`crate::encoding::encode_unshield`].
	pub recipient: [u8; 32],
	/// The asset of the spent note.
	pub asset_id: u32,
	/// Relay fee, taken from the note.
	pub fee: u128,
	/// Zero for a total unshield.
	pub change_commitment: [u8; 32],
	/// `blake2_256` of the SCALE-encoded `[change_memo]`; every unshield key binds it.
	pub memo_digest: [u8; 32],
}

/// What a shield proof attests to: the inserted commitment opens to the
/// deposited value and asset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShieldStatement {
	/// The commitment inserted into the tree.
	pub commitment: [u8; 32],
	/// The deposited value.
	pub value: u128,
	/// The deposited asset.
	pub asset_id: u32,
}

/// Cross-pallet interface for zero-knowledge proof verification.
///
/// `version` selects the verifying key; `None` means the circuit's active one.
/// `Ok(false)` is an invalid proof, `Err` a request that cannot be checked.
pub trait ZkVerifierPort {
	/// Verify a private transfer proof (2-in / 2-out).
	fn verify_transfer_proof(
		proof: &[u8],
		statement: &TransferStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Verify an unshield (pool withdrawal) proof.
	fn verify_unshield_proof(
		proof: &[u8],
		statement: &UnshieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Verify a shield (pool deposit) proof.
	fn verify_shield_proof(
		proof: &[u8],
		statement: &ShieldStatement,
		version: Option<u32>,
	) -> Result<bool, sp_runtime::DispatchError>;

	/// Whether `version` is registered for `circuit_id` and not retired.
	fn is_supported_version(circuit_id: u32, version: u32) -> bool;

	/// Weight of one `verify_*_proof` call: key read, preparation and the
	/// pairing. A caller that verifies a proof must add it to its own weight.
	fn verification_weight() -> frame_support::weights::Weight;
}
