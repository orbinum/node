//! Pool-rejection codes for unsigned transactions.
//!
//! `InvalidTransaction::Custom` carries a bare `u8`, which reaches operators as
//! `Custom error: N` with no name attached. Naming the codes here keeps the two
//! validators from drifting apart and makes a rejection diagnosable from a log
//! line alone.
//!
//! Codes are part of the observable interface: a wallet or relayer may branch on
//! them, so **never reuse a number for a different meaning** — retire it and add
//! a new one instead.

use sp_runtime::transaction_validity::InvalidTransaction;

/// The Merkle root is not in the historic window and does not anchor a sealed
/// tree, so no proof can be verified against it.
pub const UNKNOWN_ROOT: u8 = 1;

/// Every input nullifier is the dummy sentinel, i.e. the transaction spends
/// nothing. Rejected as anti-spam: it would insert commitments for free.
pub const ALL_INPUTS_DUMMY: u8 = 2;

/// The pool does not hold enough of the asset to cover `amount + fee`.
pub const INSUFFICIENT_POOL_BALANCE: u8 = 3;

/// `amount + fee` overflows the balance type.
pub const AMOUNT_OVERFLOW: u8 = 4;

/// The circuit version is not registered in the verifier, so the proof could
/// never verify. Checked first — it is the cheapest gate of all.
pub const UNSUPPORTED_CIRCUIT_VERSION: u8 = 10;

/// The memos do not have the shape the spend requires: one full memo per output
/// of a transfer; none for a total unshield and a full one for a partial one.
pub const INVALID_MEMO: u8 = 11;

/// The proof does not verify against its public values. Checked last — it is
/// the most expensive gate — and the one that keeps a copy of a pending spend
/// with swapped memos or a higher fee from displacing the original.
pub const INVALID_PROOF: u8 = 12;

/// The spend fails a check the dispatchable runs (duplicate or existing output,
/// zero amount, invalid recipient, unverified asset, …). Admission runs the same
/// checks so that nothing admitted can fail after its proof is verified: such a
/// spend would fill blocks for free without ever spending its nullifier.
pub const INVALID_SPEND: u8 = 13;

/// Build an `InvalidTransaction` from one of the codes above.
pub fn reject(code: u8) -> InvalidTransaction {
	InvalidTransaction::Custom(code)
}
