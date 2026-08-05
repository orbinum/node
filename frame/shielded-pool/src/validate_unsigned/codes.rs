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

/// `amount + fee` overflows the balance type.
///
/// Deliberately distinct from [`ALL_INPUTS_DUMMY`]: both meanings once shared
/// code 2 across the two validators, which made a rejection ambiguous to anyone
/// reading a node log.
pub const AMOUNT_OVERFLOW: u8 = 4;

/// The pool does not hold enough of the asset to cover `amount + fee`.
pub const INSUFFICIENT_POOL_BALANCE: u8 = 3;

/// The circuit version is not registered in the verifier, so the proof could
/// never verify. Checked first — it is the cheapest gate of all.
pub const UNSUPPORTED_CIRCUIT_VERSION: u8 = 10;

/// Build an `InvalidTransaction` from one of the codes above.
pub fn reject(code: u8) -> InvalidTransaction {
	InvalidTransaction::Custom(code)
}
