// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Relay constants, grouped by what they govern.
//!
//! Three roles are kept apart because they answer to different authorities: the
//! admission limits are the relay's own policy, the transaction parameters are
//! what it signs and pays for, and the fallbacks are last-resort copies of state
//! that normally lives on-chain.
//!
//! `RELAY_GAS_LIMIT` deliberately spans two of them — it bounds the transaction
//! the relay signs and, through the 2× gas floor, the fee it demands in return.

use super::operations::{SELECTOR_PRIVATE_TRANSFER, SELECTOR_UNSHIELD};

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

/// ShieldedPool precompile: `0x0000000000000000000000000000000000000801`.
///
/// The only address the relay will call. Anything else is rejected before the
/// selector is even read.
pub(crate) const SHIELDED_POOL_PRECOMPILE: [u8; 20] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x01,
];

// ---------------------------------------------------------------------------
// Admission limits
// ---------------------------------------------------------------------------

/// Maximum calldata size accepted by the relay (32 KB).
///
/// A realistic shielded-pool calldata is ~2–5 KB: a 256 B Groth16 proof plus the
/// ABI head and Merkle path. The cap prevents an attacker from passing the
/// selector and fee checks with megabytes of data the relayer would then pay
/// calldata gas for.
pub(crate) const MAX_CALLDATA_BYTES: usize = 32_768;

// ---------------------------------------------------------------------------
// Transaction parameters
// ---------------------------------------------------------------------------

/// Maximum fee per gas paid by the relay tx (10 gwei).
pub(crate) const MAX_FEE_PER_GAS_WEI: u64 = 10_000_000_000;

/// Gas limit used for relay transactions, and the basis of the 2× gas floor in
/// [`super::validation::compute_effective_min_fee`].
pub(crate) const RELAY_GAS_LIMIT: u64 = 2_000_000;

// ---------------------------------------------------------------------------
// Runtime API fallbacks
// ---------------------------------------------------------------------------

/// Last-resort minimum fee, used ONLY when the `relay_config()` Runtime API call
/// fails entirely — that is, on a node running a pre-API runtime.
///
/// The authoritative value lives in `pallet-relayer::MinRelayFee` and is
/// governance-modifiable via `set_min_relay_fee`. This matches
/// `pallet-relayer::DefaultMinRelayFee` (0.001 ORB) so all three sources agree
/// out of the box.
pub(crate) const MIN_RELAY_FEE_FALLBACK: u128 = 1_000_000_000_000_000; // 0.001 ORB in planck

/// Selector whitelist used on the same fallback path.
///
/// Built from the operation constants — themselves re-exported from the
/// precompile — so this list cannot drift from what the decoder accepts.
pub(crate) const SELECTORS_FALLBACK: [[u8; 4]; 2] = [SELECTOR_UNSHIELD, SELECTOR_PRIVATE_TRANSFER];
