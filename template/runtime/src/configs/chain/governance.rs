// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Who may perform each privileged action, by role. Every role is root (sudo); moving
//! one to a multisig, a council or an OpenGov track means changing its alias.
//!
//! Root regardless of these roles: the runtime itself (`system.set_code` and storage),
//! `sudo`, the base fee (`baseFee.set_*`), manual seal's switch and staking's bonds, counts and eras (see [`StakingAdmin`]), which
//! check root in code.

use crate::AccountId;
use frame_system::EnsureRoot;

/// Staking's admin calls (cancelling deferred slashes, the commission floor and
/// ceiling, restoring ledgers, migrating controllers in batch, the validator
/// self-stake incentive), nomination pools' limits (`set_configs`) and aborting
/// an election.
///
/// Not staking's bonds, counts and eras: `set_staking_configs`,
/// `set_validator_count`, `increase_validator_count`, `scale_validator_count`,
/// `force_no_eras`, `force_new_era`, `force_new_era_always` and `force_unstake`
/// check root in code, whatever this alias becomes. Nor ah-client's mode
/// (`set_mode`, `force_on_migration_end`): `LocalRelayFilter` refuses every
/// client call, so only root, which skips the filter, reaches them.
pub type StakingAdmin = EnsureRoot<AccountId>;

/// Validator admission: the allowlist, bans, the admission mode and the
/// minimum author version.
pub type AdmissionAdmin = EnsureRoot<AccountId>;

/// Automatic reward payment: its limits and pausing it.
pub type PayoutAdmin = EnsureRoot<AccountId>;

/// Cross-chain trust: the consensus clients and state machines ISMP accepts
/// proofs from (`pallet-ismp`), the GRANDPA chains its client follows
/// (`ismp-grandpa`), and the sources, fee and outbound pause of our messaging
/// (`ismp-messaging`).
pub type CrossChainAdmin = EnsureRoot<AccountId>;

/// Zero-knowledge circuits: registering, activating, retiring, denying and
/// removing verification keys (`pallet-zk-verifier`).
pub type CircuitAdmin = EnsureRoot<AccountId>;

/// The shielded pool's asset registry: registering, verifying and unverifying
/// assets.
pub type ShieldedAssetAdmin = EnsureRoot<AccountId>;
