// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The Orbinum runtime. Compiles with `#[no_std]` for Wasm.
//!
//! | Module | Contents |
//! |---|---|
//! | `primitives` | primitive types, the extrinsic format, constants and the runtime version |
//! | `opaque` | extrinsic-agnostic types for the node, and the session keys |
//! | `configs` | each pallet's `Config`, by domain |
//! | `apis` | the runtime APIs |
//! | `evm` | precompiles, self-contained Ethereum transactions and the H160 ↔ account mapping |
//! | `economy` | where fees, tips, slashes and rewards go |
//! | `staking` | admission, offences, payouts and the staking glue |
//! | `signature` | the extrinsic signature |
//! | `genesis` | genesis presets |
//! | `migrations` | runtime upgrade migrations |
//! | `pallets` | pallets defined in this crate |
//! | `benchmarks` | the pallets `frame-benchmarking` measures |
//!
//! Tests sit beside the module they exercise; `test_utils` holds the helpers they share.

#![cfg_attr(not(feature = "std"), no_std)]
// `#[frame_support::runtime]` expands too deeply for the default limit of 128.
#![recursion_limit = "256"]
#![allow(clippy::new_without_default, clippy::or_fun_call)]
#![cfg_attr(feature = "runtime-benchmarks", warn(unused_crate_dependencies))]

extern crate alloc;

// Linked for its Wasm panic handler and allocator; `as _` silences `unused_crate_dependencies`.
use sp_io as _;

// `#[frame_support::runtime]` names `Vec` unqualified.
use alloc::vec::Vec;

// Before `apis`, which calls the `list_benchmarks!` and `add_benchmarks!` it defines.
#[cfg(feature = "runtime-benchmarks")]
#[macro_use]
mod benchmarks;

mod apis;
mod configs;
mod economy;
mod evm;
mod genesis;
mod migrations;
// Declared here, not in `primitives`: `SessionKeys`' path is part of the metadata.
#[path = "primitives/opaque.rs"]
pub mod opaque;
mod pallets;
mod primitives;
mod signature;
pub mod staking;
mod weights;

#[cfg(test)]
mod test_utils;

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

/// Orbinum-local runtime APIs.
pub use apis::ismp as runtime_api;
#[cfg(feature = "std")]
pub use apis::RuntimeApi;
pub use apis::RUNTIME_API_VERSIONS;
pub use configs::system::{BlockHashCount, SS58Prefix, EXISTENTIAL_DEPOSIT};
pub use evm::account::{
	evm_bytes_to_account_id_bytes, evm_h160_to_account_id, evm_h160_to_account_id_bytes,
};
pub use evm::self_contained::TransactionConverter;
#[cfg(feature = "std")]
pub use primitives::version::native_version;
pub use primitives::version::VERSION;
pub use primitives::{constants::*, types::*};
/// The extrinsic signature. An ECDSA key's account is `[eth_addr ‖ 0x00×12]`, the one
/// `EeSuffixAddressMapping` gives its EVM address.
pub use signature::OrbinumSignature;

pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;

pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
	migrations::Migrations,
>;

#[frame_support::runtime]
mod runtime {
	#[runtime::runtime]
	#[runtime::derive(
		RuntimeEvent,
		RuntimeCall,
		RuntimeError,
		RuntimeOrigin,
		RuntimeFreezeReason,
		RuntimeHoldReason,
		RuntimeSlashReason,
		RuntimeLockId,
		RuntimeTask
	)]
	pub struct Runtime;

	// Genesis and hooks run in index order, whatever the order below. Session (16)
	// builds its genesis before Staking (22) has bonded anyone, so the first session
	// runs on the genesis keys. In each block's hooks: Session rotates (16), Staking
	// applies due slashes (22), AhClient (24) sends the session report that lets
	// staking start an era or plan the next one, AutoPayout (25) sees that era, and
	// RcClient (26) hands an elected set over. The election runs in `on_poll`.
	// Pools (28, 29) have no block hooks; EraPruning (30) works in `on_idle`.

	#[runtime::pallet_index(0)]
	pub type System = frame_system;

	#[runtime::pallet_index(1)]
	pub type Timestamp = pallet_timestamp;

	#[runtime::pallet_index(2)]
	pub type Aura = pallet_aura;

	#[runtime::pallet_index(3)]
	pub type Grandpa = pallet_grandpa;

	#[runtime::pallet_index(4)]
	pub type Balances = pallet_balances;

	#[runtime::pallet_index(5)]
	pub type TransactionPayment = pallet_transaction_payment;

	#[runtime::pallet_index(6)]
	pub type Sudo = pallet_sudo;

	#[runtime::pallet_index(7)]
	pub type Ethereum = pallet_ethereum;

	#[runtime::pallet_index(8)]
	pub type EVM = pallet_evm;

	#[runtime::pallet_index(9)]
	pub type EVMChainId = pallet_evm_chain_id;

	#[runtime::pallet_index(10)]
	pub type BaseFee = pallet_base_fee;

	#[runtime::pallet_index(11)]
	pub type ManualSeal = pallets::manual_seal;

	#[runtime::pallet_index(12)]
	pub type ZkVerifier = pallet_zk_verifier;

	#[runtime::pallet_index(13)]
	pub type ShieldedPool = pallet_shielded_pool;

	// Consensus and sessions.
	#[runtime::pallet_index(14)]
	pub type Authorship = pallet_authorship;

	#[runtime::pallet_index(15)]
	pub type ValidatorSet = pallet_validator_set;

	#[runtime::pallet_index(16)]
	pub type Session = pallet_session;

	#[runtime::pallet_index(17)]
	pub type Historical = pallet_session::historical;

	#[runtime::pallet_index(18)]
	pub type Offences = pallet_offences;

	// ISMP / Hyperbridge. Relayers cache these indices from metadata; keep them fixed.
	// `IsmpGrandpa` is the GRANDPA consensus client that verifies counterparty
	// finality; Orbinum keeps its own consensus (solochain, not a parachain).
	#[runtime::pallet_index(19)]
	pub type Ismp = pallet_ismp;

	#[runtime::pallet_index(20)]
	pub type IsmpGrandpa = ismp_grandpa;

	#[runtime::pallet_index(21)]
	pub type IsmpMessaging = pallet_ismp_messaging;

	// Staking.
	#[runtime::pallet_index(22)]
	pub type Staking = pallet_staking_async;

	#[runtime::pallet_index(23)]
	pub type VoterList = pallet_bags_list<Instance1>;

	// The session side's client: hands the elected set to `Session` and reports
	// each session to staking.
	#[runtime::pallet_index(24)]
	pub type AhClient = pallet_staking_async_ah_client;

	#[runtime::pallet_index(25)]
	pub type AutoPayout = pallet_auto_payout;

	// The staking side's client: hands the elected set to `AhClient` and takes
	// its session reports and offences to staking.
	#[runtime::pallet_index(26)]
	pub type RcClient = pallet_staking_async_rc_client;

	#[runtime::pallet_index(27)]
	pub type PagedElection = pallet_paged_election;

	// Members stake through a pool, one nominator to staking; their funds stay
	// in their accounts, held as delegations (`staking::pools`).
	#[runtime::pallet_index(28)]
	pub type NominationPools = pallet_nomination_pools;

	#[runtime::pallet_index(29)]
	pub type DelegatedStaking = pallet_delegated_staking;

	// Prunes eras past the history from `on_idle` (`staking::pruning`).
	#[runtime::pallet_index(30)]
	pub type EraPruning = staking::pruning;
}
