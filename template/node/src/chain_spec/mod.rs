//! Chain specifications for Orbinum Node.
//!
//! Each submodule covers one network environment:
//! - [`dev`]     — single-validator development node (`--dev`)
//! - [`local`]   — two-validator local testnet (Alice + Bob)
//! - [`testnet`] — public Orbinum Testnet, chain ID 2700
//! - [`mainnet`] — Orbinum Mainnet stub, chain ID 270 (not yet launched)

mod dev;
mod local;
mod mainnet;
mod testnet;

pub use dev::development_config;
pub use local::local_testnet_config;
pub use mainnet::orbinum_mainnet_config;
pub use testnet::orbinum_testnet_config;

use sc_chain_spec::Properties;
pub(crate) use sp_consensus_aura::sr25519::AuthorityId as AuraId;
pub(crate) use sp_consensus_grandpa::AuthorityId as GrandpaId;
#[allow(unused_imports)]
pub use sp_core::ecdsa;
use sp_core::{ed25519, sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};

use orbinum_runtime::{evm_bytes_to_account_id_bytes, AccountId, Balance, SS58Prefix, Signature};

pub type ChainSpec = sc_service::GenericChainSpec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Smallest indivisible unit of ORB (1 ORB = 10^18 planck).
pub(crate) const PLANCK: Balance = 1_000_000_000_000_000_000;

/// Total ORB supply minted at genesis: 1,000,000,000 ORB.
pub(crate) const TOTAL_SUPPLY: Balance = 1_000_000_000 * PLANCK;

/// Small operational balance granted to the sudo account.
pub(crate) const DEV_BALANCE: Balance = 10_000 * PLANCK;

/// Initial faucet allocation: 100,000,000 ORB.
pub(crate) const FAUCET_BALANCE: Balance = 100_000_000 * PLANCK;

/// EVM chain ID for Orbinum Mainnet (registered in ChainList).
pub(crate) const EVM_CHAIN_ID: u64 = 270;

/// EVM chain ID for Orbinum Testnet (registered in ChainList).
pub(crate) const TESTNET_EVM_CHAIN_ID: u64 = 2700;

/// Initial base fee per gas for testnet genesis: 1 gwei.
/// EIP-1559 adjusts this value dynamically with network traffic.
pub(crate) const TESTNET_BASE_FEE: u64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Converts a 20-byte Ethereum address into a Substrate `AccountId`.
pub(crate) fn ethereum_account_id(eth_address: [u8; 20]) -> AccountId {
	evm_bytes_to_account_id_bytes(eth_address).into()
}

/// Wraps a raw 32-byte Sr25519 public key as an `AuraId`.
pub(crate) fn aura_id(bytes: [u8; 32]) -> AuraId {
	sr25519::Public::from_raw(bytes).into()
}

/// Wraps a raw 32-byte Ed25519 public key as a `GrandpaId`.
pub(crate) fn grandpa_id(bytes: [u8; 32]) -> GrandpaId {
	ed25519::Public::from_raw(bytes).into()
}

/// Derives a public key from a well-known dev seed (e.g. `"Alice"`, `"Bob"`).
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{seed}"), None)
		.expect("static values are valid; qed")
		.public()
}

#[allow(dead_code)]
type AccountPublic = <Signature as Verify>::Signer;

/// Derives a Substrate `AccountId` from a well-known dev seed.
#[allow(dead_code)]
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Derives an `(AuraId, GrandpaId)` pair from a well-known dev seed.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

/// Constructs an `orbinum_runtime::opaque::SessionKeys` value from an Aura and GRANDPA key.
///
/// Used in chain-spec genesis patches to populate `session.keys`.
pub(crate) fn session_keys(
	aura: AuraId,
	grandpa: GrandpaId,
) -> orbinum_runtime::opaque::SessionKeys {
	orbinum_runtime::opaque::SessionKeys { aura, grandpa }
}

/// Derives a validator's `AccountId` from their Aura (sr25519) public key.
///
/// The validator's on-chain identity IS their sr25519 key — the same 32 bytes
/// serve as both `AccountId32` and `AuraId`.
pub(crate) fn aura_to_account(aura: &AuraId) -> orbinum_runtime::AccountId {
	let raw: [u8; 32] = <[u8; 32]>::try_from(aura.as_ref()).expect("AuraId is 32 bytes");
	orbinum_runtime::AccountId::from(raw)
}

/// Common `Properties` shared by all Orbinum chain configurations.
pub(crate) fn properties() -> Properties {
	let mut properties = Properties::new();
	properties.insert("tokenSymbol".into(), "ORB".into());
	properties.insert("tokenDecimals".into(), 18.into());
	properties.insert("ss58Format".into(), SS58Prefix::get().into());
	properties.insert("isEthereum".into(), true.into());
	properties
}
