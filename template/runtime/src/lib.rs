//! The Orbinum runtime. Compiles with `#[no_std]` for Wasm.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]
#![allow(clippy::new_without_default, clippy::or_fun_call)]
#![cfg_attr(feature = "runtime-benchmarks", warn(unused_crate_dependencies))]

extern crate alloc;

// Required for WASM side effects; suppress unused_crate_dependencies warning.
use sp_io as _;

mod configs;
mod evm_account;
mod genesis_config_preset;
mod orbinum_signature;
mod precompiles;
mod weights;

#[cfg(test)]
mod runtime_tests;

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

use alloc::{borrow::Cow, vec, vec::Vec};
use core::marker::PhantomData;
use ethereum::AuthorizationList;
use scale_codec::{Decode, Encode};
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::{AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList};
use sp_core::{
	crypto::{ByteArray, KeyTypeId},
	ConstU128, OpaqueMetadata, H160, H256, U256,
};
use sp_runtime::{
	generic, impl_opaque_keys,
	traits::{
		BlakeTwo256, Block as BlockT, Convert, DispatchInfoOf, Dispatchable, Get, IdentityLookup,
		NumberFor, OpaqueKeys, PostDispatchInfoOf, UniqueSaturatedInto,
	},
	transaction_validity::{TransactionSource, TransactionValidity, TransactionValidityError},
	ApplyExtrinsicResult, ConsensusEngineId, ExtrinsicInclusionMode, Perbill, Permill,
};
use sp_version::RuntimeVersion;
#[cfg(feature = "with-paritydb-weights")]
use frame_support::weights::constants::ParityDbWeight as RuntimeDbWeight;
#[cfg(feature = "with-rocksdb-weights")]
use frame_support::weights::constants::RocksDbWeight as RuntimeDbWeight;
use frame_support::{
	genesis_builder_helper::build_state,
	parameter_types,
	traits::{ConstBool, ConstU32, ConstU64, ConstU8, FindAuthor, OnFinalize, OnTimestampSet},
	weights::{constants::WEIGHT_REF_TIME_PER_MILLIS, IdentityFee, Weight},
	PalletId,
};
use pallet_transaction_payment::FungibleAdapter;
use polkadot_runtime_common::SlowAdjustingFeeUpdate;
use sp_genesis_builder::PresetId;
use fp_evm::weight_per_gas;
use fp_rpc::TransactionStatus;
use pallet_ethereum::{Call::transact, PostLogContent, Transaction as EthereumTransaction};
use pallet_evm::{Account as EVMAccount, FeeCalculator, Runner};

pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;

pub use evm_account::{
	evm_bytes_to_account_id_bytes, evm_h160_to_account_id, evm_h160_to_account_id_bytes,
};
use evm_account::{EeSuffixAddressMapping, EnsureAddressMatches};
use precompiles::FrontierPrecompiles;

pub type BlockNumber = u32;

/// ECDSA keys derive their `AccountId` as `[eth_addr | 0x00×12]` — the same layout
/// `EeSuffixAddressMapping` uses, so an EVM address and its Substrate account agree.
pub use orbinum_signature::OrbinumSignature;
pub type Signature = OrbinumSignature;

pub type AccountId = sp_runtime::AccountId32;
pub type AccountIndex = u32;
pub type Balance = u128;
pub type Nonce = u32;
pub type Hash = H256;
pub type Hashing = BlakeTwo256;
pub type DigestItem = generic::DigestItem;
pub type Address = AccountId;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type SignedBlock = generic::SignedBlock<Block>;
pub type BlockId = generic::BlockId<Block>;

/// Order is wire format, not style: Tesseract builds signed payloads against this exact
/// tuple, so it must end in `ChargeTransactionPayment` → `CheckMetadataHash`. Reordering
/// or inserting an extension invalidates every signature the relayer produces.
pub type SignedExtra = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
	frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
	fp_self_contained::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic =
	fp_self_contained::CheckedExtrinsic<AccountId, RuntimeCall, SignedExtra, H160>;

/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;

/// Storage migrations run on runtime upgrade, oldest first.
///
/// Drop an entry once every live chain has passed its version — a migration
/// that can no longer run is dead weight that could be re-armed by mistake.
/// Empty: every live chain is past v3.
///
/// Deliberately does NOT include `pallet_ismp::migrations::SeedCommitmentCaps`, which
/// 2606 ships: it seeds retention caps for `Evm(56)` and `Evm(137)` (BSC, Polygon),
/// state machines we have no consensus client for — our `ConsensusClients` is GRANDPA
/// alone. Hyperbridge itself wires it only on its mainnet runtime and deliberately not
/// on its testnet one. The default cap applies instead, which is the right value for
/// us; see the note on `MAX_STATE_MACHINE_COMMITMENTS` in `configs::ismp`.
pub type Migrations = ();

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
	Migrations,
>;

pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

/// Extrinsic-agnostic types for the CLI, so a node keeps syncing across upgrades that
/// change the core data structures.
pub mod opaque {
	use super::*;

	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	pub type BlockId = generic::BlockId<Block>;

	impl_opaque_keys! {
		pub struct SessionKeys {
			pub aura: Aura,
			pub grandpa: Grandpa,
		}
	}
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: Cow::Borrowed("orbinum"),
	impl_name: Cow::Borrowed("orbinum"),
	authoring_version: 1,
	spec_version: 10,
	impl_version: 1,
	apis: RUNTIME_API_VERSIONS,
	transaction_version: 3,
	system_version: 1,
};

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> sp_version::NativeVersion {
	sp_version::NativeVersion {
		runtime_version: VERSION,
		can_author_with: Default::default(),
	}
}

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
/// We allow for 2000ms of compute with a 6 second average block time.
pub const WEIGHT_MILLISECS_PER_BLOCK: u64 = 2000;
pub const MAXIMUM_BLOCK_WEIGHT: Weight = Weight::from_parts(
	WEIGHT_MILLISECS_PER_BLOCK * WEIGHT_REF_TIME_PER_MILLIS,
	u64::MAX,
);
/// 8 MiB: GRANDPA consensus proofs do not fit the 5 MiB this was before ISMP.
///
/// Bigger blocks widen the DoS surface — re-run benchmarks and confirm validators keep
/// up under load before mainnet.
pub const MAXIMUM_BLOCK_LENGTH: u32 = 8 * 1024 * 1024;

/// Applies to block LENGTH only; weights stay at `NORMAL_DISPATCH_RATIO`.
pub const BLOCK_LENGTH_NORMAL_RATIO: Perbill = Perbill::from_percent(85);

// Pallet `Config` impls live in `configs/`, grouped by domain. They are plain
// `impl` items, so moving them out changes nothing about assembly — unlike the
// macro blocks below, which must stay whole.
pub use configs::{consensus::*, evm::*, privacy::*, system::*};

// Imported rather than fully qualified: the qualified paths bury the runtime-API
// signatures. `IsmpEvent`/`IsmpRequest` are aliased because bare `Event`/`Request`
// collide with runtime types of the same name.
use ismp::{
	consensus::{ConsensusClientId, StateMachineHeight, StateMachineId},
	events::Event as IsmpEvent,
	host::StateMachine,
	router::{GetResponse, Request as IsmpRequest},
};
// `configs::ismp` is deliberately not glob-imported: it would shadow the `ismp` crate.
// Its `Config` impls apply regardless of imports.

parameter_types! {
	pub storage EnableManualSeal: bool = false;
}

// Dev-only manual seal, defined inline because `#[frame_support::runtime]` below
// must see the pallet in this crate root. Its `Config` impl lives in `configs/evm`
// with the rest of the EVM stack.
#[frame_support::pallet]
pub mod pallet_manual_seal {
	use super::*;
	use frame_support::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T> {
		pub enable: bool,
		#[serde(skip)]
		pub _config: PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			EnableManualSeal::set(&self.enable);
		}
	}
}

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
	pub type ManualSeal = pallet_manual_seal;

	#[runtime::pallet_index(12)]
	pub type ZkVerifier = pallet_zk_verifier;

	#[runtime::pallet_index(13)]
	pub type ShieldedPool = pallet_shielded_pool;

	// Index 14 is retired. Do not reassign: a new pallet here would make
	// previously encoded calls decode as a different extrinsic.

	#[runtime::pallet_index(15)]
	pub type Authorship = pallet_authorship;

	#[runtime::pallet_index(16)]
	pub type Relayer = pallet_relayer;

	#[runtime::pallet_index(17)]
	pub type ValidatorSet = pallet_validator_set;

	#[runtime::pallet_index(18)]
	pub type Session = pallet_session;

	// ISMP / Hyperbridge. `IsmpGrandpa` is the consensus client that lets Hyperbridge
	// verify this chain's own finality — what keeps Orbinum sovereign, not a parachain.
	#[runtime::pallet_index(19)]
	pub type Ismp = pallet_ismp;

	#[runtime::pallet_index(20)]
	pub type IsmpGrandpa = ismp_grandpa;

	#[runtime::pallet_index(21)]
	pub type IsmpMessaging = pallet_ismp_messaging;
}

#[derive(Clone)]
pub struct TransactionConverter<B>(PhantomData<B>);

impl<B> Default for TransactionConverter<B> {
	fn default() -> Self {
		Self(PhantomData)
	}
}

impl<B: BlockT> fp_rpc::ConvertTransaction<<B as BlockT>::Extrinsic> for TransactionConverter<B> {
	fn convert_transaction(
		&self,
		transaction: pallet_ethereum::Transaction,
	) -> <B as BlockT>::Extrinsic {
		let extrinsic = UncheckedExtrinsic::new_bare(
			pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
		);
		let encoded = extrinsic.encode();
		<B as BlockT>::Extrinsic::decode(&mut &encoded[..])
			.expect("Encoded extrinsic is always valid")
	}
}

impl fp_self_contained::SelfContainedCall for RuntimeCall {
	type SignedInfo = H160;

	fn is_self_contained(&self) -> bool {
		match self {
			RuntimeCall::Ethereum(call) => call.is_self_contained(),
			_ => false,
		}
	}

	fn check_self_contained(&self) -> Option<Result<Self::SignedInfo, TransactionValidityError>> {
		match self {
			RuntimeCall::Ethereum(call) => call.check_self_contained(),
			_ => None,
		}
	}

	fn validate_self_contained(
		&self,
		info: &Self::SignedInfo,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		len: usize,
	) -> Option<TransactionValidity> {
		match self {
			RuntimeCall::Ethereum(call) => call.validate_self_contained(info, dispatch_info, len),
			_ => None,
		}
	}

	fn pre_dispatch_self_contained(
		&self,
		info: &Self::SignedInfo,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		len: usize,
	) -> Option<Result<(), TransactionValidityError>> {
		match self {
			RuntimeCall::Ethereum(call) => {
				call.pre_dispatch_self_contained(info, dispatch_info, len)
			}
			_ => None,
		}
	}

	fn apply_self_contained(
		self,
		info: Self::SignedInfo,
	) -> Option<sp_runtime::DispatchResultWithInfo<PostDispatchInfoOf<Self>>> {
		match self {
			call @ RuntimeCall::Ethereum(pallet_ethereum::Call::transact { .. }) => {
				Some(call.dispatch(RuntimeOrigin::from(
					pallet_ethereum::RawOrigin::EthereumTransaction(info),
				)))
			}
			_ => None,
		}
	}
}

#[cfg(feature = "runtime-benchmarks")]
mod benches {
	frame_benchmarking::define_benchmarks!(
		[frame_benchmarking, BaselineBench::<Runtime>]
		[frame_system, SystemBench::<Runtime>]
		[pallet_balances, Balances]
		[pallet_timestamp, Timestamp]
		[pallet_sudo, Sudo]
		[pallet_evm, EVM]
		[pallet_evm_precompile_curve25519, EVMPrecompileCurve25519Bench::<Runtime>]
		[pallet_evm_precompile_sha3fips, EVMPrecompileSha3FIPSBench::<Runtime>]
		[pallet_zk_verifier, ZkVerifier]
		[pallet_shielded_pool, ShieldedPool]
		[pallet_relayer, Relayer]
		[pallet_validator_set, ValidatorSet]
		[ismp_grandpa, IsmpGrandpa]
		[pallet_ismp_messaging, IsmpMessaging]
	);
}

/// Orbinum-local ISMP runtime API.
///
/// Upstream has no coprocessor accessor, and neither `Coprocessor` nor
/// `HostStateMachine` is a `#[pallet::constant]`, so neither reaches metadata. Without
/// this, the value is undiscoverable from a running node and callers must restate it.
pub mod runtime_api {
	use ismp::host::StateMachine;

	sp_api::decl_runtime_apis! {
		/// Build-dependent ISMP identities that are otherwise compile-time only.
		pub trait OrbinumIsmpApi {
			/// The configured coprocessor, i.e. which Hyperbridge deployment this
			/// build talks to. `None` would mean ISMP proxying is disabled.
			fn coprocessor() -> Option<StateMachine>;
		}
	}
}

impl_runtime_apis! {
	impl sp_api::Core<Block> for Runtime {
		fn version() -> RuntimeVersion {
			VERSION
		}

		fn execute_block(block: <Block as BlockT>::LazyBlock) {
			Executive::execute_block(block)
		}

		fn initialize_block(header: &<Block as BlockT>::Header) -> ExtrinsicInclusionMode {
			Executive::initialize_block(header)
		}
	}

	impl sp_api::Metadata<Block> for Runtime {
		fn metadata() -> OpaqueMetadata {
			OpaqueMetadata::new(Runtime::metadata().into())
		}

		fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
			Runtime::metadata_at_version(version)
		}

		fn metadata_versions() -> Vec<u32> {
			Runtime::metadata_versions()
		}
	}

	impl sp_block_builder::BlockBuilder<Block> for Runtime {
		fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
			Executive::apply_extrinsic(extrinsic)
		}

		fn finalize_block() -> <Block as BlockT>::Header {
			Executive::finalize_block()
		}

		fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
			data.create_extrinsics()
		}

		fn check_inherents(
			block: <Block as BlockT>::LazyBlock,
			data: sp_inherents::InherentData,
		) -> sp_inherents::CheckInherentsResult {
			data.check_extrinsics(&block)
		}
	}

	impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
		fn validate_transaction(
			source: TransactionSource,
			tx: <Block as BlockT>::Extrinsic,
			block_hash: <Block as BlockT>::Hash,
		) -> TransactionValidity {
			Executive::validate_transaction(source, tx, block_hash)
		}
	}

	impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
		fn offchain_worker(header: &<Block as BlockT>::Header) {
			Executive::offchain_worker(header)
		}
	}

	#[cfg(feature = "try-runtime")]
	impl frame_try_runtime::TryRuntime<Block> for Runtime {
		fn on_runtime_upgrade(checks: frame_try_runtime::UpgradeCheckSelect) -> (Weight, Weight) {
			let weight = Executive::try_runtime_upgrade(checks)
				.expect("try_runtime_upgrade must not fail");
			(weight, BlockWeights::get().max_block)
		}

		fn execute_block(
			block: <Block as BlockT>::LazyBlock,
			state_root_check: bool,
			signature_check: bool,
			select: frame_try_runtime::TryStateSelect,
		) -> Weight {
			Executive::try_execute_block(block, state_root_check, signature_check, select)
				.expect("try_execute_block must not fail")
		}
	}

	impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
		fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
			build_state::<RuntimeGenesisConfig>(config)
		}

		fn get_preset(id: &Option<PresetId>) -> Option<Vec<u8>> {
			frame_support::genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(id, genesis_config_preset::get_preset)
		}

		fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
			vec![
				PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
				PresetId::from("orbinum_local_testnet_runtime_preset"),
				PresetId::from("orbinum_testnet_runtime_preset"),
				PresetId::from("orbinum_mainnet_runtime_preset"),
			]
		}
	}

	impl sp_session::SessionKeys<Block> for Runtime {
		fn generate_session_keys(
			owner: Vec<u8>,
			seed: Option<Vec<u8>>,
		) -> sp_session::OpaqueGeneratedSessionKeys {
			opaque::SessionKeys::generate(&owner, seed).into()
		}

		fn decode_session_keys(
			encoded: Vec<u8>,
		) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
			opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
		}
	}

	impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
		fn slot_duration() -> sp_consensus_aura::SlotDuration {
			sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
		}

		fn authorities() -> Vec<AuraId> {
			pallet_aura::Authorities::<Runtime>::get().into_inner()
		}
	}

	impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
		fn grandpa_authorities() -> GrandpaAuthorityList {
			Grandpa::grandpa_authorities()
		}

		fn current_set_id() -> sp_consensus_grandpa::SetId {
			Grandpa::current_set_id()
		}

		fn submit_report_equivocation_unsigned_extrinsic(
			_equivocation_proof: sp_consensus_grandpa::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			_key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			None
		}

		fn generate_key_ownership_proof(
			_set_id: sp_consensus_grandpa::SetId,
			_authority_id: GrandpaId,
		) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
			// NOTE: this is the only implementation possible since we've
			// defined our key owner proof type as a bottom type (i.e. a type
			// with no values).
			None
		}
	}

	impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
		fn account_nonce(account: AccountId) -> Nonce {
			System::account_nonce(account)
		}
	}

	impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<
		Block,
		Balance,
	> for Runtime {
		fn query_info(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32
		) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
			TransactionPayment::query_info(uxt, len)
		}

		fn query_fee_details(
			uxt: <Block as BlockT>::Extrinsic,
			len: u32,
		) -> pallet_transaction_payment::FeeDetails<Balance> {
			TransactionPayment::query_fee_details(uxt, len)
		}

		fn query_weight_to_fee(weight: Weight) -> Balance {
			TransactionPayment::weight_to_fee(weight)
		}

		fn query_length_to_fee(length: u32) -> Balance {
			TransactionPayment::length_to_fee(length)
		}
	}

	impl fp_rpc::EthereumRuntimeRPCApi<Block> for Runtime {
		fn chain_id() -> u64 {
			<Runtime as pallet_evm::Config>::ChainId::get()
		}

		fn account_basic(address: H160) -> EVMAccount {
			let (account, _) = pallet_evm::Pallet::<Runtime>::account_basic(&address);
			account
		}

		fn gas_price() -> U256 {
			let (gas_price, _) = <Runtime as pallet_evm::Config>::FeeCalculator::min_gas_price();
			gas_price
		}

		fn account_code_at(address: H160) -> Vec<u8> {
			pallet_evm::AccountCodes::<Runtime>::get(address)
		}

		fn author() -> H160 {
			<pallet_evm::Pallet<Runtime>>::find_author()
		}

		fn storage_at(address: H160, index: U256) -> H256 {
			pallet_evm::AccountStorages::<Runtime>::get(address, H256::from(index.to_big_endian()))
		}

		fn call(
			from: H160,
			to: H160,
			data: Vec<u8>,
			value: U256,
			gas_limit: U256,
			max_fee_per_gas: Option<U256>,
			max_priority_fee_per_gas: Option<U256>,
			nonce: Option<U256>,
			estimate: bool,
			access_list: Option<Vec<(H160, Vec<H256>)>>,
			authorization_list: Option<AuthorizationList>,
		) -> Result<pallet_evm::CallInfo, sp_runtime::DispatchError> {
			use pallet_evm::GasWeightMapping as _;

			let config = if estimate {
				let mut config = <Runtime as pallet_evm::Config>::config().clone();
				config.estimate = true;
				Some(config)
			} else {
				None
			};

			// Estimated encoded transaction size must be based on the heaviest transaction
			// type (EIP7702Transaction) to be compatible with all transaction types.
			let mut estimated_transaction_len = data.len() +
				// pallet ethereum index: 1
				// transact call index: 1
				// Transaction enum variant: 1
				// chain_id 8 bytes
				// nonce: 32
				// max_priority_fee_per_gas: 32
				// max_fee_per_gas: 32
				// gas_limit: 32
				// action: 21 (enum varianrt + call address)
				// value: 32
				// access_list: 1 (empty vec size)
				// authorization_list: 1 (empty vec size)
				// 65 bytes signature
				259;

			if access_list.is_some() {
				estimated_transaction_len += access_list.encoded_size();
			}

			if authorization_list.is_some() {
				estimated_transaction_len += authorization_list.encoded_size();
			}

			let gas_limit = if gas_limit > U256::from(u64::MAX) {
				u64::MAX
			} else {
				gas_limit.low_u64()
			};
			let without_base_extrinsic_weight = true;

			let (weight_limit, proof_size_base_cost) =
				match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
					gas_limit,
					without_base_extrinsic_weight
				) {
					weight_limit if weight_limit.proof_size() > 0 => {
						(Some(weight_limit), Some(estimated_transaction_len as u64))
					}
					_ => (None, None),
				};

			<Runtime as pallet_evm::Config>::Runner::call(
				from,
				to,
				data,
				value,
				gas_limit.unique_saturated_into(),
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.unwrap_or_default(),
				authorization_list.unwrap_or_default(),
				false,
				true,
				weight_limit,
				proof_size_base_cost,
				config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config()),
			).map_err(|err| err.error.into())
		}

		fn create(
			from: H160,
			data: Vec<u8>,
			value: U256,
			gas_limit: U256,
			max_fee_per_gas: Option<U256>,
			max_priority_fee_per_gas: Option<U256>,
			nonce: Option<U256>,
			estimate: bool,
			access_list: Option<Vec<(H160, Vec<H256>)>>,
			authorization_list: Option<AuthorizationList>,
		) -> Result<pallet_evm::CreateInfo, sp_runtime::DispatchError> {
			use pallet_evm::GasWeightMapping as _;

			let config = if estimate {
				let mut config = <Runtime as pallet_evm::Config>::config().clone();
				config.estimate = true;
				Some(config)
			} else {
				None
			};


			let mut estimated_transaction_len = data.len() +
				// from: 20
				// value: 32
				// gas_limit: 32
				// nonce: 32
				// 1 byte transaction action variant
				// chain id 8 bytes
				// 65 bytes signature
				190;

			if max_fee_per_gas.is_some() {
				estimated_transaction_len += 32;
			}
			if max_priority_fee_per_gas.is_some() {
				estimated_transaction_len += 32;
			}
			if access_list.is_some() {
				estimated_transaction_len += access_list.encoded_size();
			}
			if authorization_list.is_some() {
				estimated_transaction_len += authorization_list.encoded_size();
			}

			let gas_limit = if gas_limit > U256::from(u64::MAX) {
				u64::MAX
			} else {
				gas_limit.low_u64()
			};
			let without_base_extrinsic_weight = true;

			let (weight_limit, proof_size_base_cost) =
				match <Runtime as pallet_evm::Config>::GasWeightMapping::gas_to_weight(
					gas_limit,
					without_base_extrinsic_weight
				) {
					weight_limit if weight_limit.proof_size() > 0 => {
						(Some(weight_limit), Some(estimated_transaction_len as u64))
					}
					_ => (None, None),
				};

			<Runtime as pallet_evm::Config>::Runner::create(
				from,
				data,
				value,
				gas_limit.unique_saturated_into(),
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.unwrap_or_default(),
				authorization_list.unwrap_or_default(),
				false,
				true,
				weight_limit,
				proof_size_base_cost,
				config.as_ref().unwrap_or(<Runtime as pallet_evm::Config>::config()),
			).map_err(|err| err.error.into())
		}

		fn current_transaction_statuses() -> Option<Vec<TransactionStatus>> {
			pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
		}

		fn current_block() -> Option<pallet_ethereum::Block> {
			pallet_ethereum::CurrentBlock::<Runtime>::get()
		}

		fn current_receipts() -> Option<Vec<pallet_ethereum::Receipt>> {
			pallet_ethereum::CurrentReceipts::<Runtime>::get()
		}

		fn current_all() -> (
			Option<pallet_ethereum::Block>,
			Option<Vec<pallet_ethereum::Receipt>>,
			Option<Vec<TransactionStatus>>
		) {
			(
				pallet_ethereum::CurrentBlock::<Runtime>::get(),
				pallet_ethereum::CurrentReceipts::<Runtime>::get(),
				pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
			)
		}

		fn extrinsic_filter(
			xts: Vec<<Block as BlockT>::Extrinsic>,
		) -> Vec<EthereumTransaction> {
			xts.into_iter().filter_map(|xt| match xt.0.function {
				RuntimeCall::Ethereum(transact { transaction }) => Some(transaction),
				_ => None
			}).collect::<Vec<EthereumTransaction>>()
		}

		fn elasticity() -> Option<Permill> {
			Some(pallet_base_fee::Elasticity::<Runtime>::get())
		}

		fn gas_limit_multiplier_support() {}

		fn pending_block(
			xts: Vec<<Block as BlockT>::Extrinsic>,
		) -> (Option<pallet_ethereum::Block>, Option<Vec<TransactionStatus>>) {
			for ext in xts.into_iter() {
				let _ = Executive::apply_extrinsic(ext);
			}

			Ethereum::on_finalize(System::block_number() + 1);

			(
				pallet_ethereum::CurrentBlock::<Runtime>::get(),
				pallet_ethereum::CurrentTransactionStatuses::<Runtime>::get()
			)
		}

		fn initialize_pending_block(header: &<Block as BlockT>::Header) {
			Executive::initialize_block(header);
		}
	}

	impl fp_rpc::ConvertTransactionRuntimeApi<Block> for Runtime {
		fn convert_transaction(transaction: EthereumTransaction) -> <Block as BlockT>::Extrinsic {
			UncheckedExtrinsic::new_bare(
				pallet_ethereum::Call::<Runtime>::transact { transaction }.into(),
			)
		}
	}

	// ShieldedPool Runtime API implementation
	impl pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi<Block> for Runtime {
		fn get_merkle_tree_info() -> (pallet_shielded_pool::Hash, u32, u32) {
			ShieldedPool::get_merkle_tree_info()
		}

		fn get_merkle_proof(leaf_index: u32) -> Option<pallet_shielded_pool::DefaultMerklePath> {
			ShieldedPool::get_merkle_proof(leaf_index)
		}

		fn get_forest_info() -> ([u8; 32], u32, u32, u32, u32) {
			ShieldedPool::get_forest_info()
		}

		fn get_root_for_leaf(leaf_index: u32) -> Option<([u8; 32], u32)> {
			ShieldedPool::get_root_for_leaf(leaf_index)
		}

		fn get_merkle_proof_for_commitment(
			commitment: pallet_shielded_pool::Hash,
		) -> Option<(u32, pallet_shielded_pool::DefaultMerklePath)> {
			ShieldedPool::get_merkle_proof_for_commitment(commitment)
		}

		fn relay_config() -> pallet_shielded_pool_runtime_api::RelayConfig {
			use pallet_relayer::RelayerInterface;
			let min_fee_planck = pallet_relayer::Pallet::<Runtime>::min_relay_fee();
			// Fallback selectors for day-0 operation: when the chain launches the
			// AllowedSelectors storage is empty, so we return the canonical defaults
			// (unshield + privateTransfer) derived from keccak256(sig)[0..4].
			// Once governance calls `set_allowed_selectors`, the stored list takes
			// precedence and these hardcoded values are never reached again.
			let allowed_selectors = {
				let stored = pallet_relayer::Pallet::<Runtime>::allowed_selectors();
				if stored.is_empty() {
					// Taken from the precompile itself rather than copied: a
					// literal here that drifts from the decoder fails silently,
					// since a wrong selector is simply "unsupported".
					sp_std::vec![
						pallet_evm_precompile_shielded_pool::selectors::UNSHIELD,
						pallet_evm_precompile_shielded_pool::selectors::PRIVATE_TRANSFER,
					]
				} else {
					stored
				}
			};
			pallet_shielded_pool_runtime_api::RelayConfig { min_fee_planck, allowed_selectors }
		}
	}

	impl pallet_zk_verifier_runtime_api::ZkVerifierRuntimeApi<Block> for Runtime {
		fn get_circuit_version_info(
			circuit_id: u32,
		) -> Option<pallet_zk_verifier_runtime_api::CircuitVersionInfo> {
			pallet_zk_verifier::Pallet::<Runtime>::runtime_api_get_circuit_version_info(circuit_id)
				.map(|info| pallet_zk_verifier_runtime_api::CircuitVersionInfo {
					circuit_id: info.circuit_id,
					active_version: info.active_version,
					supported_versions: info.supported_versions,
					vk_hashes: info
						.vk_hashes
						.into_iter()
						.map(|item| pallet_zk_verifier_runtime_api::VkVersionHash {
							version: item.version,
							vk_hash: item.vk_hash,
						})
						.collect(),
				})
		}

		fn get_all_circuit_versions() -> alloc::vec::Vec<pallet_zk_verifier_runtime_api::CircuitVersionInfo> {
			pallet_zk_verifier::Pallet::<Runtime>::runtime_api_get_all_circuit_versions()
				.into_iter()
				.map(|info| pallet_zk_verifier_runtime_api::CircuitVersionInfo {
					circuit_id: info.circuit_id,
					active_version: info.active_version,
					supported_versions: info.supported_versions,
					vk_hashes: info
						.vk_hashes
						.into_iter()
						.map(|item| pallet_zk_verifier_runtime_api::VkVersionHash {
							version: item.version,
							vk_hash: item.vk_hash,
						})
						.collect(),
				})
				.collect()
		}
	}

	// ISMP Runtime API — the read path relayers depend on:
	//   relayer -> RPC (ismp_query*) -> this runtime API -> offchain DB
	//
	// Thin delegations; the pallet owns the logic. `requests`/`responses` read the
	// offchain DB, populated only when offchain indexing is on — `command.rs` forces
	// it, because a node without it answers every query with an empty list and no error.
	impl pallet_ismp_runtime_api::IsmpRuntimeApi<Block, <Block as BlockT>::Hash> for Runtime {
		fn host_state_machine() -> StateMachine {
			configs::ismp::network::host_state_machine()
		}

		fn block_events() -> Vec<IsmpEvent> {
			Ismp::block_events()
		}

		fn block_events_with_metadata() -> Vec<(IsmpEvent, Option<u32>)> {
			Ismp::block_events_with_metadata()
		}

		fn consensus_state(id: ConsensusClientId) -> Option<Vec<u8>> {
			pallet_ismp::ConsensusStates::<Runtime>::get(id)
		}

		/// The host's *local* timestamp when this height was committed. This is the
		/// clock the challenge period is measured against — not the counterparty's
		/// own block timestamp, which lives in `StateCommitment.timestamp`.
		///
		/// Reads `BoundedStateMachineUpdateTime`, **not** the similarly named
		/// `StateMachineUpdateTime`. On 2512 the latter is a legacy map that nothing
		/// writes any more (outside benchmarks) and that `on_idle` drains to empty,
		/// yet it still carries the `#[pallet::getter(fn state_machine_update_time)]`
		/// attribute — so the obvious-looking read returns `None` forever, leaving
		/// relayers unable to tell when a challenge period has elapsed and no error
		/// to point at.
		///
		/// On 2606 the trap is gone: upstream deleted the legacy map and moved the
		/// getter onto the bounded one, so the explicit read below is now simply
		/// naming the only map there is. `pallet_ismp`'s own
		/// `IsmpHost::state_machine_update_time` reads the same bounded map. Kept
		/// explicit so a future rename cannot silently redirect it.
		fn state_machine_update_time(id: StateMachineHeight) -> Option<u64> {
			pallet_ismp::BoundedStateMachineUpdateTime::<Runtime>::get(id.id, id.height)
		}

		fn challenge_period(id: StateMachineId) -> Option<u64> {
			pallet_ismp::ChallengePeriod::<Runtime>::get(id)
		}

		fn latest_state_machine_height(id: StateMachineId) -> Option<u64> {
			pallet_ismp::LatestStateMachineHeight::<Runtime>::get(id)
		}

		fn requests(request_commitments: Vec<H256>) -> Vec<IsmpRequest> {
			Ismp::requests(request_commitments)
		}

		/// Returns `GetResponse`, not `Response`: ISMP has no first-class POST
		/// response — an application replies with a POST in the opposite direction.
		/// The published docs show `Vec<Response>` here, which does not compile
		/// against this version.
		///
		/// That asymmetry is the design, not a gap waiting on an API: `IsmpDispatcher`
		/// declares `dispatch_request` and nothing else, on 2512, on 2606, and on
		/// Hyperbridge's unpublished `main` alike. Request/reply is built by dispatching
		/// a POST back from state recorded in `on_accept`, a block later.
		fn responses(response_commitments: Vec<H256>) -> Vec<GetResponse> {
			Ismp::responses(response_commitments)
		}
	}

	impl crate::runtime_api::OrbinumIsmpApi<Block> for Runtime {
		fn coprocessor() -> Option<StateMachine> {
			configs::ismp::network::coprocessor()
		}
	}

	// Relayer Runtime API implementation
	impl pallet_relayer_runtime_api::RelayerRuntimeApi<Block> for Runtime {
		fn is_relayer(account: sp_runtime::AccountId32) -> bool {
			pallet_relayer::RelayerByAccount::<Runtime>::contains_key(&account)
		}

		fn pending_fees(account: sp_runtime::AccountId32, asset_id: u32) -> u128 {
			pallet_relayer::PendingRelayerFees::<Runtime>::get(&account, asset_id)
		}

		fn registered_evm_address(account: sp_runtime::AccountId32) -> Option<[u8; 20]> {
			pallet_relayer::RelayerByAccount::<Runtime>::get(&account).map(|h| h.0)
		}

		fn get_active_relayers() -> sp_std::vec::Vec<([u8; 20], sp_runtime::AccountId32)> {
			// Capped: this iterates a map with no inherent bound, and a runtime
			// API runs inside the caller's block/RPC budget. Registration is
			// gated on the validator set, so the live count cannot exceed
			// `MaxValidators` — the cap is headroom against a future path that
			// registers without that gate, not against today's storage.
			const MAX_RELAYERS_RETURNED: usize = 256;
			pallet_relayer::RelayerRegistry::<Runtime>::iter()
				.take(MAX_RELAYERS_RETURNED)
				.map(|(h160, account)| (h160.0, account))
				.collect()
		}

		fn is_relayer_evm(evm_address: [u8; 20]) -> bool {
			pallet_relayer::RelayerRegistry::<Runtime>::contains_key(
				sp_core::H160::from(evm_address),
			)
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	impl frame_benchmarking::Benchmark<Block> for Runtime {
		fn benchmark_metadata(extra: bool) -> (
			Vec<frame_benchmarking::BenchmarkList>,
			Vec<frame_support::traits::StorageInfo>,
		) {
			use frame_benchmarking::{baseline, BenchmarkList};
			use frame_support::traits::StorageInfoTrait;

			use baseline::Pallet as BaselineBench;
			use frame_system_benchmarking::Pallet as SystemBench;

			use pallet_evm_precompile_curve25519_benchmarking::Pallet as EVMPrecompileCurve25519Bench;
			use pallet_evm_precompile_sha3fips_benchmarking::Pallet as EVMPrecompileSha3FIPSBench;

			let mut list = Vec::<BenchmarkList>::new();
			list_benchmarks!(list, extra);

			let storage_info = AllPalletsWithSystem::storage_info();
			(list, storage_info)
		}

		#[allow(non_local_definitions)]
		fn dispatch_benchmark(
			config: frame_benchmarking::BenchmarkConfig
		) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, alloc::string::String> {
			use frame_benchmarking::{baseline, BenchmarkBatch};
			use frame_support::traits::TrackedStorageKey;

			use baseline::Pallet as BaselineBench;
			use frame_system_benchmarking::Pallet as SystemBench;
			use pallet_evm_precompile_curve25519_benchmarking::Pallet as EVMPrecompileCurve25519Bench;
			use pallet_evm_precompile_sha3fips_benchmarking::Pallet as EVMPrecompileSha3FIPSBench;

			impl baseline::Config for Runtime {}
			impl frame_system_benchmarking::Config for Runtime {}
			impl pallet_evm_precompile_curve25519_benchmarking::Config for Runtime {}
			impl pallet_evm_precompile_sha3fips_benchmarking::Config for Runtime {}

			let whitelist: Vec<TrackedStorageKey> = Vec::new();

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);
			add_benchmarks!(params, batches);
			Ok(batches)
		}
	}
}
