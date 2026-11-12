// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! The runtime APIs: one `impl_runtime_apis!` (the macro must see every API at once),
//! delegating to the pallets and to the helpers beside it.
//!
//! - `evm`: what the Ethereum RPC API's `call` and `create` share.
//! - `ismp`: the Orbinum-local ISMP API.
//! - `zk`: `pallet-zk-verifier`'s types as its API returns them.

pub(crate) mod evm;
pub mod ismp;
#[cfg(test)]
mod tests;
mod zk;

#[cfg(feature = "try-runtime")]
use crate::configs::system::BlockWeights;
use crate::{
	genesis, opaque, AccountId, Aura, Balance, Block, Ethereum, Executive, Grandpa, Historical,
	InherentDataExt, Ismp, NominationPools, Nonce, Runtime, RuntimeCall, RuntimeGenesisConfig,
	ShieldedPool, Staking, System, TransactionPayment, UncheckedExtrinsic, VERSION,
};
#[cfg(feature = "runtime-benchmarks")]
use crate::{
	AllPalletsWithSystem, AutoPayout, Balances, IsmpGrandpa, IsmpMessaging, PagedElection, Sudo,
	Timestamp, ValidatorSet, VoterList, ZkVerifier, EVM,
};
use ::ismp::{
	consensus::{ConsensusClientId, StateMachineHeight, StateMachineId},
	events::Event as IsmpEvent,
	host::StateMachine,
	router::{GetResponse, Request as IsmpRequest},
};
use alloc::vec::Vec;
use ethereum::AuthorizationList;
use fp_rpc::TransactionStatus;
use frame_support::{traits::OnFinalize, weights::Weight};
use pallet_ethereum::{Call::transact, Transaction as EthereumTransaction};
use pallet_evm::{Account as EVMAccount, FeeCalculator, Runner};
use scale_codec::Encode;
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::{AuthorityId as GrandpaId, AuthorityList as GrandpaAuthorityList};
use sp_core::{crypto::KeyTypeId, OpaqueMetadata, H160, H256, U256};
use sp_genesis_builder::PresetId;
use sp_runtime::{
	traits::{Block as BlockT, Get, NumberFor},
	transaction_validity::{TransactionSource, TransactionValidity},
	ApplyExtrinsicResult, ExtrinsicInclusionMode, Permill,
};
use sp_version::RuntimeVersion;

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
			genesis::build_state(config)
		}

		fn get_preset(id: &Option<PresetId>) -> Option<Vec<u8>> {
			frame_support::genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(id, genesis::get_preset)
		}

		fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
			genesis::preset_names()
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

	impl pallet_staking_async_runtime_api::StakingApi<Block, Balance, AccountId> for Runtime {
		fn nominations_quota(balance: Balance) -> u32 {
			Staking::api_nominations_quota(balance)
		}

		fn eras_stakers_page_count(era: sp_staking::EraIndex, account: AccountId) -> sp_staking::Page {
			Staking::api_eras_stakers_page_count(era, account)
		}

		fn pending_rewards(era: sp_staking::EraIndex, account: AccountId) -> bool {
			Staking::api_pending_rewards(era, account)
		}
	}

	impl pallet_nomination_pools_runtime_api::NominationPoolsApi<Block, AccountId, Balance> for Runtime {
		fn pending_rewards(member: AccountId) -> Balance {
			NominationPools::api_pending_rewards(member).unwrap_or_default()
		}

		fn points_to_balance(pool_id: pallet_nomination_pools::PoolId, points: Balance) -> Balance {
			NominationPools::api_points_to_balance(pool_id, points)
		}

		fn balance_to_points(pool_id: pallet_nomination_pools::PoolId, new_funds: Balance) -> Balance {
			NominationPools::api_balance_to_points(pool_id, new_funds)
		}

		fn pool_pending_slash(pool_id: pallet_nomination_pools::PoolId) -> Balance {
			NominationPools::api_pool_pending_slash(pool_id)
		}

		fn member_pending_slash(member: AccountId) -> Balance {
			NominationPools::api_member_pending_slash(member)
		}

		fn pool_needs_delegate_migration(pool_id: pallet_nomination_pools::PoolId) -> bool {
			NominationPools::api_pool_needs_delegate_migration(pool_id)
		}

		fn member_needs_delegate_migration(member: AccountId) -> bool {
			NominationPools::api_member_needs_delegate_migration(member)
		}

		fn member_total_balance(member: AccountId) -> Balance {
			NominationPools::api_member_total_balance(member)
		}

		fn pool_balance(pool_id: pallet_nomination_pools::PoolId) -> Balance {
			NominationPools::api_pool_balance(pool_id)
		}

		fn pool_accounts(pool_id: pallet_nomination_pools::PoolId) -> (AccountId, AccountId) {
			NominationPools::api_pool_accounts(pool_id)
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
			equivocation_proof: sp_consensus_grandpa::EquivocationProof<
				<Block as BlockT>::Hash,
				NumberFor<Block>,
			>,
			key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
		) -> Option<()> {
			let key_owner_proof = key_owner_proof.decode()?;
			Grandpa::submit_unsigned_equivocation_report(equivocation_proof, key_owner_proof)
		}

		fn generate_key_ownership_proof(
			_set_id: sp_consensus_grandpa::SetId,
			authority_id: GrandpaId,
		) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
			use frame_support::traits::KeyOwnerProofSystem;
			Historical::prove((sp_consensus_grandpa::KEY_TYPE, authority_id))
				.map(|proof| proof.encode())
				.map(sp_consensus_grandpa::OpaqueKeyOwnershipProof::new)
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
			let len = evm::call_len(data.len(), &access_list, &authorization_list);
			let limits = evm::RunnerLimits::new(gas_limit, len, estimate);
			<Runtime as pallet_evm::Config>::Runner::call(
				from,
				to,
				data,
				value,
				limits.gas_limit,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.unwrap_or_default(),
				authorization_list.unwrap_or_default(),
				false,
				true,
				limits.weight_limit,
				limits.proof_size_base_cost,
				limits.config(),
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
			let len = evm::create_len(
				data.len(),
				max_fee_per_gas,
				max_priority_fee_per_gas,
				&access_list,
				&authorization_list,
			);
			let limits = evm::RunnerLimits::new(gas_limit, len, estimate);
			<Runtime as pallet_evm::Config>::Runner::create(
				from,
				data,
				value,
				limits.gas_limit,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list.unwrap_or_default(),
				authorization_list.unwrap_or_default(),
				false,
				true,
				limits.weight_limit,
				limits.proof_size_base_cost,
				limits.config(),
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

	#[api_version(5)]
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

		fn get_subtree_roots(
			tree_id: u32,
			start: u32,
			count: u32,
		) -> Option<pallet_shielded_pool::SubtreeRoots> {
			ShieldedPool::get_subtree_roots(tree_id, start, count)
		}
	}

	impl pallet_zk_verifier_runtime_api::ZkVerifierRuntimeApi<Block> for Runtime {
		fn get_circuit_version_info(
			circuit_id: u32,
		) -> Option<pallet_zk_verifier_runtime_api::CircuitVersionInfo> {
			pallet_zk_verifier::Pallet::<Runtime>::runtime_api_get_circuit_version_info(circuit_id)
				.map(zk::circuit_version_info)
		}

		fn get_all_circuit_versions() -> Vec<pallet_zk_verifier_runtime_api::CircuitVersionInfo> {
			pallet_zk_verifier::Pallet::<Runtime>::runtime_api_get_all_circuit_versions()
				.into_iter()
				.map(zk::circuit_version_info)
				.collect()
		}
	}

	// Relayers read ISMP through this API (`ismp_query*` RPCs). `requests` and `responses`
	// read the offchain DB, filled only with offchain indexing on: the node forces it
	// (`apply_ismp_requirements`), as without it every query answers an empty list.
	impl pallet_ismp_runtime_api::IsmpRuntimeApi<Block, <Block as BlockT>::Hash> for Runtime {
		fn host_state_machine() -> StateMachine {
			crate::configs::ismp::network::host_state_machine()
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

		/// The host's *local* timestamp when this height was committed: the clock the
		/// challenge period runs on, not the counterparty's block timestamp
		/// (`StateCommitment.timestamp`). Reads the map by name so a rename cannot
		/// silently redirect it.
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

		/// `GetResponse`, not the `Response` upstream docs show (which does not compile):
		/// ISMP has no POST response; `IsmpDispatcher` only dispatches requests, so an
		/// application answers a POST with a POST the other way.
		fn responses(response_commitments: Vec<H256>) -> Vec<GetResponse> {
			Ismp::responses(response_commitments)
		}
	}

	impl crate::runtime_api::OrbinumIsmpApi<Block> for Runtime {
		fn coprocessor() -> Option<StateMachine> {
			crate::configs::ismp::network::coprocessor()
		}

		fn hyperbridge_slot_duration() -> u64 {
			crate::configs::ismp::network::HYPERBRIDGE_SLOT_DURATION_MS
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
			use pallet_nomination_pools_benchmarking::Pallet as NominationPoolsBench;

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
			use pallet_nomination_pools_benchmarking::Pallet as NominationPoolsBench;

			impl baseline::Config for Runtime {}
			impl frame_system_benchmarking::Config for Runtime {}
			impl pallet_evm_precompile_curve25519_benchmarking::Config for Runtime {}
			impl pallet_evm_precompile_sha3fips_benchmarking::Config for Runtime {}
			impl pallet_nomination_pools_benchmarking::Config for Runtime {}

			let whitelist: Vec<TrackedStorageKey> = Vec::new();

			let mut batches = Vec::<BenchmarkBatch>::new();
			let params = (&config, &whitelist);
			add_benchmarks!(params, batches);
			Ok(batches)
		}
	}
}
