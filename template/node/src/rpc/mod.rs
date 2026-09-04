//! A collection of node-specific RPC methods.

use std::sync::Arc;

use futures::channel::mpsc;
use jsonrpsee::RpcModule;
// Substrate
use sc_client_api::{
	backend::{Backend, StorageProvider},
	client::BlockchainEvents,
	AuxStore, UsageProvider,
};
use sc_consensus_manual_seal::rpc::EngineCommand;
use sc_rpc::SubscriptionTaskExecutor;
use sc_service::TransactionPool;
use sp_api::{CallApiAt, ProvideRuntimeApi};
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::H256;
use sp_inherents::CreateInherentDataProviders;
use sp_keystore::Keystore;
use sp_runtime::traits::{Block as BlockT, NumberFor};
// Runtime
use orbinum_runtime::{AccountId, Balance, Hash, Nonce};

mod eth;
mod relayer_author;
mod storage_override;
pub use self::eth::{create_eth, EthDeps, LogsJournalConfig};
use self::relayer_author::{RelayerAuthor, RelayerAuthorApiServer};
use self::storage_override::EeSuffixStorageOverride;

/// GRANDPA-specific dependencies.
///
/// Wiring these is what lets a chain be verified from the outside: Hyperbridge's relayer
/// builds Orbinum finality proofs through `grandpa_proveFinality`, and without the RPC it
/// reports the method as missing rather than as unauthorised.
///
/// Everything here serves finality data for blocks that are already final — public by
/// definition, and independently verifiable against the authority set. No keys, no
/// private state. `sc-consensus-grandpa-rpc` marks none of the three methods `unsafe`,
/// so they are served under the `--rpc-methods Safe` the public endpoint runs with.
pub struct GrandpaDeps<B: BlockT, BE> {
	/// Shared with the voter, not a fresh empty one: a detached state makes
	/// `grandpa_roundState` answer with zeroed rounds instead of failing, which reads as
	/// "working" while telling the caller nothing.
	pub shared_voter_state: sc_consensus_grandpa::SharedVoterState,
	/// Current authority set, for `grandpa_roundState`.
	pub shared_authority_set: sc_consensus_grandpa::SharedAuthoritySet<B::Hash, NumberFor<B>>,
	/// Justification notifications, for `grandpa_subscribeJustifications`.
	pub justification_stream: sc_consensus_grandpa::GrandpaJustificationStream<B>,
	/// Serves `grandpa_proveFinality`.
	pub finality_provider: Arc<sc_consensus_grandpa::FinalityProofProvider<BE, B>>,
}

/// Full client dependencies.
pub struct FullDeps<B: BlockT, C, P, BE, CT, CIDP> {
	/// The client instance to use.
	pub client: Arc<C>,
	/// Transaction pool instance.
	pub pool: Arc<P>,
	/// Substrate backend — the ISMP RPC reads outgoing requests from its offchain
	/// storage, so it needs the backend rather than just the client.
	pub backend: Arc<BE>,
	/// Manual seal command sink
	pub command_sink: Option<mpsc::Sender<EngineCommand<Hash>>>,
	/// Keystore — holds the node's session keys and its `evmr` relay key.
	pub keystore: Arc<dyn Keystore>,
	/// Ethereum-compatibility specific dependencies.
	pub eth: EthDeps<B, C, P, CT, CIDP>,
	/// GRANDPA finality RPC dependencies.
	pub grandpa: GrandpaDeps<B, BE>,
}

pub struct DefaultEthConfig<C, BE>(std::marker::PhantomData<(C, BE)>);

impl<B, C, BE> fc_rpc::EthConfig<B, C> for DefaultEthConfig<C, BE>
where
	B: BlockT,
	C: StorageProvider<B, BE> + Sync + Send + 'static,
	BE: Backend<B> + 'static,
{
	type EstimateGasAdapter = ();
	// Frontier's stock overrides assume either AccountId20 or HashedAddressMapping;
	// this runtime is AccountId32 with EeSuffixAddressMapping.
	type RuntimeStorageOverride = EeSuffixStorageOverride<B, C, BE>;
}

/// Instantiate all Full RPC extensions.
pub fn create_full<B, C, P, BE, CT, CIDP>(
	deps: FullDeps<B, C, P, BE, CT, CIDP>,
	subscription_task_executor: SubscriptionTaskExecutor,
	pubsub_notification_sinks: Arc<
		fc_mapping_sync::EthereumBlockNotificationSinks<
			fc_mapping_sync::EthereumBlockNotification<B>,
		>,
	>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
	B: BlockT<Hash = H256>,
	C: CallApiAt<B> + ProvideRuntimeApi<B>,
	C::Api: sp_block_builder::BlockBuilder<B>,
	C::Api: sp_consensus_aura::AuraApi<B, AuraId>,
	C::Api: substrate_frame_rpc_system::AccountNonceApi<B, AccountId, Nonce>,
	C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<B, Balance>,
	C::Api: fp_rpc::ConvertTransactionRuntimeApi<B>,
	C::Api: fp_rpc::EthereumRuntimeRPCApi<B>,
	C::Api: pallet_shielded_pool_runtime_api::ShieldedPoolRuntimeApi<B>,
	C::Api: pallet_zk_verifier_runtime_api::ZkVerifierRuntimeApi<B>,
	C::Api: pallet_relayer_runtime_api::RelayerRuntimeApi<B>,
	C::Api: pallet_ismp_runtime_api::IsmpRuntimeApi<B, B::Hash>,
	C: sc_client_api::ProofProvider<B> + sc_client_api::BlockBackend<B>,
	C::Api: sp_api::Core<B>,
	C: HeaderBackend<B> + HeaderMetadata<B, Error = BlockChainError> + 'static,
	C: BlockchainEvents<B> + AuxStore + UsageProvider<B> + StorageProvider<B, BE>,
	BE: Backend<B> + Send + Sync + 'static,
	BE::OffchainStorage: Clone + Send + Sync + 'static,
	P: TransactionPool<Block = B, Hash = B::Hash> + 'static,
	u64: From<<<B as BlockT>::Header as sp_runtime::traits::Header>::Number>,
	CIDP: CreateInherentDataProviders<B, ()> + Send + 'static,
	CT: fp_rpc::ConvertTransaction<<B as BlockT>::Extrinsic> + Send + Sync + 'static,
	NumberFor<B>: sc_consensus_grandpa::BlockNumberOps,
{
	use pallet_ismp_rpc::{IsmpApiServer, IsmpRpcHandler};
	use pallet_relayer_rpc::{Relayer, RelayerApiServer};
	use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
	use pallet_zk_verifier_rpc::{ZkVerifier, ZkVerifierApiServer};
	use sc_consensus_grandpa_rpc::{Grandpa, GrandpaApiServer};
	use sc_consensus_manual_seal::rpc::{ManualSeal, ManualSealApiServer};
	use substrate_frame_rpc_system::{System, SystemApiServer};

	// Orbinum Privacy + Chain RPC
	use fc_rpc_v2::{ChainApiServer, ChainRpc, PrivacyApiServer, PrivacyRpc};

	let mut io = RpcModule::new(());
	let FullDeps {
		client,
		pool,
		backend,
		command_sink,
		keystore,
		eth,
		grandpa,
	} = deps;

	io.merge(System::new(client.clone(), pool.clone()).into_rpc())?;
	io.merge(
		Grandpa::new(
			subscription_task_executor.clone(),
			grandpa.shared_authority_set,
			grandpa.shared_voter_state,
			grandpa.justification_stream,
			grandpa.finality_provider,
		)
		.into_rpc(),
	)?;
	io.merge(TransactionPayment::new(client.clone()).into_rpc())?;
	io.merge(ZkVerifier::new(client.clone()).into_rpc())?;
	io.merge(Relayer::new(client.clone()).into_rpc())?;
	io.merge(RelayerAuthor::new(client.clone(), keystore).into_rpc())?;
	// Exposes the `ismp_query*` methods. `new` fails if the backend has no offchain
	// storage — the misconfiguration that leaves relayers unable to see our messages.
	io.merge(IsmpRpcHandler::new(client.clone(), backend.clone())?.into_rpc())?;

	io.merge(PrivacyRpc::new(client.clone()).into_rpc())?;
	io.merge(ChainRpc::new(client.clone()).into_rpc())?;

	if let Some(command_sink) = command_sink {
		io.merge(
			// We provide the rpc handler with the sending end of the channel to allow the rpc
			// send EngineCommands to the background block authorship task.
			ManualSeal::new(command_sink).into_rpc(),
		)?;
	}

	// Ethereum compatibility RPCs
	let io = create_eth::<_, _, _, _, _, _, DefaultEthConfig<C, BE>>(
		io,
		eth,
		subscription_task_executor,
		pubsub_notification_sinks,
	)?;

	Ok(io)
}
