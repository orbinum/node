//! The pallets `frame-benchmarking` measures. Defines `list_benchmarks!` and
//! `add_benchmarks!`, which the `Benchmark` runtime API runs.

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
	[pallet_validator_set, ValidatorSet]
	[pallet_staking_async, Staking]
	[pallet_paged_election, PagedElection]
	[pallet_nomination_pools, NominationPoolsBench::<Runtime>]
	[pallet_auto_payout, AutoPayout]
	[pallet_bags_list, VoterList]
	[ismp_grandpa, IsmpGrandpa]
	[pallet_ismp_messaging, IsmpMessaging]
);
