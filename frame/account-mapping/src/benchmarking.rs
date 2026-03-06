//! Benchmarks for `pallet-account-mapping`.
//!
//! Run with:
//! ```sh
//! ./scripts/benchmark.sh pallet_account_mapping
//! ```
//! or directly:
//! ```sh
//! cargo run --release --features runtime-benchmarks -- \
//!     benchmark pallet \
//!     --pallet pallet_account_mapping \
//!     --extrinsic "*" \
//!     --steps 50 --repeat 20 \
//!     --output frame/account-mapping/src/weights.rs \
//!     --template scripts/frame-weight-template.hbs
//! ```

use super::*;
use crate::pallet::{
	AccountAliases, AccountMetadatas, AliasListings, Identities, MappedAccounts, OriginalAccounts,
	SupportedChains,
};
use frame_benchmarking::v2::*;
use frame_support::traits::{Currency, Get, ReservableCurrency};
use frame_system::RawOrigin;
use scale_codec::Encode;
use sp_core::crypto::KeyTypeId;
use sp_runtime::traits::Convert;

// KeyTypeId reserved for ECDSA signatures in benchmarks.
// Does not collide with any production KeyTypeId (all use standard 4-char ASCII).
const BENCH_KEY: KeyTypeId = KeyTypeId(*b"bktp");

// Fixture: short valid alias of realistic maximum length for benchmarks.
// Uses `b"bench_alias_xx"` where xx varies to avoid collisions between benchmarks.

fn make_alias<T: Config>(seed: &[u8]) -> AliasOf<T> {
	let mut bytes: alloc::vec::Vec<u8> = seed.to_vec();
	// Pad to exactly 14 bytes — zeros are not valid [a-z0-9_],
	// so we use 'a' as padding.
	while bytes.len() < 14 {
		bytes.push(b'a');
	}
	bytes.truncate(14);
	bytes
		.try_into()
		.expect("14-byte alias always fits within MaxAliasLength ≥ 14")
}

fn fund_account<T: Config>(who: &T::AccountId) {
	let amount = T::AliasDeposit::get() * 100u32.into();
	let _ = T::Currency::make_free_balance_be(who, amount);
}

fn register_alias_for<T: Config>(who: &T::AccountId, alias: AliasOf<T>) {
	fund_account::<T>(who);
	let deposit = T::AliasDeposit::get();
	T::Currency::reserve(who, deposit).expect("sufficient balance");

	let evm_address = T::AccountIdToEvmAddress::convert(who.clone());
	let record = crate::pallet::IdentityRecord::<T> {
		owner: who.clone(),
		evm_address,
		deposit,
		chain_links: Default::default(),
	};
	Identities::<T>::insert(&alias, record);
	AccountAliases::<T>::insert(who, &alias);
}

#[benchmarks(
    where
        <T as Config>::RuntimeCall: From<frame_system::Call<T>>,
)]
mod benchmarks {
	use super::*;

	// ─── map_account ────────────────────────────────────────────────────────

	#[benchmark]
	fn map_account() {
		let caller: T::AccountId = whitelisted_caller();
		fund_account::<T>(&caller);

		#[extrinsic_call]
		map_account(RawOrigin::Signed(caller.clone()));

		assert!(OriginalAccounts::<T>::contains_key(&caller));
	}

	// ─── unmap_account ──────────────────────────────────────────────────────

	#[benchmark]
	fn unmap_account() {
		let caller: T::AccountId = whitelisted_caller();
		fund_account::<T>(&caller);

		// Pre-state: account already mapped.
		let address = T::AccountIdToEvmAddress::convert(caller.clone())
			.expect("caller must have an EVM address in benchmark");
		OriginalAccounts::<T>::insert(&caller, address);
		MappedAccounts::<T>::insert(address, &caller);

		#[extrinsic_call]
		unmap_account(RawOrigin::Signed(caller.clone()));

		assert!(!OriginalAccounts::<T>::contains_key(&caller));
	}

	// ─── register_alias ─────────────────────────────────────────────────────

	#[benchmark]
	fn register_alias() {
		let caller: T::AccountId = whitelisted_caller();
		fund_account::<T>(&caller);
		let alias = make_alias::<T>(b"reg_bench");

		#[extrinsic_call]
		register_alias(RawOrigin::Signed(caller.clone()), alias.clone());

		assert!(Identities::<T>::contains_key(&alias));
		assert!(AccountAliases::<T>::contains_key(&caller));
	}

	// ─── release_alias ──────────────────────────────────────────────────────

	#[benchmark]
	fn release_alias() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"rel_bench");
		register_alias_for::<T>(&caller, alias.clone());

		#[extrinsic_call]
		release_alias(RawOrigin::Signed(caller.clone()));

		assert!(!AccountAliases::<T>::contains_key(&caller));
		assert!(!Identities::<T>::contains_key(&alias));
	}

	// ─── transfer_alias ─────────────────────────────────────────────────────

	#[benchmark]
	fn transfer_alias() {
		let sender: T::AccountId = whitelisted_caller();
		let receiver: T::AccountId = account("receiver", 0, 0);
		fund_account::<T>(&receiver);

		let alias = make_alias::<T>(b"txfr_bench");
		register_alias_for::<T>(&sender, alias.clone());

		#[extrinsic_call]
		transfer_alias(RawOrigin::Signed(sender.clone()), receiver.clone());

		assert!(AccountAliases::<T>::contains_key(&receiver));
		assert!(!AccountAliases::<T>::contains_key(&sender));
	}

	// ─── put_alias_on_sale ──────────────────────────────────────────────────

	#[benchmark]
	fn put_alias_on_sale() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"sale_bench");
		register_alias_for::<T>(&caller, alias.clone());

		let price = T::AliasDeposit::get() * 10u32.into();

		#[extrinsic_call]
		put_alias_on_sale(RawOrigin::Signed(caller.clone()), price, None);

		assert!(AliasListings::<T>::contains_key(&alias));
	}

	// ─── cancel_sale ────────────────────────────────────────────────────────

	#[benchmark]
	fn cancel_sale() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"cncl_bench");
		register_alias_for::<T>(&caller, alias.clone());

		let price = T::AliasDeposit::get() * 10u32.into();
		let listing = crate::pallet::SaleListing::<T> {
			price,
			allowed_buyers: None,
		};
		AliasListings::<T>::insert(&alias, listing);

		#[extrinsic_call]
		cancel_sale(RawOrigin::Signed(caller.clone()));

		assert!(!AliasListings::<T>::contains_key(&alias));
	}

	// ─── buy_alias ──────────────────────────────────────────────────────────

	#[benchmark]
	fn buy_alias() {
		// Seller with listed alias.
		let seller: T::AccountId = account("seller", 0, 0);
		let alias = make_alias::<T>(b"buy_bench");
		register_alias_for::<T>(&seller, alias.clone());

		let price = T::AliasDeposit::get() * 5u32.into();
		let listing = crate::pallet::SaleListing::<T> {
			price,
			allowed_buyers: None,
		};
		AliasListings::<T>::insert(&alias, listing);

		// Buyer with enough funds (price + deposit).
		let buyer: T::AccountId = whitelisted_caller();
		let buyer_funds = T::AliasDeposit::get() * 50u32.into();
		let _ = T::Currency::make_free_balance_be(&buyer, buyer_funds);

		#[extrinsic_call]
		buy_alias(RawOrigin::Signed(buyer.clone()), alias.clone());

		assert!(AccountAliases::<T>::contains_key(&buyer));
		assert!(!AccountAliases::<T>::contains_key(&seller));
		assert!(!AliasListings::<T>::contains_key(&alias));
	}

	// ─── add_chain_link ─────────────────────────────────────────────────────
	//
	// Uses `sp_io::crypto` (host functions) to generate and sign, compatible
	// with no_std/WASM without requiring sp-core/full_crypto.

	#[benchmark]
	fn add_chain_link() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"link_bench");
		register_alias_for::<T>(&caller, alias.clone());

		SupportedChains::<T>::insert(1u32, SignatureScheme::Eip191);

		// Generate a key pair in the keystore with a deterministic seed.
		let pubkey = sp_io::crypto::ecdsa_generate(BENCH_KEY, Some(b"//bench_link_01".to_vec()));

		let account_bytes = caller.encode();
		let final_hash = crate::utils::eip191_message_hash(&account_bytes);

		// Sign using host function — compatible with WASM and no_std.
		let sig = sp_io::crypto::ecdsa_sign_prehashed(BENCH_KEY, &pubkey, &final_hash)
			.expect("signing must succeed with a freshly generated key");
		let sig_bytes: [u8; 65] = sig.0;

		// Derive the Ethereum address from the generated key pair.
		let full_pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig_bytes, &final_hash)
			.ok()
			.expect("recovery must succeed with a valid signature");
		let addr_hash = sp_io::hashing::keccak_256(&full_pubkey[..]);
		let eth_addr: crate::ExternalAddr = addr_hash[12..]
			.to_vec()
			.try_into()
			.expect("20 bytes always fit in ExternalAddr");

		#[extrinsic_call]
		add_chain_link(
			RawOrigin::Signed(caller.clone()),
			1u32,
			eth_addr.into_inner(),
			sig_bytes.to_vec(),
		);

		let record = Identities::<T>::get(&alias).expect("identity must exist");
		assert_eq!(record.chain_links.len(), 1);
	}

	// ─── remove_chain_link ──────────────────────────────────────────────────

	#[benchmark]
	fn remove_chain_link() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"rmlink_bnch");
		register_alias_for::<T>(&caller, alias.clone());

		// Insert a chain link directly into storage (bypasses verification).
		let mut record = Identities::<T>::get(&alias).expect("identity must exist");
		let link_addr: crate::ExternalAddr = b"0xbenchmarkaddr12345678"
			.to_vec()
			.try_into()
			.expect("addr fits in ExternalAddr");
		record
			.chain_links
			.try_push(crate::ChainLink {
				chain_id: 1,
				address: link_addr,
			})
			.expect("MAX_CHAIN_LINKS > 0");
		Identities::<T>::insert(&alias, record);

		#[extrinsic_call]
		remove_chain_link(RawOrigin::Signed(caller.clone()), 1u32);

		let record = Identities::<T>::get(&alias).expect("identity must exist");
		assert!(record.chain_links.is_empty());
	}

	// ─── set_account_metadata ───────────────────────────────────────────────

	#[benchmark]
	fn set_account_metadata() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"meta_bench");
		register_alias_for::<T>(&caller, alias.clone());

		let display_name: Option<
			frame_support::BoundedVec<
				u8,
				frame_support::pallet_prelude::ConstU32<{ crate::MAX_METADATA_LEN }>,
			>,
		> = Some(b"Benchmark User".to_vec().try_into().expect("short name"));
		let bio: Option<
			frame_support::BoundedVec<
				u8,
				frame_support::pallet_prelude::ConstU32<{ crate::MAX_METADATA_LEN }>,
			>,
		> = Some(
			b"Benchmark bio string for testing"
				.to_vec()
				.try_into()
				.expect("short bio"),
		);

		#[extrinsic_call]
		set_account_metadata(RawOrigin::Signed(caller.clone()), display_name, bio, None);

		assert!(AccountMetadatas::<T>::contains_key(&caller));
	}

	// ─── dispatch_as_linked_account ──────────────────────────────────────────
	//
	// Benchmark of the proxy call with host functions (WASM-compatible).

	#[benchmark]
	fn dispatch_as_linked_account() {
		let owner: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"dispatch_bnch");
		register_alias_for::<T>(&owner, alias.clone());
		SupportedChains::<T>::insert(1u32, crate::SignatureScheme::Eip191);

		// Generate a key pair in the keystore.
		let pubkey =
			sp_io::crypto::ecdsa_generate(BENCH_KEY, Some(b"//bench_dispatch_01".to_vec()));

		// Sign the owner's AccountId (to verify ownership of the chain link).
		let account_bytes = owner.encode();
		let final_hash = crate::utils::eip191_message_hash(&account_bytes);
		let sig = sp_io::crypto::ecdsa_sign_prehashed(BENCH_KEY, &pubkey, &final_hash)
			.expect("valid signing");
		let sig_bytes: [u8; 65] = sig.0;

		let full_pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig_bytes, &final_hash)
			.ok()
			.expect("valid recovery");
		let addr_hash = sp_io::hashing::keccak_256(&full_pubkey[..]);
		let eth_addr: crate::ExternalAddr = addr_hash[12..]
			.to_vec()
			.try_into()
			.expect("20 bytes fit in ExternalAddr");

		// Insert the chain link directly (bypasses add_chain_link).
		let mut record = crate::pallet::Identities::<T>::get(&alias).expect("identity exists");
		record
			.chain_links
			.try_push(crate::ChainLink {
				chain_id: 1,
				address: eth_addr.clone(),
			})
			.expect("free slot");
		crate::pallet::Identities::<T>::insert(&alias, record);
		crate::pallet::ReverseChainLinks::<T>::insert((1u32, eth_addr.clone()), &owner);

		// Prepare the inner call (empty remark) and its EIP-191 signature.
		let inner_call: <T as crate::pallet::Config>::RuntimeCall =
			frame_system::Call::<T>::remark {
				remark: Default::default(),
			}
			.into();
		let payload = inner_call.encode();
		let call_hash = crate::utils::eip191_message_hash(&payload);
		let sig2 = sp_io::crypto::ecdsa_sign_prehashed(BENCH_KEY, &pubkey, &call_hash)
			.expect("valid signing of inner call");
		let sig2_bytes: [u8; 65] = sig2.0;

		let relayer: T::AccountId = account("relayer", 0, 0);
		fund_account::<T>(&relayer);

		#[extrinsic_call]
		dispatch_as_linked_account(
			frame_system::RawOrigin::Signed(relayer),
			owner.clone(),
			1u32,
			addr_hash[12..].to_vec(),
			sig2_bytes.to_vec(),
			alloc::boxed::Box::new(inner_call),
		);
	}

	// ─── register_private_link ───────────────────────────────────────────────

	#[benchmark]
	fn register_private_link() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"prv_reg_bench");
		register_alias_for::<T>(&caller, alias.clone());

		let commitment = sp_io::hashing::keccak_256(b"benchmark_private_link_commitment");

		#[extrinsic_call]
		register_private_link(RawOrigin::Signed(caller.clone()), 501u32, commitment);

		let links = crate::pallet::PrivateChainLinks::<T>::get(&alias);
		assert_eq!(links.len(), 1);
		assert_eq!(links[0].commitment, commitment);
	}

	// ─── remove_private_link ─────────────────────────────────────────────────

	#[benchmark]
	fn remove_private_link() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"prv_rm_bench");
		register_alias_for::<T>(&caller, alias.clone());

		let commitment = sp_io::hashing::keccak_256(b"benchmark_remove_private_link");
		let link = crate::PrivateChainLink {
			chain_id: 502u32,
			commitment,
		};
		let mut links = crate::pallet::PrivateChainLinks::<T>::get(&alias);
		links.try_push(link).expect("free slot");
		crate::pallet::PrivateChainLinks::<T>::insert(&alias, links);

		#[extrinsic_call]
		remove_private_link(RawOrigin::Signed(caller.clone()), commitment);

		assert!(crate::pallet::PrivateChainLinks::<T>::get(&alias).is_empty());
	}

	// ─── reveal_private_link ─────────────────────────────────────────────────
	//
	// The chain must be in `SupportedChains` for this benchmark because
	// `reveal_private_link` verifies the signature from the external wallet.

	#[benchmark]
	fn reveal_private_link() {
		let caller: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"prv_rev_bench");
		register_alias_for::<T>(&caller, alias.clone());
		SupportedChains::<T>::insert(1u32, crate::SignatureScheme::Eip191);

		// Generate a key pair in the keystore with a deterministic seed.
		let pubkey = sp_io::crypto::ecdsa_generate(BENCH_KEY, Some(b"//bench_reveal_01".to_vec()));

		let account_bytes = caller.encode();
		let final_hash = crate::utils::eip191_message_hash(&account_bytes);
		let sig = sp_io::crypto::ecdsa_sign_prehashed(BENCH_KEY, &pubkey, &final_hash)
			.expect("valid signing");
		let sig_bytes: [u8; 65] = sig.0;

		let full_pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig_bytes, &final_hash)
			.ok()
			.expect("valid recovery");
		let addr_hash = sp_io::hashing::keccak_256(&full_pubkey[..]);
		let addr_bytes = addr_hash[12..].to_vec();

		// Compute commitment: keccak_256(chain_id_le ++ address ++ blinding).
		let blinding = [0x11u8; 32];
		let mut preimage = alloc::vec::Vec::new();
		preimage.extend_from_slice(&1u32.to_le_bytes());
		preimage.extend_from_slice(&addr_bytes);
		preimage.extend_from_slice(&blinding);
		let commitment = sp_io::hashing::keccak_256(&preimage);

		// Insert the private link into storage.
		let link = crate::PrivateChainLink {
			chain_id: 1u32,
			commitment,
		};
		let mut prv_links = crate::pallet::PrivateChainLinks::<T>::get(&alias);
		prv_links.try_push(link).expect("free slot");
		crate::pallet::PrivateChainLinks::<T>::insert(&alias, prv_links);

		#[extrinsic_call]
		reveal_private_link(
			RawOrigin::Signed(caller.clone()),
			commitment,
			addr_bytes,
			blinding,
			sig_bytes.to_vec(),
		);

		// The private link must have been promoted to a public chain link.
		assert!(crate::pallet::PrivateChainLinks::<T>::get(&alias).is_empty());
		let record = crate::pallet::Identities::<T>::get(&alias).expect("identity exists");
		assert_eq!(record.chain_links.len(), 1);
	}

	// ─── dispatch_as_private_link ────────────────────────────────────────────
	//
	// The mock verifier in benchmarks accepts any non-empty proof with byte[0] == 0x01.
	// In production the real verifier (pallet-zk-verifier) takes longer; this measures
	// the extrinsic coordination overhead without the ZK cost.

	#[benchmark]
	fn dispatch_as_private_link() {
		let owner: T::AccountId = whitelisted_caller();
		let alias = make_alias::<T>(b"prv_disp_bnch");
		register_alias_for::<T>(&owner, alias.clone());

		let commitment = sp_io::hashing::keccak_256(b"benchmark_dispatch_private");
		let link = crate::PrivateChainLink {
			chain_id: 503u32,
			commitment,
		};
		let mut prv_links = crate::pallet::PrivateChainLinks::<T>::get(&alias);
		prv_links.try_push(link).expect("free slot");
		crate::pallet::PrivateChainLinks::<T>::insert(&alias, prv_links);

		// Proof marked as valid by MockPrivateLinkVerifier (byte[0] == 0x01).
		let mut zk_proof = alloc::vec![0u8; 64];
		zk_proof[0] = 0x01;

		let inner_call: <T as crate::pallet::Config>::RuntimeCall =
			frame_system::Call::<T>::remark {
				remark: Default::default(),
			}
			.into();

		let relayer: T::AccountId = account("relayer", 0, 0);
		fund_account::<T>(&relayer);

		#[extrinsic_call]
		dispatch_as_private_link(
			frame_system::RawOrigin::Signed(relayer),
			owner.clone(),
			commitment,
			zk_proof,
			alloc::boxed::Box::new(inner_call),
		);
	}

	// ─── Benchmark test suite wiring ─────────────────────────────────────────

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
