#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

// ── External modules to the FRAME pallet ───────────────────────────────────────

/// ZK port: `PrivateLinkVerifierPort` + stub `DisabledPrivateLinkVerifier`.
pub mod ports;
pub use ports::{DisabledPrivateLinkVerifier, PrivateLinkVerifierPort};

/// Non-generic types, constants, and structs (no dependency on `T: Config`).
pub mod types;
pub use types::*;

/// Validation logic and cryptography decoupled from the pallet state.
pub mod utils;

/// Trait and weight estimates for all extrinsics.
pub mod weights;
pub use weights::WeightInfo;

#[cfg(test)]
pub mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

/// Implementations of Runtime API functions over the pallet storage.
/// Used from `impl_runtime_apis!` in the node runtime.
pub mod runtime_api_impl;

use sp_core::H160;

// ── Pallet FRAME ─────────────────────────────────────────────────────────────

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use alloc::{boxed::Box, vec::Vec};
	use frame_support::sp_runtime::traits::{Convert, Dispatchable, Zero};
	use frame_support::{
		dispatch::GetDispatchInfo,
		pallet_prelude::*,
		traits::{Currency, ExistenceRequirement, ReservableCurrency, UnfilteredDispatchable},
		Blake2_128Concat, Parameter,
	};
	use frame_system::pallet_prelude::*;

	// ── Generic types (depend on T: Config) ──────────────────────────────────────

	pub type BalanceOf<T> =
		<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

	/// Alias: UTF-8 string bounded by `T::MaxAliasLength`.
	pub type AliasOf<T> = BoundedVec<u8, <T as Config>::MaxAliasLength>;

	/// Sale listing for an alias.
	#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen)]
	#[scale_info(skip_type_params(T))]
	pub struct SaleListing<T: Config> {
		/// Asking price in native ORB.
		pub price: BalanceOf<T>,
		/// Optional whitelist. `None` = public sale. `Some` = private/OTC sale.
		pub allowed_buyers:
			Option<BoundedVec<T::AccountId, ConstU32<{ crate::MAX_WHITELIST_SIZE }>>>,
	}

	/// Identity record stored per alias.
	#[derive(
		Encode,
		Decode,
		Clone,
		PartialEq,
		Eq,
		RuntimeDebug,
		TypeInfo,
		MaxEncodedLen
	)]
	#[scale_info(skip_type_params(T))]
	pub struct IdentityRecord<T: Config> {
		/// AccountId32 owner of this alias.
		pub owner: T::AccountId,
		/// Derived EVM H160 address (None for purely native accounts).
		pub evm_address: Option<H160>,
		/// Balance reserved as deposit for this alias.
		pub deposit: BalanceOf<T>,
		/// Links to external chains (Bitcoin, Solana, …).
		pub chain_links: BoundedVec<ChainLink, ConstU32<MAX_CHAIN_LINKS>>,
	}

	// ── Pallet ────────────────────────────────────────────────────────────────

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	// ── Config ────────────────────────────────────────────────────────────────

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// Currency used for alias deposits.
		type Currency: ReservableCurrency<Self::AccountId>;

		/// Converts a Substrate AccountId to its equivalent EVM H160, if one exists.
		type AccountIdToEvmAddress: Convert<Self::AccountId, Option<H160>>;

		/// Minimum deposit required to register an alias.
		#[pallet::constant]
		type AliasDeposit: Get<BalanceOf<Self>>;

		/// Maximum alias length in bytes.
		#[pallet::constant]
		type MaxAliasLength: Get<u32>;

		/// Weights. Use [`weights::SubstrateWeight`] as a reference;
		/// replace with real benchmarks in production.
		type WeightInfo: crate::WeightInfo;

		/// Verifier for ZK proofs of `dispatch_as_private_link` (Phase 2).
		/// Use [`DisabledPrivateLinkVerifier`] until the circuit is deployed.
		type PrivateLinkVerifier: crate::PrivateLinkVerifierPort;

		/// Runtime call type (for `dispatch_as_linked_account` and `dispatch_as_private_link`).
		type RuntimeCall: Parameter
			+ Dispatchable<RuntimeOrigin = Self::RuntimeOrigin>
			+ GetDispatchInfo
			+ UnfilteredDispatchable<RuntimeOrigin = Self::RuntimeOrigin>;
	}

	// ──────────────────────────────────────────────
	// Storage
	// ──────────────────────────────────────────────

	/// EVM H160 → AccountId32 (stateful mapping).
	#[pallet::storage]
	#[pallet::getter(fn mapped_account)]
	pub type MappedAccounts<T: Config> =
		StorageMap<_, Blake2_128Concat, H160, T::AccountId, OptionQuery>;

	/// AccountId32 → EVM H160 (reverse index).
	#[pallet::storage]
	#[pallet::getter(fn mapped_address)]
	pub type OriginalAccounts<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, H160, OptionQuery>;

	/// Alias (bytes) → IdentityRecord.
	#[pallet::storage]
	#[pallet::getter(fn identity_of)]
	pub type Identities<T: Config> =
		StorageMap<_, Blake2_128Concat, AliasOf<T>, IdentityRecord<T>, OptionQuery>;

	/// Mapping of ChainId (u32) to its supported signature scheme.
	#[pallet::storage]
	#[pallet::getter(fn supported_chain)]
	pub type SupportedChains<T: Config> =
		StorageMap<_, Blake2_128Concat, ChainId, SignatureScheme, OptionQuery>;

	/// AccountId32 → Alias (reverse index for uniqueness enforcement).
	#[pallet::storage]
	#[pallet::getter(fn alias_of)]
	pub type AccountAliases<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, AliasOf<T>, OptionQuery>;

	/// Alias → sale listing. Present only when alias is listed for sale.
	#[pallet::storage]
	#[pallet::getter(fn listing_price)]
	pub type AliasListings<T: Config> =
		StorageMap<_, Blake2_128Concat, AliasOf<T>, SaleListing<T>, OptionQuery>;

	/// AccountId32 → AccountMetadata (profile details).
	#[pallet::storage]
	#[pallet::getter(fn account_metadata)]
	pub type AccountMetadatas<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, AccountMetadata, OptionQuery>;

	/// (ChainId, ExternalAddr) → AccountId32 (Reverse link index).
	#[pallet::storage]
	#[pallet::getter(fn link_owner)]
	pub type ReverseChainLinks<T: Config> =
		StorageMap<_, Blake2_128Concat, (ChainId, ExternalAddr), T::AccountId, OptionQuery>;

	/// Alias → private chain link commitments.
	/// No address is ever stored here — only Poseidon commitments.
	/// Coexists with the public `chain_links` inside `IdentityRecord`.
	#[pallet::storage]
	#[pallet::getter(fn private_chain_links)]
	pub type PrivateChainLinks<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		AliasOf<T>,
		BoundedVec<PrivateChainLink, ConstU32<MAX_CHAIN_LINKS>>,
		ValueQuery,
	>;

	// ──────────────────────────────────────────────
	// Events
	// ──────────────────────────────────────────────

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A stateful EVM mapping was registered.
		AccountMapped {
			account: T::AccountId,
			address: H160,
		},
		/// A stateful EVM mapping was removed.
		AccountUnmapped {
			account: T::AccountId,
			address: H160,
		},
		/// A human-readable alias was registered.
		AliasRegistered {
			account: T::AccountId,
			alias: AliasOf<T>,
			evm_address: Option<H160>,
		},
		/// An alias was released and the deposit returned.
		AliasReleased {
			account: T::AccountId,
			alias: AliasOf<T>,
		},
		/// An alias was transferred to a new owner.
		AliasTransferred {
			from: T::AccountId,
			to: T::AccountId,
			alias: AliasOf<T>,
		},
		/// An alias was listed for sale.
		AliasListedForSale {
			seller: T::AccountId,
			alias: AliasOf<T>,
			price: BalanceOf<T>,
			/// True if a buyer whitelist was set.
			private: bool,
		},
		/// A sale listing was cancelled by the owner.
		AliasSaleCancelled {
			seller: T::AccountId,
			alias: AliasOf<T>,
		},
		/// An alias was sold: price paid to seller, deposit reserved from buyer.
		AliasSold {
			seller: T::AccountId,
			buyer: T::AccountId,
			alias: AliasOf<T>,
			price: BalanceOf<T>,
		},
		/// A chain link was added via signature verification.
		ChainLinkAdded {
			account: T::AccountId,
			chain_id: ChainId,
			address: ExternalAddr,
		},
		/// A chain link was removed.
		ChainLinkRemoved {
			account: T::AccountId,
			chain_id: ChainId,
		},
		/// Account metadata (profile) was updated.
		MetadataUpdated { account: T::AccountId },
		/// A new chain support was added by governance.
		SupportedChainAdded {
			chain_id: ChainId,
			scheme: SignatureScheme,
		},
		/// A chain support was removed by governance.
		SupportedChainRemoved { chain_id: ChainId },
		/// A call was executed on behalf of a linked account.
		ProxyCallExecuted {
			owner: T::AccountId,
			chain_id: ChainId,
			address: ExternalAddr,
		},
		/// A private chain link commitment was registered. Address never revealed.
		PrivateChainLinkAdded {
			account: T::AccountId,
			chain_id: ChainId,
			commitment: [u8; 32],
		},
		/// A private chain link commitment was removed by its owner.
		PrivateChainLinkRemoved {
			account: T::AccountId,
			chain_id: ChainId,
			commitment: [u8; 32],
		},
		/// A private chain link commitment was revealed and promoted to a public chain link.
		/// Once emitted, the address is permanently public.
		PrivateChainLinkRevealed {
			account: T::AccountId,
			chain_id: ChainId,
			address: ExternalAddr,
		},
		/// A call was dispatched using a private link without revealing the wallet address.
		/// The commitment identifies which private slot was used; the real address is never exposed.
		PrivateLinkDispatchExecuted {
			owner: T::AccountId,
			commitment: [u8; 32],
		},
	}

	// ──────────────────────────────────────────────
	// Errors
	// ──────────────────────────────────────────────

	#[pallet::error]
	pub enum Error<T> {
		/// The account already has a stateful EVM mapping.
		AlreadyMapped,
		/// The EVM address is already mapped to another account.
		AddressAlreadyMapped,
		/// The account has no stateful EVM mapping to remove.
		NotMapped,
		/// The requested alias is already taken.
		AliasTaken,
		/// The account already owns an alias; release it first.
		AlreadyHasAlias,
		/// The account does not own any alias.
		NoAlias,
		/// Alias contains invalid characters (only [a-z0-9_] allowed).
		InvalidAliasCharacters,
		/// Alias is too short (minimum 3 bytes).
		AliasTooShort,
		/// The destination account already owns an alias.
		NewOwnerAlreadyHasAlias,
		/// Cannot transfer an alias to yourself.
		CannotTransferToSelf,
		/// The alias is not listed for sale.
		NotForSale,
		/// The alias is already listed for sale.
		AlreadyForSale,
		/// Sale price cannot be zero.
		PriceCannotBeZero,
		/// Buyer already owns an alias.
		BuyerAlreadyHasAlias,
		/// The buyer is not in the seller's whitelist for this alias.
		NotInWhitelist,
		/// The provided whitelist exceeds the maximum allowed size.
		WhitelistTooLarge,
		/// Native Substrate accounts (without EVM mapping) cannot be mapped blindly.
		NativeAccountCannotBeMapped,
		/// Invalid signature for the provided external address.
		InvalidSignature,
		/// The provided chain_id is not yet supported for signature verification.
		UnsupportedChain,
		/// The chain link already exists for this account.
		ChainLinkAlreadyExists,
		/// The chain link does not exist.
		ChainLinkNotFound,
		/// Too many external links (limit reached).
		TooManyLinks,
		/// The chain_id is already registered in the system.
		ChainAlreadySupported,
		/// The provided external address is not linked to the requested owner.
		NotOwnerOfLink,
		/// A private link with the same chain_id or commitment already exists.
		PrivateLinkAlreadyExists,
		/// No private link found with the given commitment.
		PrivateLinkNotFound,
		/// Too many private links registered (limit reached).
		TooManyPrivateLinks,
		/// The provided (address, blinding) do not produce the stored commitment.
		CommitmentMismatch,
		/// The ZK proof for a private link dispatch is invalid.
		InvalidProof,
	}

	// ──────────────────────────────────────────────
	// Calls
	// ──────────────────────────────────────────────

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Add support for a new blockchain signature scheme.
		///
		/// Only Callable by Root/Governance.
		#[pallet::call_index(11)]
		#[pallet::weight(T::DbWeight::get().writes(1))]
		pub fn add_supported_chain(
			origin: OriginFor<T>,
			chain_id: ChainId,
			scheme: SignatureScheme,
		) -> DispatchResult {
			ensure_root(origin)?;
			SupportedChains::<T>::insert(chain_id, scheme.clone());
			Self::deposit_event(Event::SupportedChainAdded { chain_id, scheme });
			Ok(())
		}

		/// Remove support for a blockchain.
		///
		/// Only Callable by Root/Governance.
		#[pallet::call_index(12)]
		#[pallet::weight(T::DbWeight::get().writes(1))]
		pub fn remove_supported_chain(origin: OriginFor<T>, chain_id: ChainId) -> DispatchResult {
			ensure_root(origin)?;
			SupportedChains::<T>::remove(chain_id);
			Self::deposit_event(Event::SupportedChainRemoved { chain_id });
			Ok(())
		}
		/// Register a stateful EVM → Substrate mapping using the fallback H160.
		/// This is the "lite" mapping for power users who don't need an alias.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::map_account())]
		pub fn map_account(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			ensure!(
				!OriginalAccounts::<T>::contains_key(&who),
				Error::<T>::AlreadyMapped
			);

			let address = T::AccountIdToEvmAddress::convert(who.clone())
				.ok_or(Error::<T>::NativeAccountCannotBeMapped)?;
			ensure!(
				!MappedAccounts::<T>::contains_key(address),
				Error::<T>::AddressAlreadyMapped
			);

			OriginalAccounts::<T>::insert(&who, address);
			MappedAccounts::<T>::insert(address, &who);

			Self::deposit_event(Event::AccountMapped {
				account: who,
				address,
			});

			Ok(())
		}

		/// Remove a stateful EVM mapping.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::unmap_account())]
		pub fn unmap_account(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let Some(address) = OriginalAccounts::<T>::take(&who) else {
				return Err(Error::<T>::NotMapped.into());
			};

			MappedAccounts::<T>::remove(address);

			Self::deposit_event(Event::AccountUnmapped {
				account: who,
				address,
			});

			Ok(())
		}

		/// Register a human-readable alias.
		///
		/// Rules:
		/// - Alias must be 3–`MaxAliasLength` bytes long.
		/// - Only lowercase alphanumeric characters and underscores: [a-z0-9_].
		/// - Requires reserving `AliasDeposit` ORB to prevent spam.
		/// - Each account can hold at most one alias at a time.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::register_alias())]
		pub fn register_alias(origin: OriginFor<T>, alias: AliasOf<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Validate format via utils (decoupled from the pallet state).
			crate::utils::validate_alias(&alias).map_err(|e| match e {
				crate::utils::AliasValidationError::TooShort => Error::<T>::AliasTooShort,
				crate::utils::AliasValidationError::InvalidCharacters => {
					Error::<T>::InvalidAliasCharacters
				}
			})?;

			// One alias per account.
			ensure!(
				!AccountAliases::<T>::contains_key(&who),
				Error::<T>::AlreadyHasAlias
			);

			// Alias must be unclaimed.
			ensure!(
				!Identities::<T>::contains_key(&alias),
				Error::<T>::AliasTaken
			);

			// Reserve the deposit.
			let deposit = T::AliasDeposit::get();
			T::Currency::reserve(&who, deposit)?;

			// Derive EVM address if available.
			let evm_address = T::AccountIdToEvmAddress::convert(who.clone());

			let record = IdentityRecord::<T> {
				owner: who.clone(),
				evm_address,
				deposit,
				chain_links: BoundedVec::default(),
			};

			Identities::<T>::insert(&alias, record);
			AccountAliases::<T>::insert(&who, &alias);

			Self::deposit_event(Event::AliasRegistered {
				account: who,
				alias,
				evm_address,
			});

			Ok(())
		}

		/// Release an alias, unreserving the deposit.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::release_alias())]
		pub fn release_alias(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let alias = AccountAliases::<T>::take(&who).ok_or(Error::<T>::NoAlias)?;

			let record = Identities::<T>::take(&alias).ok_or(Error::<T>::NoAlias)?;

			// Clean up reverse chain links.
			for link in record.chain_links.iter() {
				ReverseChainLinks::<T>::remove((link.chain_id, link.address.clone()));
			}

			// Clean up private chain link commitments (addresses never revealed).
			PrivateChainLinks::<T>::remove(&alias);

			// [C-1 FIX] Remove the active listing so the alias cannot be
			// purchased after being re-registered by another user.
			AliasListings::<T>::remove(&alias);

			// Return the reserved deposit.
			T::Currency::unreserve(&who, record.deposit);

			Self::deposit_event(Event::AliasReleased {
				account: who,
				alias,
			});

			Ok(())
		}

		/// Transfer ownership of an alias to another account.
		///
		/// Rules:
		/// - The caller must own the alias.
		/// - The destination account must not already own an alias.
		/// - The deposit is moved atomically: unreserved from sender, reserved from recipient.
		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::transfer_alias())]
		pub fn transfer_alias(origin: OriginFor<T>, new_owner: T::AccountId) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Cannot transfer to yourself.
			ensure!(who != new_owner, Error::<T>::CannotTransferToSelf);

			// Destination must not already have an alias.
			ensure!(
				!AccountAliases::<T>::contains_key(&new_owner),
				Error::<T>::NewOwnerAlreadyHasAlias,
			);

			// Take the alias from the current owner.
			let alias = AccountAliases::<T>::take(&who).ok_or(Error::<T>::NoAlias)?;

			// Load the identity record.
			let mut record = Identities::<T>::get(&alias).ok_or(Error::<T>::NoAlias)?;

			// [C-2 FIX] Cancel the active listing: the new owner must not
			// inherit a sale they did not authorize.
			AliasListings::<T>::remove(&alias);

			// Move the deposit: unreserve from old owner, reserve from new owner.
			// [H-1 FIX] Manual rollback is incorrect; FRAME automatically reverts
			// storage if the extrinsic returns Err.
			T::Currency::unreserve(&who, record.deposit);
			T::Currency::reserve(&new_owner, record.deposit)?;

			// Update the record with new owner and re-derived EVM address.
			let new_evm = T::AccountIdToEvmAddress::convert(new_owner.clone());
			record.owner = new_owner.clone();
			record.evm_address = new_evm;

			// Write back.
			Identities::<T>::insert(&alias, record.clone());
			AccountAliases::<T>::insert(&new_owner, &alias);

			// Update reverse chain links to new owner.
			for link in record.chain_links.iter() {
				ReverseChainLinks::<T>::insert((link.chain_id, link.address.clone()), &new_owner);
			}

			Self::deposit_event(Event::AliasTransferred {
				from: who,
				to: new_owner,
				alias,
			});

			Ok(())
		}

		/// List your alias for sale at a fixed price.
		///
		/// - `price`: asking price in native ORB. Must be > 0.
		/// - `allowed_buyers`: optional whitelist of up to `MAX_WHITELIST_SIZE` addresses.
		///   Pass `None` for a public listing (anyone can buy).
		///   Pass `Some(vec![…])` to restrict to specific buyers (private/OTC sale).
		/// - While listed the alias is still fully usable by the owner.
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::put_alias_on_sale())]
		pub fn put_alias_on_sale(
			origin: OriginFor<T>,
			price: BalanceOf<T>,
			allowed_buyers: Option<alloc::vec::Vec<T::AccountId>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			ensure!(price > Zero::zero(), Error::<T>::PriceCannotBeZero);

			let alias = AccountAliases::<T>::get(&who).ok_or(Error::<T>::NoAlias)?;

			// Refuse to re-list if already listed (must cancel first).
			ensure!(
				!AliasListings::<T>::contains_key(&alias),
				Error::<T>::AlreadyForSale
			);

			// Convert Vec to BoundedVec (enforces MAX_WHITELIST_SIZE).
			let bounded_buyers: Option<
				BoundedVec<T::AccountId, ConstU32<{ crate::MAX_WHITELIST_SIZE }>>,
			> = match allowed_buyers {
				None => None,
				Some(v) => Some(v.try_into().map_err(|_| Error::<T>::WhitelistTooLarge)?),
			};

			let private = bounded_buyers.is_some();
			let listing = SaleListing {
				price,
				allowed_buyers: bounded_buyers,
			};

			AliasListings::<T>::insert(&alias, listing);

			Self::deposit_event(Event::AliasListedForSale {
				seller: who,
				alias,
				price,
				private,
			});
			Ok(())
		}

		/// Cancel a sale listing, keeping the alias.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::cancel_sale())]
		pub fn cancel_sale(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let alias = AccountAliases::<T>::get(&who).ok_or(Error::<T>::NoAlias)?;

			ensure!(
				AliasListings::<T>::contains_key(&alias),
				Error::<T>::NotForSale
			);

			AliasListings::<T>::remove(&alias);

			Self::deposit_event(Event::AliasSaleCancelled { seller: who, alias });
			Ok(())
		}

		/// Purchase a listed alias.
		///
		/// The buyer must:
		/// - Not already own an alias.
		/// - Have enough free balance for (price + AliasDeposit).
		///
		/// Atomically:
		///   1. Payment (`price` ORB) transferred from buyer to seller.
		///   2. Seller's deposit unreserved back to seller.
		///   3. Buyer's deposit reserved from buyer.
		///   4. Alias ownership transferred.
		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::buy_alias())]
		pub fn buy_alias(origin: OriginFor<T>, alias: AliasOf<T>) -> DispatchResult {
			let buyer = ensure_signed(origin)?;

			// Buyer must not already own an alias.
			ensure!(
				!AccountAliases::<T>::contains_key(&buyer),
				Error::<T>::BuyerAlreadyHasAlias
			);

			// Retrieve the sale listing.
			let listing = AliasListings::<T>::get(&alias).ok_or(Error::<T>::NotForSale)?;

			// Whitelist check: if the listing is private, buyer must be in the list.
			if let Some(ref whitelist) = listing.allowed_buyers {
				ensure!(whitelist.contains(&buyer), Error::<T>::NotInWhitelist);
			}

			// Load the identity record to get the seller and their deposit.
			let mut record = Identities::<T>::get(&alias).ok_or(Error::<T>::NoAlias)?;
			let seller = record.owner.clone();

			// Step 1: transfer sale price from buyer to seller (free → free).
			T::Currency::transfer(
				&buyer,
				&seller,
				listing.price,
				ExistenceRequirement::KeepAlive,
			)?;

			// Step 2: unreserve seller's deposit back to seller.
			T::Currency::unreserve(&seller, record.deposit);

			// Step 3: reserve buyer's deposit (buyer now owns the alias).
			T::Currency::reserve(&buyer, record.deposit)?;

			// Step 4: update storage — atomic at block commit.
			AliasListings::<T>::remove(&alias);
			AccountAliases::<T>::remove(&seller);
			let new_evm = T::AccountIdToEvmAddress::convert(buyer.clone());
			record.owner = buyer.clone();
			record.evm_address = new_evm;
			Identities::<T>::insert(&alias, record);
			AccountAliases::<T>::insert(&buyer, &alias);

			Self::deposit_event(Event::AliasSold {
				seller,
				buyer,
				alias,
				price: listing.price,
			});
			Ok(())
		}

		/// Add a link to an external blockchain account by verifying a signature.
		///
		/// Supported chains (Initial Phase):
		/// - ChainId 1 (Ethereum): Verifies an EIP-191 style signature of the Substrate AccountId.
		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::add_chain_link())]
		pub fn add_chain_link(
			origin: OriginFor<T>,
			chain_id: ChainId,
			address: Vec<u8>,
			signature: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Account must have an alias to manage identity.
			let alias = AccountAliases::<T>::get(&who).ok_or(Error::<T>::NoAlias)?;
			let mut record = Identities::<T>::get(&alias).ok_or(Error::<T>::NoAlias)?;

			// Check if already exists.
			ensure!(
				!record.chain_links.iter().any(|l| l.chain_id == chain_id),
				Error::<T>::ChainLinkAlreadyExists
			);

			// [H-2 FIX] Single ECDSA recovery via utils (no duplication).
			// [M-3 FIX] Unknown chain_id returns UnsupportedChain, not InvalidSignature.
			let scheme = SupportedChains::<T>::get(chain_id).ok_or(Error::<T>::UnsupportedChain)?;

			match scheme {
				SignatureScheme::Eip191 => {
					// Ethereum: EIP-191 — mensaje = prefix32 + keccak256(AccountId32).
					let sig_array: [u8; 65] = signature
						.try_into()
						.map_err(|_| Error::<T>::InvalidSignature)?;
					crate::utils::verify_ethereum_signature(
						address.as_slice(),
						&who.encode(),
						&sig_array,
					)
					.map_err(|_| Error::<T>::InvalidSignature)?;
				}
				SignatureScheme::Ed25519 => {
					// Solana/Ed25519 signature of the AccountId32.
					let sig_array: [u8; 64] = signature
						.try_into()
						.map_err(|_| Error::<T>::InvalidSignature)?;
					crate::utils::verify_ed25519_signature(
						address.as_slice(),
						&who.encode(),
						&sig_array,
					)
					.map_err(|_| Error::<T>::InvalidSignature)?;
				}
			}

			// Add the link.
			let bounded_addr: ExternalAddr = address
				.clone()
				.try_into()
				.map_err(|_| Error::<T>::InvalidAliasCharacters)?; // Max length exceeded

			record
				.chain_links
				.try_push(ChainLink {
					chain_id,
					address: bounded_addr.clone(),
				})
				.map_err(|_| Error::<T>::TooManyLinks)?;

			Identities::<T>::insert(&alias, record);
			ReverseChainLinks::<T>::insert((chain_id, bounded_addr.clone()), &who);

			Self::deposit_event(Event::ChainLinkAdded {
				account: who,
				chain_id,
				address: bounded_addr,
			});
			Ok(())
		}

		/// Remove an existing chain link.
		#[pallet::call_index(9)]
		#[pallet::weight(T::WeightInfo::remove_chain_link())]
		pub fn remove_chain_link(origin: OriginFor<T>, chain_id: ChainId) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let alias = AccountAliases::<T>::get(&who).ok_or(Error::<T>::NoAlias)?;
			let mut record = Identities::<T>::get(&alias).ok_or(Error::<T>::NoAlias)?;

			let pos = record
				.chain_links
				.iter()
				.position(|l| l.chain_id == chain_id)
				.ok_or(Error::<T>::ChainLinkNotFound)?;

			let link = record.chain_links.remove(pos);
			Identities::<T>::insert(&alias, record);
			ReverseChainLinks::<T>::remove((chain_id, link.address));

			Self::deposit_event(Event::ChainLinkRemoved {
				account: who,
				chain_id,
			});
			Ok(())
		}

		/// Update account profile metadata.
		#[pallet::call_index(10)]
		#[pallet::weight(T::WeightInfo::set_account_metadata())]
		pub fn set_account_metadata(
			origin: OriginFor<T>,
			display_name: Option<BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>>,
			bio: Option<BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>>,
			avatar: Option<BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// [H-3 FIX] Only accounts that already paid the alias deposit can
			// write metadata, preventing mass spam in the state trie.
			ensure!(AccountAliases::<T>::contains_key(&who), Error::<T>::NoAlias);

			let metadata = AccountMetadata {
				display_name,
				bio,
				avatar,
			};
			AccountMetadatas::<T>::insert(&who, metadata);

			Self::deposit_event(Event::MetadataUpdated { account: who });
			Ok(())
		}

		/// Dispatch a call on behalf of a linked external account.
		///
		/// This is the "Universal Proxy Signing" feature. It allows a wallet from another
		/// chain (e.g. Solana via Phantom) to authorize an action on its Orbinum identity.
		#[pallet::call_index(13)]
		#[pallet::weight(T::WeightInfo::dispatch_as_linked_account())]
		pub fn dispatch_as_linked_account(
			origin: OriginFor<T>,
			owner: T::AccountId,
			chain_id: ChainId,
			address: Vec<u8>,
			signature: Vec<u8>,
			call: Box<<T as Config>::RuntimeCall>,
		) -> DispatchResult {
			let _relayer = ensure_signed(origin)?; // Anyone can pay gas to proxy the call

			// 1. Verify that (chain_id, address) is linked to 'owner'.
			let bounded_addr: ExternalAddr = address
				.clone()
				.try_into()
				.map_err(|_| Error::<T>::InvalidAliasCharacters)?;
			let actual_owner = ReverseChainLinks::<T>::get((chain_id, bounded_addr.clone()))
				.ok_or(Error::<T>::NotOwnerOfLink)?;
			ensure!(actual_owner == owner, Error::<T>::NotOwnerOfLink);

			// 2. Verify signature of the call payload.
			// Payload must be the encoded Call.
			let payload = call.encode();
			let scheme = SupportedChains::<T>::get(chain_id).ok_or(Error::<T>::UnsupportedChain)?;

			match scheme {
				SignatureScheme::Eip191 => {
					let sig_array: [u8; 65] = signature
						.try_into()
						.map_err(|_| Error::<T>::InvalidSignature)?;
					crate::utils::verify_ethereum_signature(
						address.as_slice(),
						&payload,
						&sig_array,
					)
					.map_err(|_| Error::<T>::InvalidSignature)?;
				}
				SignatureScheme::Ed25519 => {
					let sig_array: [u8; 64] = signature
						.try_into()
						.map_err(|_| Error::<T>::InvalidSignature)?;
					crate::utils::verify_ed25519_signature(
						address.as_slice(),
						&payload,
						&sig_array,
					)
					.map_err(|_| Error::<T>::InvalidSignature)?;
				}
			}

			// 3. Dispatch the call with the owner's origin.
			let result =
				call.dispatch_bypass_filter(frame_system::RawOrigin::Signed(owner.clone()).into());

			let dispatch_result = result.map(|_| ()).map_err(|e| e.error);

			dispatch_result?;

			Self::deposit_event(Event::ProxyCallExecuted {
				owner,
				chain_id,
				address: bounded_addr,
			});
			Ok(())
		}

		/// Register a private chain link by storing only its commitment on-chain.
		///
		/// The real address is never written to chain. The commitment must be computed
		/// off-chain using Poseidon:
		///   `inner      = Poseidon2(Fr::from(chain_id), address_as_field_element)`
		///   `commitment = Poseidon2(inner, blinding_as_field_element)`
		///
		/// Encoding: chain_id → `Fr::from(u64)`, address → zero-padded to 32 bytes then LE
		/// field element, blinding → 32-byte scalar as LE field element.
		///
		/// - `chain_id` does NOT need to be in `SupportedChains` (no signature check here).
		/// - Private links coexist with public links under the same alias.
		/// - Maximum `MAX_CHAIN_LINKS` private links per alias (shared limit).
		#[pallet::call_index(14)]
		#[pallet::weight(T::WeightInfo::register_private_link())]
		pub fn register_private_link(
			origin: OriginFor<T>,
			chain_id: ChainId,
			commitment: [u8; 32],
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let alias = AccountAliases::<T>::get(&who).ok_or(Error::<T>::NoAlias)?;
			let mut links = PrivateChainLinks::<T>::get(&alias);

			// Reject duplicate chain_id or identical commitment.
			ensure!(
				!links
					.iter()
					.any(|l| l.chain_id == chain_id || l.commitment == commitment),
				Error::<T>::PrivateLinkAlreadyExists
			);

			links
				.try_push(PrivateChainLink {
					chain_id,
					commitment,
				})
				.map_err(|_| Error::<T>::TooManyPrivateLinks)?;

			PrivateChainLinks::<T>::insert(&alias, links);
			Self::deposit_event(Event::PrivateChainLinkAdded {
				account: who,
				chain_id,
				commitment,
			});
			Ok(())
		}

		/// Remove a private chain link by its commitment.
		///
		/// No signature required: owning the alias is sufficient proof.
		/// The address is never revealed during removal.
		#[pallet::call_index(15)]
		#[pallet::weight(T::WeightInfo::remove_private_link())]
		pub fn remove_private_link(origin: OriginFor<T>, commitment: [u8; 32]) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let alias = AccountAliases::<T>::get(&who).ok_or(Error::<T>::NoAlias)?;
			let mut links = PrivateChainLinks::<T>::get(&alias);

			let pos = links
				.iter()
				.position(|l| l.commitment == commitment)
				.ok_or(Error::<T>::PrivateLinkNotFound)?;

			let removed = links.remove(pos);
			PrivateChainLinks::<T>::insert(&alias, links);

			Self::deposit_event(Event::PrivateChainLinkRemoved {
				account: who,
				chain_id: removed.chain_id,
				commitment,
			});
			Ok(())
		}

		/// Reveal a private link and promote it permanently to a public chain link.
		///
		/// Steps:
		///   1. Verifies `Poseidon2(Poseidon2(chain_id_fe, address_fe), blinding_fe) == stored commitment`.
		///   2. Verifies the external wallet signature of the owner's AccountId
		///      (same verification as `add_chain_link`).
		///   3. Removes the commitment from `PrivateChainLinks`.
		///   4. Inserts the address into the public `chain_links` of the `IdentityRecord`.
		///
		/// **This operation is irreversible.** Once revealed, the link is public.
		///
		/// Use case: selective disclosure — proving wallet ownership to an auditor,
		/// regulator, DAO, or grant committee without having been public from the start.
		#[pallet::call_index(16)]
		#[pallet::weight(T::WeightInfo::reveal_private_link())]
		pub fn reveal_private_link(
			origin: OriginFor<T>,
			commitment: [u8; 32],
			address: Vec<u8>,
			blinding: [u8; 32],
			signature: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let alias = AccountAliases::<T>::get(&who).ok_or(Error::<T>::NoAlias)?;
			let mut private_links = PrivateChainLinks::<T>::get(&alias);

			// 1. Locate and stage removal of the private link.
			let pos = private_links
				.iter()
				.position(|l| l.commitment == commitment)
				.ok_or(Error::<T>::PrivateLinkNotFound)?;
			let link = private_links.remove(pos);
			let chain_id = link.chain_id;

			// 2. Verify commitment: Poseidon2(Poseidon2(chain_id_fe, address_fe), blinding_fe)
			//    Encoding:
			//      chain_id_fe : Fr::from(chain_id as u64) → 4-byte LE, zero-padded to 32
			//      address_fe  : address bytes, zero-padded on right to 32 bytes, as LE field element
			//      blinding_fe : 32-byte random scalar, as LE field element
			let mut chain_id_fe_bytes = [0u8; 32];
			chain_id_fe_bytes[..4].copy_from_slice(&chain_id.to_le_bytes());

			let mut addr_fe_bytes = [0u8; 32];
			let copy_len = address.len().min(32);
			addr_fe_bytes[..copy_len].copy_from_slice(&address[..copy_len]);

			let inner = orbinum_zk_core::infrastructure::host_interface
                ::poseidon_host_interface::poseidon_hash_2(
                    &chain_id_fe_bytes,
                    &addr_fe_bytes,
                );
			let computed_vec = orbinum_zk_core::infrastructure::host_interface
                ::poseidon_host_interface::poseidon_hash_2(
                    &inner,
                    &blinding,
                );
			let computed: [u8; 32] = computed_vec
				.try_into()
				.map_err(|_| Error::<T>::CommitmentMismatch)?;
			ensure!(computed == commitment, Error::<T>::CommitmentMismatch);

			// 3. Verify the external wallet signature of the owner's AccountId.
			let scheme = SupportedChains::<T>::get(chain_id).ok_or(Error::<T>::UnsupportedChain)?;
			match scheme {
				SignatureScheme::Eip191 => {
					let sig_array: [u8; 65] = signature
						.try_into()
						.map_err(|_| Error::<T>::InvalidSignature)?;
					crate::utils::verify_ethereum_signature(
						address.as_slice(),
						&who.encode(),
						&sig_array,
					)
					.map_err(|_| Error::<T>::InvalidSignature)?;
				}
				SignatureScheme::Ed25519 => {
					let sig_array: [u8; 64] = signature
						.try_into()
						.map_err(|_| Error::<T>::InvalidSignature)?;
					crate::utils::verify_ed25519_signature(
						address.as_slice(),
						&who.encode(),
						&sig_array,
					)
					.map_err(|_| Error::<T>::InvalidSignature)?;
				}
			}

			// 4. Promote to public chain link.
			let mut record = Identities::<T>::get(&alias).ok_or(Error::<T>::NoAlias)?;
			let bounded_addr: ExternalAddr = address
				.clone()
				.try_into()
				.map_err(|_| Error::<T>::InvalidAliasCharacters)?;

			ensure!(
				!record.chain_links.iter().any(|l| l.chain_id == chain_id),
				Error::<T>::ChainLinkAlreadyExists
			);

			record
				.chain_links
				.try_push(ChainLink {
					chain_id,
					address: bounded_addr.clone(),
				})
				.map_err(|_| Error::<T>::TooManyLinks)?;

			// 5. Persist all changes atomically.
			PrivateChainLinks::<T>::insert(&alias, private_links);
			Identities::<T>::insert(&alias, record);
			ReverseChainLinks::<T>::insert((chain_id, bounded_addr.clone()), &who);

			Self::deposit_event(Event::PrivateChainLinkRevealed {
				account: who,
				chain_id,
				address: bounded_addr,
			});
			Ok(())
		}

		/// Dispatch a call using a privately linked wallet without revealing its address.
		///
		/// This is the Phase 2 completion of private identity. The caller provides:
		///   - `owner`: the Orbinum account that owns the alias and the private link.
		///   - `commitment`: the `[u8; 32]` stored in `PrivateChainLinks`.
		///   - `zk_proof`: a Groth16 proof asserting both:
		///       (a) Knowledge of `(address, blinding)` matching the commitment.
		///       (b) The external wallet at `address` signed `call_hash`.
		///   - `call`: the Substrate call to execute as `owner`.
		///
		/// The wallet address is **never revealed** at any point.
		///
		/// Gas can be paid by a relayer (any signed origin).
		///
		/// **Requires**: the `private_link_dispatch` ZK circuit artifact in
		/// `pallet-zk-verifier`. Set `type PrivateLinkVerifier = DisabledPrivateLinkVerifier`
		/// until the circuit is deployed.
		#[pallet::call_index(17)]
		#[pallet::weight(T::WeightInfo::dispatch_as_private_link())]
		pub fn dispatch_as_private_link(
			origin: OriginFor<T>,
			owner: T::AccountId,
			commitment: [u8; 32],
			zk_proof: Vec<u8>,
			call: Box<<T as Config>::RuntimeCall>,
		) -> DispatchResult {
			let _relayer = ensure_signed(origin)?;

			// 1. Verify alias exists for owner.
			let alias = AccountAliases::<T>::get(&owner).ok_or(Error::<T>::NoAlias)?;

			// 2. Verify the commitment is a registered private link.
			let links = PrivateChainLinks::<T>::get(&alias);
			ensure!(
				links.iter().any(|l| l.commitment == commitment),
				Error::<T>::PrivateLinkNotFound
			);

			// 3. Compute call_hash = blake2_256(encoded call) — this is the
			//    signed message verified inside the ZK circuit.
			let call_encoded = call.encode();
			let call_hash = sp_io::hashing::blake2_256(&call_encoded);

			// 4. Verify the ZK proof via the configured verifier port.
			ensure!(
				T::PrivateLinkVerifier::verify(&commitment, &call_hash, &zk_proof),
				Error::<T>::InvalidProof
			);

			// 5. Dispatch the call with the owner's origin.
			call.dispatch_bypass_filter(frame_system::RawOrigin::Signed(owner.clone()).into())
				.map(|_| ())
				.map_err(|e| e.error)?;

			Self::deposit_event(Event::PrivateLinkDispatchExecuted { owner, commitment });
			Ok(())
		}
	} // end #[pallet::call]

	// ──────────────────────────────────────────────
	// Helper impls
	// ──────────────────────────────────────────────

	impl<T: Config> Pallet<T> {
		/// Resolve an alias string to its IdentityRecord.
		///
		/// Returns `None` if the alias has an invalid format or is not registered.
		/// [L-2 FIX] Validates characters and length before querying storage.
		pub fn resolve_alias(alias: &[u8]) -> Option<IdentityRecord<T>> {
			crate::utils::validate_alias(alias).ok()?;
			let bounded: AliasOf<T> = alias.to_vec().try_into().ok()?;
			Identities::<T>::get(&bounded)
		}

		pub fn get_account_metadata(account: &T::AccountId) -> Option<AccountMetadata> {
			AccountMetadatas::<T>::get(account)
		}

		/// Returns all supported chains and their schemes.
		pub fn get_supported_chains() -> Vec<(u32, SignatureScheme)> {
			SupportedChains::<T>::iter().collect()
		}
	}
}
