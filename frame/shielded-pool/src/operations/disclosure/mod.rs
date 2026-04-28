mod batch_submit;
mod policy;
mod record;
mod request;
mod submit;
pub mod validation;

use crate::{
	pallet::{BalanceOf, BatchDisclosureSubmission, Config},
	types::{Auditor, Commitment, DisclosureCondition},
};
use frame_support::{BoundedVec, pallet_prelude::*};
use frame_system::pallet_prelude::BlockNumberFor;

pub struct DisclosureOperation;

impl DisclosureOperation {
	pub fn set_audit_policy<T: Config>(
		who: &T::AccountId,
		auditors: BoundedVec<Auditor<T::AccountId>, ConstU32<10>>,
		conditions: BoundedVec<DisclosureCondition<BalanceOf<T>, BlockNumberFor<T>>, ConstU32<10>>,
		max_frequency: Option<BlockNumberFor<T>>,
		valid_until: Option<BlockNumberFor<T>>,
	) -> DispatchResult {
		policy::set_audit_policy::<T>(who, auditors, conditions, max_frequency, valid_until)
	}

	pub fn request_disclosure<T: Config>(
		auditor: &T::AccountId,
		target: &T::AccountId,
		reason: BoundedVec<u8, ConstU32<256>>,
	) -> DispatchResult {
		request::request_disclosure::<T>(auditor, target, reason)
	}

	pub fn reject_disclosure<T: Config>(
		target: &T::AccountId,
		auditor: &T::AccountId,
		reason: BoundedVec<u8, ConstU32<256>>,
	) -> DispatchResult {
		request::reject_disclosure::<T>(target, auditor, reason)
	}

	pub fn disclose<T: Config>(
		who: &T::AccountId,
		commitment: Commitment,
		proof_bytes: BoundedVec<u8, ConstU32<256>>,
		public_signals: BoundedVec<u8, ConstU32<76>>,
		auditor: Option<&T::AccountId>,
	) -> DispatchResult {
		submit::disclose::<T>(who, commitment, proof_bytes, public_signals, auditor)
	}

	pub fn batch_submit_proofs<T: Config>(
		who: &T::AccountId,
		submissions: BoundedVec<BatchDisclosureSubmission<T::AccountId>, ConstU32<10>>,
	) -> DispatchResult {
		batch_submit::batch_submit_proofs::<T>(who, submissions)
	}
}
