//! Routing a transaction's payment: the fee and the tip go to different places.

use crate::AccountId;
use core::marker::PhantomData;
use frame_support::traits::{
	fungible::{Balanced, Credit},
	tokens::imbalance::ResolveTo,
	Get, OnUnbalanced, TypedGet,
};

/// `pallet_transaction_payment`'s unbalance handler: it is handed the fee, then
/// the tip in currency `F`, and sends each to its own destination.
pub struct DealWithFees<F, FeeDest, TipDest>(PhantomData<(F, FeeDest, TipDest)>);

impl<F, FeeDest, TipDest> OnUnbalanced<Credit<AccountId, F>> for DealWithFees<F, FeeDest, TipDest>
where
	F: Balanced<AccountId>,
	FeeDest: OnUnbalanced<Credit<AccountId, F>>,
	TipDest: OnUnbalanced<Credit<AccountId, F>>,
{
	fn on_unbalanceds(mut fee_then_tip: impl Iterator<Item = Credit<AccountId, F>>) {
		if let Some(fee) = fee_then_tip.next() {
			FeeDest::on_unbalanced(fee);
		}
		if let Some(tip) = fee_then_tip.next() {
			TipDest::on_unbalanced(tip);
		}
	}

	/// A lone credit is a fee.
	fn on_nonzero_unbalanced(fee: Credit<AccountId, F>) {
		FeeDest::on_unbalanced(fee);
	}
}

/// Pays the current block's author in currency `F`, or `Fallback` when there is
/// none (an RPC simulation, a manually sealed dev block).
pub struct ToAuthor<F, Author, Fallback>(PhantomData<(F, Author, Fallback)>);

impl<F, Author, Fallback> OnUnbalanced<Credit<AccountId, F>> for ToAuthor<F, Author, Fallback>
where
	F: Balanced<AccountId>,
	Author: Get<Option<AccountId>>,
	Fallback: TypedGet<Type = AccountId>,
{
	fn on_nonzero_unbalanced(credit: Credit<AccountId, F>) {
		let credit = match Author::get() {
			Some(author) => match F::resolve(&author, credit) {
				Ok(()) => return,
				Err(credit) => credit,
			},
			None => credit,
		};
		ResolveTo::<Fallback, F>::on_unbalanced(credit);
	}
}
