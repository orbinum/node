//! Every pallet's index, pinned: an index is part of every call, event and
//! error encoding, and ISMP's relayers cache the metadata. Changing one is a
//! `transaction_version` bump and a client release, never a side effect.

use crate::*;
use frame_support::traits::PalletInfoAccess;

#[test]
fn pallet_indices_are_pinned() {
	let indices = [
		(System::index(), 0),
		(Timestamp::index(), 1),
		(Aura::index(), 2),
		(Grandpa::index(), 3),
		(Balances::index(), 4),
		(TransactionPayment::index(), 5),
		(Sudo::index(), 6),
		(Ethereum::index(), 7),
		(EVM::index(), 8),
		(EVMChainId::index(), 9),
		(BaseFee::index(), 10),
		(ManualSeal::index(), 11),
		(ZkVerifier::index(), 12),
		(ShieldedPool::index(), 13),
		(Authorship::index(), 14),
		(ValidatorSet::index(), 15),
		(Session::index(), 16),
		(Historical::index(), 17),
		(Offences::index(), 18),
		(Ismp::index(), 19),
		(IsmpGrandpa::index(), 20),
		(IsmpMessaging::index(), 21),
		(Staking::index(), 22),
		(VoterList::index(), 23),
		(AhClient::index(), 24),
		(AutoPayout::index(), 25),
		(RcClient::index(), 26),
		(PagedElection::index(), 27),
		(NominationPools::index(), 28),
		(DelegatedStaking::index(), 29),
		(EraPruning::index(), 30),
	];
	for (n, (actual, pinned)) in indices.into_iter().enumerate() {
		assert_eq!(actual, pinned, "pallet {n}");
	}
}
