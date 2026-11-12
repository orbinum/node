// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! The snapshot: candidates by index, and voters by page with their votes as
//! candidate indices.

use crate::phragmen::Accumulator;
use frame_election_provider_support::{ExtendedBalance, VoteWeight};
use frame_support::{BoundedVec, traits::Get};
use scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// A candidate's position in the target snapshot.
pub type TargetIndex = u16;

/// A candidate's state: its approval, and the sum of its voters' contributions
/// to its score under the loads of the winners applied so far.
#[derive(
	Encode,
	Decode,
	MaxEncodedLen,
	TypeInfo,
	Clone,
	Copy,
	Default,
	PartialEq,
	Eq,
	Debug
)]
pub struct Candidate {
	/// Stake of every voter approving it.
	pub approval: ExtendedBalance,
	pub sum: Accumulator,
}

/// A voter with stake, and its valid votes as candidate indices, deduplicated
/// and in its own order.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, PartialEq, Eq, Debug)]
#[codec(mel_bound(AccountId: MaxEncodedLen))]
#[scale_info(skip_type_params(MaxVotes))]
pub struct SnapshotVoter<AccountId, MaxVotes: Get<u32>> {
	pub who: AccountId,
	pub stake: VoteWeight,
	pub votes: BoundedVec<TargetIndex, MaxVotes>,
}

/// What a voter page costs a round, known before reading it: its voters, and
/// how many of them approve each candidate.
#[derive(Encode, Decode, MaxEncodedLen, TypeInfo, Clone, PartialEq, Eq, Debug)]
#[scale_info(skip_type_params(MaxTargets))]
pub struct PageInfo<MaxTargets: Get<u32>> {
	pub voters: u32,
	pub approvers: BoundedVec<u32, MaxTargets>,
}

impl<MaxTargets: Get<u32>> PageInfo<MaxTargets> {
	/// Voters of the page approving `target`.
	pub fn approvers_of(&self, target: TargetIndex) -> u32 {
		self.approvers
			.get(usize::from(target))
			.copied()
			.unwrap_or(0)
	}
}
