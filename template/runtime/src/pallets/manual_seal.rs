// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

//! Dev-only manual seal: a genesis switch that lets the node seal blocks on demand and
//! stops Aura from checking their slots (`configs::consensus::ConsensusOnTimestampSet`).

use frame_support::parameter_types;

pub use pallet::*;

parameter_types! {
	pub storage EnableManualSeal: bool = false;
}

// No doc comment: the pallet's docs would reach the metadata.
#[frame_support::pallet]
pub mod pallet {
	use super::EnableManualSeal;
	use core::marker::PhantomData;
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
