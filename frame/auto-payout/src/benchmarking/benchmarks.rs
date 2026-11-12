// Copyright (C) Orbinum Technologies.
// SPDX-License-Identifier: GPL-3.0-or-later

//! Benchmarks for `pallet-auto-payout`'s calls. The hooks price their pages
//! with staking's weights and their storage accesses with `DbWeight`.

use crate::*;
use frame_benchmarking::v2::*;
use frame_support::traits::{EnsureOrigin, Get};

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn set_limits() -> Result<(), BenchmarkError> {
		let limits = T::DefaultLimits::get();
		let origin =
			T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

		#[extrinsic_call]
		_(origin as T::RuntimeOrigin, limits);

		assert_eq!(Limits::<T>::get(), limits);
		Ok(())
	}

	#[benchmark]
	fn pause() -> Result<(), BenchmarkError> {
		let origin =
			T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

		#[extrinsic_call]
		_(origin as T::RuntimeOrigin);

		assert!(Paused::<T>::get());
		Ok(())
	}

	#[benchmark]
	fn resume() -> Result<(), BenchmarkError> {
		Paused::<T>::put(true);
		let origin =
			T::AdminOrigin::try_successful_origin().map_err(|_| BenchmarkError::Weightless)?;

		#[extrinsic_call]
		_(origin as T::RuntimeOrigin);

		assert!(!Paused::<T>::get());
		Ok(())
	}

	impl_benchmark_test_suite!(
		Pallet,
		crate::tests::mock::new_test_ext(),
		crate::tests::mock::Test
	);
}
