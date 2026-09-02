//! Weights for `pallet-ismp-messaging`.
//!
//! The callback weights are discarded today: `WeightFeeHandler` with `POLICY = false`
//! returns `actual_weight: None` before looking at any of them. The moment relayer fees
//! are switched on they become the block's accounted weight, so a callback returning
//! `Weight::zero()` would make inbound delivery free and unmetered after a one-character
//! change in an unrelated file. Both upstream reference modules do exactly that.
//!
//! Conservative hand-written values, not benchmark output — over-charging costs
//! throughput, under-charging costs safety.
//!
//! Regenerating: `--extrinsic='*'` holds every result in memory through the analysis
//! phase and gets OOM-killed on a 16 GiB Linux host (measured: 15.4 GB resident before
//! the kernel reaped it). Benchmark one extrinsic per process and stitch the parts with
//! `scripts/benchmarks/merge-weights.sh` — see that script and the header of
//! `run_benchmarks.sh` for the full procedure.
//!
//! `on_response` resists even that: it is the one extrinsic whose analysis phase blows
//! past the memory of a 16 GiB Linux box on its own. Measured on macOS, where it does
//! complete, the real cost is ~3.4M ps against the 30M charged here — this value
//! over-charges by ~9x, so keeping it costs a little throughput and risks nothing. It is
//! also the cheapest handler in the pallet (two `len()` calls over at most 64 values and
//! one event), and with `POLICY = false` its weight is discarded before it is read.

use frame_support::weights::{Weight, constants::RocksDbWeight};

/// Weight functions for `pallet-ismp-messaging`.
pub trait WeightInfo {
	/// `b` is the body length in bytes.
	fn dispatch_post(b: u32) -> Weight;
	fn accept_source() -> Weight;
	fn remove_source() -> Weight;
	/// `b` is the body length in bytes.
	fn on_accept(b: u32) -> Weight;
	/// `n` is the number of storage values in the response.
	fn on_response(n: u32) -> Weight;
	fn on_timeout() -> Weight;
}

/// Per-byte cost applied to variable-length bodies.
const PER_BYTE: u64 = 2_000;

impl WeightInfo for () {
	fn dispatch_post(b: u32) -> Weight {
		// Dominated by the commitment and offchain-index writes.
		Weight::from_parts(200_000_000, 4096)
			.saturating_add(Weight::from_parts(PER_BYTE.saturating_mul(b as u64), 0))
			.saturating_add(RocksDbWeight::get().reads(2))
			.saturating_add(RocksDbWeight::get().writes(3))
	}

	fn accept_source() -> Weight {
		Weight::from_parts(20_000_000, 1024).saturating_add(RocksDbWeight::get().writes(1))
	}

	fn remove_source() -> Weight {
		Weight::from_parts(20_000_000, 1024).saturating_add(RocksDbWeight::get().writes(1))
	}

	fn on_accept(b: u32) -> Weight {
		// One source lookup, a decode bounded by `MaxBodyLen`, one counter write.
		Weight::from_parts(50_000_000, 2048)
			.saturating_add(Weight::from_parts(PER_BYTE.saturating_mul(b as u64), 0))
			.saturating_add(RocksDbWeight::get().reads(1))
			.saturating_add(RocksDbWeight::get().writes(1))
	}

	fn on_response(n: u32) -> Weight {
		Weight::from_parts(30_000_000, 2048)
			.saturating_add(Weight::from_parts(1_000_000u64.saturating_mul(n as u64), 0))
	}

	fn on_timeout() -> Weight {
		Weight::from_parts(20_000_000, 1024)
	}
}
