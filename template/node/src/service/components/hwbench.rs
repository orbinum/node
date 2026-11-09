//! Hardware benchmark, run at startup unless `--no-hardware-benchmarks`.

use frame_benchmarking_cli::SUBSTRATE_REFERENCE_HARDWARE;
use sc_service::{Configuration, Role, TaskManager};
use sc_sysinfo::HwBench;
use sc_telemetry::Telemetry;

/// Benchmarks the hardware the database lives on. `None` when disabled or the database
/// has no path.
pub fn gather(config: &Configuration, enabled: bool) -> Option<HwBench> {
	if !enabled {
		return None;
	}
	config.database.path().map(|database_path| {
		let _ = std::fs::create_dir_all(database_path);
		sc_sysinfo::gather_hwbench(Some(database_path), &SUBSTRATE_REFERENCE_HARDWARE)
	})
}

/// Prints the results, warns an authority below the reference hardware and reports to
/// telemetry.
pub fn report(
	hwbench: HwBench,
	role: &Role,
	telemetry: Option<&Telemetry>,
	task_manager: &TaskManager,
) {
	sc_sysinfo::print_hwbench(&hwbench);
	if let Err(err) = SUBSTRATE_REFERENCE_HARDWARE.check_hardware(&hwbench, false) {
		if role.is_authority() {
			log::warn!(
				"⚠️  The hardware does not meet the minimal requirements {err} for role 'Authority'."
			);
		}
	}
	if let Some(telemetry) = telemetry {
		task_manager.spawn_handle().spawn(
			"telemetry_hwbench",
			None,
			sc_sysinfo::initialize_hwbench_telemetry(telemetry.handle(), hwbench),
		);
	}
}
