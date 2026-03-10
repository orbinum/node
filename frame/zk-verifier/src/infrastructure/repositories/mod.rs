//! Repository implementations

mod statistics_repository;
mod vk_repository;

pub use statistics_repository::{FrameStatisticsRepository, StatisticsError};
pub use vk_repository::{
	FrameVkRepository, RepositoryError, runtime_active_version, runtime_supported_versions,
	runtime_vk_hash,
};
