//! Repository implementations

mod statistics_repository;
mod vk_repository;

pub use statistics_repository::{FrameStatisticsRepository, StatisticsError};
pub use vk_repository::{FrameVkRepository, RepositoryError};
