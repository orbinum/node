pub mod poseidon_hasher;

#[cfg(feature = "poseidon-native")]
pub mod native_poseidon_hasher;

pub use poseidon_hasher::LightPoseidonHasher;

#[cfg(feature = "poseidon-native")]
pub use native_poseidon_hasher::NativePoseidonHasher;
