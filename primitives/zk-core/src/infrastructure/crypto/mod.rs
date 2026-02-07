pub mod poseidon_hasher;

#[cfg(feature = "native-poseidon")]
pub mod native_poseidon_hasher;

pub use poseidon_hasher::LightPoseidonHasher;

#[cfg(feature = "native-poseidon")]
pub use native_poseidon_hasher::NativePoseidonHasher;
