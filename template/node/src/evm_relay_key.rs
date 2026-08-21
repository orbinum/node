//! The node's EVM relay identity.
//!
//! A validator signs relay transactions with an ECDSA key of keystore type
//! `evmr`, chosen freely by the operator and independent of the Aura key — so a
//! validator's consensus identity does not dictate its EVM identity.
//!
//! This module owns the whole question of *which key that is*:
//!
//! - [`resolve`] decides where the key comes from (dev seed or keystore);
//! - [`report_identity`] tells the operator which address to register on-chain.
//!
//! Absent a key the node still authors blocks; only relaying stops. That is
//! deliberate — a misconfigured relay must not take a validator out of
//! consensus.

use std::path::Path;

use sc_chain_spec::ChainType;
use sc_service::{config::KeystoreConfig, Configuration};

/// Keystore key type for the EVM relay key, inserted via `author_insertKey`.
pub const EVM_RELAY_KEY_TYPE: sp_core::crypto::KeyTypeId = sp_core::crypto::KeyTypeId(*b"evmr");

/// Filename prefix the LocalKeystore gives `evmr` entries: `hex(b"evmr")`.
const EVM_RELAY_FILE_PREFIX: &str = "65766d72";

/// Read the EVM relay key from the on-disk keystore.
///
/// The operator chooses this key freely and inserts it with
/// `author_insertKey("evmr", <phrase>, <pubkey>)`. It is independent of the Aura
/// key, so a validator's consensus identity does not dictate its EVM identity.
///
/// This bypasses `sp_keystore::Keystore` on purpose: that API never exposes
/// secret material, and `EthValidatorSigner` needs the raw seed to sign relay
/// transactions locally. Reading the LocalKeystore file format is the only way
/// to obtain it.
///
/// TODO: signing through `Keystore::ecdsa_sign_prehashed` instead would keep the
/// key inside the keystore and work with remote/HSM backends, at the cost of
/// reworking `EthValidatorSigner`.
///
/// Files are named `{hex(key_type)}{hex(pubkey)}` and hold a JSON-encoded secret
/// phrase. When the node runs with a keystore password the phrase on disk still
/// looks ordinary, but the password takes part in key derivation — so it must be
/// threaded through, exactly as `LocalKeystore` does, or the derived address
/// silently differs from the one registered on-chain.
fn from_keystore(keystore_path: &Path, password: Option<&str>) -> Option<String> {
	debug_assert_eq!(EVM_RELAY_FILE_PREFIX, hex::encode(EVM_RELAY_KEY_TYPE.0));

	let entries = match std::fs::read_dir(keystore_path) {
		Ok(entries) => entries,
		Err(e) => {
			log::warn!(
				target: "orbinum-relay",
				"cannot read keystore directory {}: {e}", keystore_path.display()
			);
			return None;
		}
	};

	// Collect and sort: read_dir order is filesystem-dependent, and silently
	// picking a different key across restarts would change the node's relay
	// identity while only one address is registered on-chain.
	let mut candidates: Vec<_> = entries
		.flatten()
		.map(|e| e.file_name().to_string_lossy().into_owned())
		.filter(|name| name.starts_with(EVM_RELAY_FILE_PREFIX))
		.collect();
	candidates.sort();

	if candidates.len() > 1 {
		log::warn!(
			target: "orbinum-relay",
			"{} keys of type \"evmr\" in the keystore; using {}. Remove the others \
			 so the relay identity cannot change across restarts.",
			candidates.len(),
			candidates[0],
		);
	}

	for name in candidates {
		let raw = match std::fs::read_to_string(keystore_path.join(&name)) {
			Ok(raw) => raw,
			Err(e) => {
				log::warn!(target: "orbinum-relay", "cannot read keystore entry {name}: {e}");
				continue;
			}
		};
		let phrase = match serde_json::from_str::<String>(&raw) {
			Ok(phrase) => phrase,
			Err(e) => {
				log::warn!(
					target: "orbinum-relay",
					"keystore entry {name} is not a JSON-encoded phrase: {e}; skipping"
				);
				continue;
			}
		};

		// `from_string_with_seed` accepts full SURIs, so a dev account would load
		// silently and its key is public knowledge.
		if is_well_known_dev_secret(&phrase) {
			log::error!(
				target: "orbinum-relay",
				"keystore entry {name} holds a well-known development key. Its private \
				 key is public, so any relay fees sent to it are stealable. Refusing to load."
			);
			continue;
		}

		use sp_core::Pair as _;
		let pair = match sp_core::ecdsa::Pair::from_string_with_seed(&phrase, password) {
			Ok((pair, _)) => pair,
			Err(e) => {
				log::warn!(
					target: "orbinum-relay",
					"keystore entry {name} is not a valid ECDSA key: {e:?}; skipping"
				);
				continue;
			}
		};

		log::info!(target: "orbinum-relay", "Loaded EVM relay key from keystore entry {name}");
		let seed: [u8; 32] = pair.seed();
		return Some(format!("0x{}", hex::encode(seed)));
	}

	None
}

/// Whether a secret URI resolves to a publicly-known development account.
///
/// `//Alice` and friends are derived from a published mnemonic, so a key that
/// starts with `//` — or is the well-known dev phrase — is not a secret.
fn is_well_known_dev_secret(phrase: &str) -> bool {
	const DEV_PHRASE: &str =
		"bottom drive obey lake curtain smoke basket hold race lonely fit walk";
	let trimmed = phrase.trim();
	trimmed.starts_with("//") || trimmed.starts_with(DEV_PHRASE)
}
// ── Selection and reporting ──────────────────────────────────────────────────

/// Alice's ECDSA seed, used only on `--dev` so the relay works out of the box.
///
/// Public and well known; `is_well_known_dev_secret` rejects the equivalent on
/// any other chain type.
const ALICE_ECDSA_SEED: &str = "0xcb6df9de1efca7a3998a8ead4e02159d5fa99c3e0d4fd6432667390bb4726854";

/// Decide which EVM relay key this node signs with, if any.
///
/// Dev chains get Alice's key injected so relaying works without setup; every
/// other chain reads keystore type `evmr`. Returns the 32-byte seed as `0x…`.
pub fn resolve(config: &Configuration) -> Option<String> {
	if matches!(config.chain_spec.chain_type(), ChainType::Development) {
		log::info!(
			target: "orbinum-relay",
			"🔑 Dev mode: using Alice's ECDSA key as EVM relay key"
		);
		return Some(ALICE_ECDSA_SEED.to_string());
	}

	let KeystoreConfig::Path { path, password } = &config.keystore else {
		log::warn!(
			target: "orbinum-relay",
			"keystore is not on disk; relaying is disabled"
		);
		return None;
	};

	use sp_core::crypto::ExposeSecret as _;
	from_keystore(path, password.as_ref().map(|p| p.expose_secret().as_str()))
}

/// Log the address the operator has to register on-chain, or why there is none.
///
/// Registration is manual and self-service (`relayer.registerRelayer`), so the
/// address has to reach a human somehow; the startup log is that channel.
pub fn report_identity(evm_key: Option<&str>) {
	match evm_key {
		Some(key_hex) => match fc_rpc::EthValidatorSigner::from_hex(key_hex) {
			Ok(signer) => log::info!(
				target: "orbinum-relay",
				"EVM relay address: {:?} — register it with relayer.registerRelayer(evmAddress)",
				signer.address()
			),
			Err(e) => log::error!(
				target: "orbinum-relay",
				"invalid EVM relay key in keystore: {e}"
			),
		},
		None => log::warn!(
			target: "orbinum-relay",
			"no EVM relay key in keystore (type \"evmr\"); relaying is disabled. \
			 Insert one with author_insertKey to enable it."
		),
	}
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_file_prefix_matches_the_key_type() {
		// The scan matches filenames, so a drift between the two would make the
		// node silently find no key at all.
		assert_eq!(EVM_RELAY_FILE_PREFIX, hex::encode(EVM_RELAY_KEY_TYPE.0));
	}

	#[test]
	fn dev_suris_are_recognised_as_public() {
		for phrase in ["//Alice", "//Bob", "  //Alice  ", "//Alice//stash"] {
			assert!(
				is_well_known_dev_secret(phrase),
				"{phrase:?} must be treated as public",
			);
		}
	}

	#[test]
	fn the_published_dev_phrase_is_recognised() {
		let dev = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";
		assert!(is_well_known_dev_secret(dev));
		// Also with a derivation appended, which still resolves to a known key.
		assert!(is_well_known_dev_secret(&format!("{dev}//Alice")));
	}

	#[test]
	fn a_real_mnemonic_is_not_flagged() {
		for phrase in [
			"legal winner thank year wave sausage worth useful legal winner thank yellow",
			"0xcb6df9de1efca7a3998a8ead4e02159d5fa99c3e0d4fd6432667390bb4726854",
		] {
			assert!(
				!is_well_known_dev_secret(phrase),
				"{phrase:?} must not be flagged",
			);
		}
	}

	#[test]
	fn a_missing_keystore_directory_yields_no_key() {
		let missing = Path::new("/nonexistent/orbinum/keystore");
		assert_eq!(from_keystore(missing, None), None);
	}

	#[test]
	fn an_empty_keystore_yields_no_key() {
		let dir = std::env::temp_dir().join("orbinum-evmr-empty");
		std::fs::create_dir_all(&dir).unwrap();
		assert_eq!(from_keystore(&dir, None), None);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn a_key_of_another_type_is_ignored() {
		// An `aura` entry must not be mistaken for a relay key — that confusion
		// is exactly what this module was written to end.
		let dir = std::env::temp_dir().join("orbinum-evmr-aura-only");
		std::fs::create_dir_all(&dir).unwrap();
		let aura_prefix = hex::encode(b"aura");
		std::fs::write(dir.join(format!("{aura_prefix}00")), "\"//Alice\"").unwrap();

		assert_eq!(from_keystore(&dir, None), None);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn a_dev_key_in_the_keystore_is_refused() {
		let dir = std::env::temp_dir().join("orbinum-evmr-dev-key");
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::write(
			dir.join(format!("{EVM_RELAY_FILE_PREFIX}00")),
			"\"//Alice\"",
		)
		.unwrap();

		// Loading it would route relay fees to a key whose secret is published.
		assert_eq!(from_keystore(&dir, None), None);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn a_real_key_is_loaded_as_a_hex_seed() {
		let dir = std::env::temp_dir().join("orbinum-evmr-real-key");
		std::fs::create_dir_all(&dir).unwrap();
		let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
		std::fs::write(
			dir.join(format!("{EVM_RELAY_FILE_PREFIX}00")),
			format!("\"{phrase}\""),
		)
		.unwrap();

		let seed = from_keystore(&dir, None).expect("a valid mnemonic must load");
		assert!(seed.starts_with("0x"));
		assert_eq!(seed.len(), 2 + 64, "32-byte seed as hex");

		// Deterministic: the same phrase always yields the same relay identity.
		assert_eq!(from_keystore(&dir, None).as_deref(), Some(seed.as_str()));
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn a_corrupt_entry_is_skipped_rather_than_fatal() {
		let dir = std::env::temp_dir().join("orbinum-evmr-corrupt");
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::write(dir.join(format!("{EVM_RELAY_FILE_PREFIX}00")), "not json").unwrap();

		assert_eq!(from_keystore(&dir, None), None);
		let _ = std::fs::remove_dir_all(&dir);
	}
}
