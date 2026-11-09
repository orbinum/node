//! The version this binary declares, and when the chain's minimum above it is reported.

use super::*;
use scale_codec::Encode;
use sp_inherents::{InherentData, InherentDataProvider as _};

fn version(text: &str) -> NodeVersion {
	NodeVersion::parse(text).expect("valid version")
}

#[test]
fn author_version_is_the_crate_version() {
	assert_eq!(AUTHOR_VERSION, version(env!("CARGO_PKG_VERSION")));
	assert_eq!(AUTHOR_VERSION.to_string(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn provider_declares_the_author_version() {
	let mut data = InherentData::new();
	futures::executor::block_on(inherent_data_provider().provide_inherent_data(&mut data)).unwrap();
	assert_eq!(
		data.get_data::<NodeVersion>(&pallet_validator_set::author_version::INHERENT_IDENTIFIER)
			.unwrap(),
		Some(AUTHOR_VERSION)
	);
}

#[test]
fn no_minimum_or_one_at_or_below_ours_is_not_reported() {
	assert_eq!(minimum_above_ours(None).unwrap(), None);
	assert_eq!(
		minimum_above_ours(Some(&AUTHOR_VERSION.encode())).unwrap(),
		None
	);
	assert_eq!(
		minimum_above_ours(Some(&version("0.0.1").encode())).unwrap(),
		None
	);
}

#[test]
fn a_minimum_above_ours_is_reported() {
	let above = version("65535.0.0");
	assert_eq!(
		minimum_above_ours(Some(&above.encode())).unwrap(),
		Some(above)
	);
}

#[test]
fn an_undecodable_minimum_is_an_error() {
	assert!(minimum_above_ours(Some(&[1])).is_err());
}
