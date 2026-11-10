//! The declared node version: parsing, ordering and display.

use crate::NodeVersion;

const V: fn(u16, u16, u16) -> NodeVersion = NodeVersion::new;

#[test]
fn parses_release_and_suffixed_versions() {
	assert_eq!(NodeVersion::parse("0.3.0"), Some(V(0, 3, 0)));
	assert_eq!(NodeVersion::parse("1.12.7-rc.1"), Some(V(1, 12, 7)));
	assert_eq!(NodeVersion::parse("2.0.1+sha.abc"), Some(V(2, 0, 1)));
	assert_eq!(
		NodeVersion::parse("65535.0.65535"),
		Some(V(65535, 0, 65535))
	);
}

#[test]
fn rejects_malformed_versions() {
	for bad in [
		"",
		"1",
		"1.2",
		"1.2.3.4",
		"a.b.c",
		"1.2.x",
		"1..2",
		".1.2",
		"1.2.",
		"70000.0.0",
		"1.65536.0",
		"-1.2.3",
		" 1.2.3",
	] {
		assert_eq!(NodeVersion::parse(bad), None, "{bad:?}");
	}
}

#[test]
fn parses_at_compile_time() {
	const PARSED: Option<NodeVersion> = NodeVersion::parse("1.2.3");
	assert_eq!(PARSED, Some(V(1, 2, 3)));
}

#[test]
fn orders_by_major_then_minor_then_patch() {
	assert!(V(0, 3, 0) < V(0, 3, 1));
	assert!(V(0, 3, 9) < V(0, 4, 0));
	assert!(V(0, 9, 9) < V(1, 0, 0));
	assert_eq!(V(1, 2, 3), V(1, 2, 3));
}

#[test]
fn displays_as_major_minor_patch() {
	assert_eq!(V(0, 4, 12).to_string(), "0.4.12");
}
