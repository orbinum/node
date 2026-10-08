//! The node version a block author declares, and the rules the runtime applies
//! to it.
//!
//! The runtime cannot see the binary executing it, so the author's node states
//! its version in an inherent and the runtime checks the statement against
//! [`MinAuthorVersion`](crate::MinAuthorVersion). It coordinates honest
//! operators; it does not stop a modified binary from claiming any version.
//!
//! A binary that predates this inherent provides none: while no minimum is set
//! that changes nothing, and once one is, its blocks are invalid.
//!
//! Declarations are public chain state: anyone can map a validator to the
//! version it runs, as telemetry and `system_version` already allow.
//!
//! - [`version`]: the declared [`NodeVersion`].
//! - [`inherent`]: how the node hands it to the runtime.
//! - `declarations`: what the runtime accepts, records and rejects.

mod declarations;
pub mod inherent;
pub mod version;

pub use inherent::INHERENT_IDENTIFIER;
#[cfg(feature = "std")]
pub use inherent::InherentDataProvider;
pub use version::NodeVersion;
