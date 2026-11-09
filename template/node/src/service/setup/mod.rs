//! What every command shares: the node's types, and its client, databases, import
//! queue and transaction pool (`partial`).

mod partial;
pub mod types;

pub use partial::{new_partial, Partial};
