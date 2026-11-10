//! The inherent that carries the author's node version from the node to the
//! runtime.

use super::NodeVersion;
use sp_inherents::InherentIdentifier;

/// Inherent identifier of the author's declared node version.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"nodevers";

/// Provides the running node's version to the blocks it authors.
#[cfg(feature = "std")]
pub struct InherentDataProvider(pub NodeVersion);

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
	async fn provide_inherent_data(
		&self,
		inherent_data: &mut sp_inherents::InherentData,
	) -> Result<(), sp_inherents::Error> {
		inherent_data.put_data(INHERENT_IDENTIFIER, &self.0)
	}

	async fn try_handle_error(
		&self,
		_identifier: &InherentIdentifier,
		_error: &[u8],
	) -> Option<Result<(), sp_inherents::Error>> {
		None
	}
}
