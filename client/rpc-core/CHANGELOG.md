# Changelog for `fc-rpc-core`

## Unreleased
- `txpool_content`, `txpool_inspect` and `eth_pendingTransactions` take the request's extensions, so the server can refuse them on a `safe` endpoint.
- Add `FilteredParams::address_in_bloom()` and `FilteredParams::topics_in_bloom()` functions to check the possible existence of Filter addresses or topics in a block.
- Removed `PendingTransaction` and `PendingTransactions` types.
