# Changelog for `fc-rpc`

## Unreleased

* `eth_getFilterChanges`: the first poll of a log filter scans its range, and every later poll skips journal logs the scan covered, so a block journaled late is not returned twice; a reorg entry is skipped on the first poll (the scan read the new chain) and passes through after it. A result over `max_past_logs`, from the scan or the journal, drops the filter instead of failing the same way on every poll.
* Fix `estimate_gas`: ensure that provided gas limit it never larger than current block's gas limit
* `EthPubSubApi::new` takes an additional `overrides` parameter.
* Fix `estimate_gas` inaccurate issue.
* Use pallet-ethereum 3.0.0-dev.
* `EthFilterApi::new` takes an additional `backend` parameter.
* Bump `fp-storage` to `2.0.0-dev`.
* Bump `fc-db` to `2.0.0-dev`.
* Removed on-memory pending transactions in favor of transaction pool.
