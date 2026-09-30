# Changelog for `fc-rpc`

## Unreleased

* Relay: `orbinum_relayShieldedCall` records a relay commit (`commitRelay`, batched) and waits for it to land before submitting the spend, so the fee is credited to this relayer. Skipped on runtimes without `ShieldedPoolRuntimeApi` v3 and `RelayerRuntimeApi` v2.
* Relay: an unregistered relay address fails fast instead of timing out, and a failed `commitRelay` submission is reported to every caller in its batch.
* Relay: one relay per spend — a request whose nullifiers are already in flight is refused, so N copies no longer cost the relayer N× gas. The dry-run is repeated after the commit lands; a commit already on-chain is not sent again; a spend another relayer's commit outranks — earlier block, or same block and lower hash, checked before and after our commit lands — is refused (that commit takes the fee); commit batches are sent from a task a disconnecting caller cannot cancel, one chunk per block, each only after the previous one is recorded, since the quota applies to the block a chunk lands in.
* Relay: a spend's claim holds while its request runs and lapses only once submitted; an error or a disconnecting caller releases it. Calldata is dry-run before claiming, so junk naming someone else's nullifier cannot block their relay. Waiting for a commit batch times out.
* Relay: the nonce recovers from a submitted transaction that never lands (the confirmed nonce is reused after `NONCE_STALL_BLOCKS`), and the chain is read under the submit lock.
* Relay: `orbinum_relayerStatus.enabled` requires registration (on runtimes with relay commits) and a balance for the worst case of a commit plus a spend.
* Relay (internal): commit batching lives in `relay/rpc/commit.rs` and the request's nullifier claim (`ClaimGuard`) in `relay/guard.rs`.
* `eth_getFilterChanges`: the first poll of a log filter scans its range, and every later poll skips journal logs the scan covered, so a block journaled late is not returned twice; a reorg entry is skipped on the first poll (the scan read the new chain) and passes through after it. A result over `max_past_logs`, from the scan or the journal, drops the filter instead of failing the same way on every poll.
* Fix `estimate_gas`: ensure that provided gas limit it never larger than current block's gas limit
* `EthPubSubApi::new` takes an additional `overrides` parameter.
* Fix `estimate_gas` inaccurate issue.
* Use pallet-ethereum 3.0.0-dev.
* `EthFilterApi::new` takes an additional `backend` parameter.
* Bump `fp-storage` to `2.0.0-dev`.
* Bump `fc-db` to `2.0.0-dev`.
* Removed on-memory pending transactions in favor of transaction pool.
