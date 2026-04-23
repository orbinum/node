# pallet-relayer-rpc

JSON-RPC server for querying pallet-relayer state from external clients (wallets, indexers, dashboards).

## Exposed Endpoints

### `relayer_isRelayer`

Returns `true` if the given SS58 address is a registered relayer.

```json
// Request
{ "method": "relayer_isRelayer", "params": ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"] }

// Response
{ "result": true }
```

---

### `relayer_pendingFees`

Returns unclaimed fees in planck (as a decimal string) for a given account and asset.

```json
// Request
{ "method": "relayer_pendingFees", "params": ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", 0] }

// Response — string to preserve u128 precision
{ "result": "1500000000000000000" }
```

---

### `relayer_registeredEvmAddress`

Returns the EVM address (0x-prefixed hex) associated with the relayer, or `null` if none is registered.

```json
// Request
{ "method": "relayer_registeredEvmAddress", "params": ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"] }

// Response
{ "result": "0xd43593c715fdd31c61141abd04a99fd6822c8558" }
```

## Node Integration

### `template/node/src/rpc/mod.rs`

```rust
use pallet_relayer_rpc::{Relayer, RelayerApiServer};

// In create_full, add to the where clause:
// C::Api: pallet_relayer_runtime_api::RelayerRuntimeApi<B>,

io.merge(Relayer::new(client.clone()).into_rpc())?;
```

### `template/node/src/service.rs`

The bound must also be propagated to `new_full`:

```rust
where
    RA::RuntimeApi: pallet_relayer_runtime_api::RelayerRuntimeApi<B>,
    // ... other bounds
```

## Parameters

- `account` — SS58 address as a string. Decoded internally to `AccountId32`.
- `asset_id` — Numeric asset identifier (u32). `0` = native ORB.

## Errors

| Code | Description |
|---|---|
| `1` | Invalid SS58 address or runtime error. |

## Dependencies

- `jsonrpsee 0.24.9`
- `pallet-relayer-runtime-api` (sibling crate)
- `sp-api`, `sp-blockchain`, `sp-core`, `sp-runtime` (polkadot-sdk `stable2506`)
