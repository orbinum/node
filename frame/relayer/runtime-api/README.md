# pallet-relayer-runtime-api

Substrate Runtime API for querying pallet-relayer state from outside the runtime (node, RPC, clients).

## Exposed Methods

| Method | Parameters | Return | Description |
|---|---|---|---|
| `is_relayer` | `account: AccountId32` | `bool` | Returns whether the account is a registered active relayer. |
| `pending_fees` | `account: AccountId32`, `asset_id: u32` | `u128` | Unclaimed fees in planck for the given asset. |
| `registered_evm_address` | `account: AccountId32` | `Option<[u8; 20]>` | EVM address (H160) associated with the relayer, if any. |

## Integration

### Runtime (`template/runtime/src/lib.rs`)

```rust
impl pallet_relayer_runtime_api::RelayerRuntimeApi<Block> for Runtime {
    fn is_relayer(account: AccountId32) -> bool {
        RelayerByAccount::<Runtime>::contains_key(&account)
    }
    fn pending_fees(account: AccountId32, asset_id: u32) -> u128 {
        PendingRelayerFees::<Runtime>::get(&account, asset_id)
    }
    fn registered_evm_address(account: AccountId32) -> Option<[u8; 20]> {
        RelayerByAccount::<Runtime>::get(&account).map(|h| h.0)
    }
}
```

### Runtime Cargo.toml

```toml
[dependencies]
pallet-relayer-runtime-api = { workspace = true }

[features]
std = [
    "pallet-relayer-runtime-api/std",
    # ...
]
```

## Technical Notes

- Compatible with `#![no_std]`. Requires `extern crate alloc` to satisfy the `decl_runtime_apis!` macro expansion.
- Trait version: `1`. Breaking changes must increment the version and keep a legacy impl.
- Fees are always expressed in planck (1 ORB = 10¹⁸ planck).
