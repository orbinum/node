# pallet-ismp-messaging

Cross-chain messaging for Orbinum over ISMP, with Hyperbridge as the transport.

## The one thing to understand

Hyperbridge is the **coprocessor** — it verifies Orbinum's consensus and carries
messages. It is the *route*, not the *recipient*.

```
Orbinum ──dispatch_post(dest = <any connected chain>)──▶ pallet-ismp
                                                              │  commitment + offchain index
                                                              ▼
                                                           relayer
                                                              ▼
                                                Hyperbridge (verifies, routes)
                                                              ▼
                                                       destination chain
```

`dest` names the chain you want to reach — any state machine Hyperbridge connects to,
parachain or EVM. `pallet-ismp` consults `Coprocessor` itself, so the bridge never
appears in the call.

An earlier revision pinned `dest` to the coprocessor, which let Orbinum talk *to* the
bridge but never *through* it. The `RequestDispatched` event records the destination
that was asked for, which is what makes the regression detectable.

## Sending

```
# dest, to (8/20/32-byte module id), body, timeout
# `dest` is any chain reachable through Hyperbridge; Kusama(1000) is just an example.
ismpMessaging.dispatchPost({ Kusama: 1000 }, "0x64656d6f2f6d6f64", "0x00" + nonce, 0)
```

Root-only for now. `timeout` is **relative seconds**, and `0` means *never expires* —
not *expires immediately*.

## Receiving

Nothing arrives until the counterparty is whitelisted:

```
ismpMessaging.acceptSource({ Kusama: 1000 })    # root
```

`pallet-ismp` proves inclusion, freshness, uniqueness and destination before the
callback runs. `AcceptedSources` is the separate decision of *whose* messages we want,
and it is the extension point: one entry per counterparty chain.

## Adding a chain or a message type

- **Another chain** → `acceptSource` for inbound; pass its `dest` for outbound. No code.
- **Another message type** → append a variant to `Message` in `payload.rs` with the next
  free `#[codec(index = N)]`. Never renumber: the discriminant is wire format.
- **Acting on a message** → `inbound.rs`, in `on_accept` after the decode.

## Rules that are load-bearing

| Rule | Why |
|---|---|
| `on_timeout` never returns `Err` | The handler resolves the module *before* deleting the commitment and propagates with `?`. Erring strands our own requests permanently. Upstream's demo errs on `Get` — copying it is a live bug. |
| A bad payload returns `Ok`, not `Err` | `handle_unsigned` is `#[transactional]`; one `Err` reverts the whole batch, including other applications' messages. |
| An unaccepted source returns `Err` | There the receipt *should* be deleted so the sender can time out and recover. |
| Bodies are never stored or put in events | Inbound delivery is `Pays::No`; per-message storage is unbounded growth paid for by a remote party. |
| Callbacks return real weights | With `POLICY = false` the weight is discarded today, but becomes the block's accounted weight the moment relayer fees are switched on. |
| `PALLET_ID` is exactly 8 bytes | `ModuleId::from_bytes` infers the variant from length alone; 7 bytes parses as nothing and Hyperbridge would reject us. |

## Regenerating weights

The committed `weights.rs` is **hand-written and conservative**, not measured. Replace it
on a machine with stable timing:

```bash
cargo build --release -p orbinum-node --features runtime-benchmarks

./target/release/orbinum-node benchmark pallet \
  --chain=dev \
  --pallet=pallet_ismp_messaging \
  --extrinsic='*' \
  --steps=50 --repeat=20 \
  --wasm-execution=compiled \
  --output=./frame/ismp-messaging/src/weights.rs \
  --template=./scripts/frame-weight-template.hbs
```

Or `./scripts/run_benchmarks.sh`, which covers this pallet plus `ismp_grandpa` and
`pallet_ismp` — none of the three were in it before.

Then point the runtime at the measured values, in `configs/ismp/mod.rs`:

```rust
type WeightInfo = pallet_ismp_messaging::weights::SubstrateWeight<Runtime>;
```

Two invariants the benchmarks depend on. If either breaks, the numbers are wrong in the
unsafe direction:

- **`Linear<0, { T::MaxBodyLen::get() }>` uses the same constant the runtime enforces.**
  Diverging measures a range the runtime allows exceeding.
- **The padded body still decodes.** `Message::Data` carries a `Vec<u8>` so growing the
  payload grows a field that is really parsed. Each benchmark asserts its intended
  outcome (`InboundCount == 1`, `Nonce > 0`) precisely so a silent fall-through to a
  rejection path fails instead of producing an under-weight.
