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
# dest, to (8/20/32-byte module id), body, timeout (relative seconds)
# `dest` is any chain reachable through Hyperbridge; Kusama(1000) is just an example.
ismpMessaging.dispatchPost({ Kusama: 1000 }, "0x64656d6f2f6d6f64", "0x00" + nonce, 600)
```

Any signed account may send (spec 15), from a Substrate wallet or a MetaMask key alike —
both land on their own account. It costs `MessageFee` plus `MessageByteFee` per byte, paid to
the `orb/ismp` treasury and **never refunded**: a charge that came back on expiry could be
recycled for free every timeout.

**What counts as a byte** follows Hyperbridge's own billing basis, which bills a POST by the
whole ABI-encoded request rather than its payload alone. So a POST is charged its body plus
its `to` module id (8, 20 or 32 bytes), and a GET its keys plus its `context`.

Both fees are **storage, not constants** — 0.01 ORB and 0.000001 ORB/byte to start — and Root
reprices them with `set_message_fee` without a runtime upgrade. The `MaxMessageFee` ceiling
(1 ORB) bounds the **worst-case total**, `fee + byte_fee × max_chargeable_size`, not the flat
term on its own: capping the two separately would let a per-byte value at the ceiling price a
full-length message at many times the cap.

A signer must set a finite `timeout` between `MinSignedTimeout` (10 min) and
`MaxSignedTimeout` (7 days); `0` means *never expires* and is refused — not to get the fee
back, which never happens, but so the commitment can eventually be reclaimed.

Expired messages leave a commitment behind, and no relayer clears it — the protocol leaves
timeouts to the sender. Orbinum runs that for you:
`scripts/hyperbridge/relay-timeout.mjs --expired`. It recovers **storage, not funds**.

### Surface

| Call | Index | Origin |
|---|---|---|
| `dispatch_post` | 0 | `DispatchOrigin` or Root |
| `accept_source` | 1 | Root |
| `remove_source` | 2 | Root |
| `dispatch_get` | 3 | `DispatchOrigin` or Root |
| `confirm_delivery` | 4 | `DispatchOrigin` or Root |
| `set_outbound_paused` | 5 | Root |
| `set_message_fee` | 6 | Root |

Storage: `AcceptedSources` (whose messages we accept), `MessageFee` / `MessageByteFee` (the
price, Root-adjustable), `OutboundPaused` (an emergency brake on *signed* dispatch — Root is
unaffected, so this chain's own automation keeps working), `InboundCount` (a liveness
counter).

Bounds worth knowing: `MaxBodyLen` (8 KiB), `MaxGetKeys` (16 keys per GET) and `MaxGetKeyLen`
(128 bytes per key). The last comes from the protocol's own shapes — EVM keys are 20 or 52
bytes, `pallet-ismp`'s child-trie keys 47-51 — with headroom, because nothing upstream
enforces it.

Root sends free and may pass `0`; it is this chain's own automation. Root can also pause
signed dispatch entirely with `set_outbound_paused(true)` without affecting itself.

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

The committed `weights.rs` is generated, but it was **measured before the signed path
existed** — it declares none of the storage that path touches (no `Balances::Account`, no
`MessageFee`, no `OutboundPaused`). Regenerate it on a machine with stable timing:

```bash
cargo build --release -p orbinum-node --features runtime-benchmarks

./target/release/orbinum-node benchmark pallet \
  --chain=dev \
  --pallet=pallet_ismp_messaging \
  --extrinsic='*' \
  --steps=50 --repeat=20 \
  --wasm-execution=compiled \
  --output=./frame/ismp-messaging/src/weights.rs \
  --template=./scripts/benchmarks/frame-weight-template.hbs
```

Or `./scripts/benchmarks/run_benchmarks.sh`, which covers this pallet plus `ismp_grandpa` and
`pallet_ismp` — none of the three were in it before.

The runtime already points at the generated values (`configs/ismp/mod.rs`), so nothing needs
rewiring afterwards.

**Run `declared_proof_sizes_stay_within_a_sane_ceiling` first.** The benchmark CLI has a bug
that writes an absurd `proof_size` for `dispatch_post` — around 2.5 exabytes, and
non-deterministically — and the header comment in `weights.rs` that documents the
hand-correction is *deleted by the very regeneration that can reintroduce it*. That test is
what survives. Re-apply the header and the corrected value if it fires.

Two invariants the benchmarks depend on. If either breaks, the numbers are wrong in the
unsafe direction:

- **Every `Linear` range uses the same constant the runtime enforces** — `MaxBodyLen` for
  bodies, `MaxGetKeys` for key counts, with each key `MaxGetKeyLen` bytes long. Diverging
  measures a range the runtime allows exceeding, or pins the expensive dimension at its
  cheapest value.
- **The padded body still decodes.** `Message::Data` carries a `Vec<u8>` so growing the
  payload grows a field that is really parsed. Each benchmark asserts its intended
  outcome (`InboundCount == 1`, `Nonce > 0`) precisely so a silent fall-through to a
  rejection path fails instead of producing an under-weight.
