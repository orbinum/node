# `RuntimeVersion` history

Log of every change to `VERSION` (`template/runtime/src/lib.rs`). Any change
to `spec_version` / `transaction_version` must add a row here in the same PR.

## Bump rules

- **`spec_version`**: any consensus-affecting change — execution logic,
  storage, migrations, proof verification. Nodes reject blocks from a runtime
  with a different `spec_version`; forkless upgrades (`system.setCode`)
  require the new value to be greater.
- **`transaction_version`**: only when the SCALE encoding of extrinsics
  changes (dispatch signatures, argument order/types). Invalidates
  offline-signed extrinsics.
- **`impl_version`**: implementation-only changes with no consensus effect
  (equivalent optimizations). Rarely touched.

## Current era (testnet, post genesis reset 2026-07-15)

The genesis reset (`69d1b837`) set `spec_version` back to 1 and
`transaction_version` to 1 for the public testnet launch.

### spec 14 — tx 3 — [Unreleased]

**On-chain proof that an outbound message was delivered.**

Until now a delivered POST and one still in flight were indistinguishable from this
chain's own state, and the explorer had to ask a public BSC RPC to tell them apart —
an answer nothing could verify. This makes the question answerable with a proof.

**Why it cannot be done the obvious way.** Upstream #840 removed `PostResponse` from
the protocol: `IsmpModule` has three callbacks and `on_response` takes a concrete
`GetResponse`, so a destination *cannot* reply to a POST. What it does leave behind is
a receipt — `handlers/request.rs:112` writes `RequestReceipts[commitment] = relayer`
before invoking the receiving module and `:122-125` deletes it again if that module
errs. Its presence therefore proves **delivered and executed successfully**, which is
a stronger claim than the `PostRequestHandled` event, and it is ordinary storage, so a
GET can prove it.

| addition | detail |
|---|---|
| `confirm_delivery` (`call_index(4)`) | Root. Dispatches a GET for the receipt of a given commitment |
| `DeliveryConfirmed` event | `commitment`, `relayer`, `height` |
| `receipts` module | `RequestReceipts` key derivation, pinned against a receipt read live from Gargantua |

**Correlation carries no storage.** The confirming GET has its own commitment, unrelated
to the POST it proves, so the link travels in `DispatchGet.context` — which comes back
inside `GetResponse.get`. A storage map keyed on dispatch would strand an entry every
time a GET expired; this strands nothing.

**What it proves, precisely.** The receipt read is *Hyperbridge's*, not the final
destination's: `ismp-grandpa` gives this chain the coprocessor's ISMP child trie root and
nothing else, so an `Evm(_)` destination's storage is not provable here. Hyperbridge's
proxy re-dispatches through the same `on_accept` that writes receipts, so a receipt there
means the coprocessor **accepted and forwarded** the message — one hop short of execution
on the far side, but proven rather than taken on an RPC's word.

**There is no negative event.** An empty answer proves the receipt was absent *at that
height*, which is indistinguishable from asking before delivery. Nothing in this pallet
can say a message failed to arrive.

**No migration, no storage change. Weights: `confirm_delivery` reuses
`dispatch_get(1)`** — it is a one-key GET, which is exactly what that curve measures.

**`transaction_version` stays at 3**, for the same reason as spec 13: adding call index 4
leaves indices 0-3 and their encodings untouched, so offline-signed extrinsics still
decode.

### spec 13 — tx 3 — 2026-09-10 (`v0.1.0-rc.24`)

Every `ismpMessaging` event now carries what the callback already had in hand.
**`transaction_version` stays at 3** — events are metadata, so no call signature,
extrinsic encoding or storage layout changed and offline-signed extrinsics stay
valid.

**No migration, no storage change. Weights unchanged.**

Spec 12 made the inbound events attributable by adding `commitment`. This adds
the rest of what was being discarded, so no further runtime upgrade is needed for
cross-chain observability:

| event | new fields |
|---|---|
| `RequestDispatched` | `nonce`, `timeout_timestamp`, `body_len`, `kind` |
| `MessageReceived` | `nonce`, `timeout_timestamp` |
| `MessageRejected` | `body_len`, `nonce`, `timeout_timestamp` |
| `GetResponseReceived` | `dest`, `height`, `nonce`, `timeout_timestamp` |
| `RequestTimedOut` | `kind`, `nonce`, `timeout_timestamp`, `body_len` |

New enum `RequestKind { Post, Get }`, one byte, shared by `RequestDispatched` and
`RequestTimedOut`.

**New extrinsic `dispatch_get` (`call_index(3)`).** `transaction_version` stays at
3: adding a call index leaves indices 0-2 and their argument encodings untouched,
so an offline-signed extrinsic still decodes. Per this file's own rule, `tx` moves
only when the encoding of existing extrinsics changes.

It exists because a POST can be refused and a GET cannot. A POST is handed to a
module on the destination, which may reject it — `pallet-ismp-demo` on Hyperbridge
rejects any `Substrate(_)` source outright (`modules/pallets/demo/src/lib.rs:372-395`),
and the relayer dry-runs before submitting, so such a message is silently dropped
rather than delivered. A GET has no receiving module: whoever answers it reads the
requested keys on `dest`, and this chain verifies that read against a state commitment
of `dest` it already holds (`ismp-2606.1.0/src/handlers/response.rs`,
`SubstrateStateMachine::verify_state_proof`). Nothing on the far side can turn us away.

**Who answers it is the honest caveat.** The public relayer does not, today: Tesseract
resolves GETs on Hyperbridge (`tesseract/messaging/messaging/src/get_requests.rs` →
`StateCoprocessor.handle_unsigned`) and delivers the response **only to EVM sources** —
`events.rs:314-336`, *"Substrate sinks can't verify the mmr proof, so they are
skipped"*. So a GET dispatched here is answered by our own relaying script
(`scripts/hyperbridge/relay-get-response.mjs`), which is a legitimate ISMP relayer: it
carries a `state_getReadProof` of Hyperbridge at `height` into `Ismp.handle_unsigned`,
and the chain verifies it against the GRANDPA-tracked commitment. The relayer adds no
trust; it adds bytes. Until upstream delivers to Substrate sinks, `dispatch_get` without
that script is a request nobody will answer.

**What of Hyperbridge is readable: its ISMP child trie, not its global state.** For the
coprocessor, `ismp-grandpa` records `state_root = child_trie_root` and
`overlay_root = mmr_root` (`ismp-grandpa-2606.0.0/src/consensus.rs:142-150`) — verified
live: our stored commitment equals Gargantua's `ismp.childTrieRoot` at that height, not its
header's `state_root`. So a GET to Hyperbridge must name keys inside `:child_storage:default:ISMPv2`
(a `RequestReceipts`/`RequestCommitments` entry), the proof is `ismp_queryChildTrieProof`
with Hyperbridge's hasher (Keccak), and a GET for a global key such as `Ismp::Nonce` can never
verify here. This holds for any relayer, not only ours.

Three guards make an unanswerable GET fail at dispatch instead of hanging until it
expires: no keys (asks nothing, still costs a round trip), more than
`MaxGetKeys` = 16 (each key is a membership proof a REMOTE chain must produce, so this
bounds work we impose on someone else), and `height == 0` — the response handler
compares the proof height for *equality*
(`ismp-2606.1.0/src/handlers/response.rs:71`), so a height nobody can prove can never
be answered.

`dispatch_get`'s weight is **not benchmarked**: it reuses `dispatch_post`'s measured
base with a deliberately generous per-key term, which over-charges rather than
under-charges. Noted in `weights.rs` for whoever next runs the suite.

**Mainnet builds now whitelist Hyperbridge with `slot_duration = 12000`** (was 6000
for both targets). The value is the counterparty's Aura slot, and it differs per
deployment: Paseo 6000, Polkadot 12000 (`developers/polkadot/solochains`; confirmed live
against `aura.slotDuration` on Gargantua and Nexus). `ismp-grandpa` reconstructs every
Hyperbridge header timestamp as `aura_slot * slot_duration`, so the old value would have
dated every mainnet state commitment ~28 years early. **Testnet builds are unchanged**
(`--features hyperbridge-testnet` still yields 6000), so nothing on the live chain moves;
the constant now follows the build feature exactly as `coprocessor()` does. Not a storage
change — it only affects what `setup-deployed.mjs` whitelists on a fresh mainnet chain.

**`timeout_timestamp` has three states downstream and conflating any two is a
bug.** `0` means the message never expires — reproducing upstream's explicit
branch (`ismp-2606.1.0/src/dispatcher.rs:134`), NOT `now + 0`. A `NULL` in an
indexer means the block predates this runtime. Anything else is a real unix-seconds
deadline. Rendering `0` as a date claims the message expired in 1970.

`GetResponseReceived.height` is the only genuine remote block number this pallet
ever emits: an inbound POST carries none, because its proof is verified against
Hyperbridge's state rather than the origin's, so the origin's height never travels
on the wire.

**Deliberately omitted**, so the omissions are not mistaken for oversights:

- `body`, `keys`, `context`, `values` — unbounded and remote-controlled, on
  callbacks that run under `Pays::No`.
- `from` on `MessageRejected` — a remote `Vec` on the one event whose firing a
  remote sender controls. Its `body_len` is emitted instead.
- `source` on `RequestTimedOut` — constant. `on_timeout` only fires for requests we
  hold a commitment for (`handlers/timeout.rs:145`), so it is always
  `HostStateMachine`.
- `payer`, `fee` — constants while `DispatchOrigin` is Root. Opening the origin is
  an upgrade with its own review.
- The proof height on inbound events — it is Hyperbridge's, not the origin's, and it
  is already in the arguments of the same `handle_unsigned` extrinsic.

Weights are unchanged on purpose: the dispatch adds one read of `Nonce` and one of
`Timestamp` that `dispatch_request` performs anyway in the same overlay, and the
callbacks copy values already in memory.

**Indexers must treat every new field as optional.** Blocks produced before this
runtime genuinely lack them, and a re-index reads that history.

### spec 12 — tx 3 — 2026-09-08 (`v0.1.0-rc.22`)

Every `ismpMessaging` message event now carries the request's `commitment`.
**`transaction_version` stays at 3** — no dispatch signature changes; only event
metadata moves, so offline-signed extrinsics stay valid.

**No migration, no storage change.**

Four variants gained `commitment: H256` — `MessageReceived`, `MessageRejected`,
`RequestTimedOut` and `GetResponseReceived`. Until now they were anonymous: an
arrival could not be attributed to any message, a rejection looked to the sender
like a plain timeout, and an expiry could not be matched to the
`RequestDispatched` it closed out. Only `RequestDispatched` carried a commitment,
which made the whole inbound half of the bridge unindexable.

The value is derived with the protocol's own `hash_request`, not invented
locally. `pallet_ismp::dispatch_request` hashes the request exactly the same way
(`pallet-ismp-2606.1.0/src/impls.rs:91`), so it is the same commitment the
sender recorded and the same one `PostRequestHandled` reports for that message —
verified on a dev node, where our `RequestDispatched` and the protocol pallet's
`ismp.Request` emit an identical hash. A local counter or a hash of our own
would have produced an identifier no other chain has ever seen, which is worse
than none.

Cheap by construction: `on_timeout` already received the whole `Request` and
discarded everything but `dest`, and `on_accept` hashes once before its three
exit paths rather than per branch.

**Weights are left as they are.** The three callbacks now do one keccak256 that
the benchmarks did not measure, so the numbers are slight under-estimates. Safe
to ship: all three are `IsmpModule` callbacks reached through `handle_unsigned`,
whose declared weight is the caller's, and `on_accept`'s existing per-byte term
(222/byte) is the same shape as the hashing cost. Re-benchmark on the reference
hardware when convenient.

**Indexers must treat the field as optional.** Blocks produced before this
version genuinely have no commitment on those four events, so anything reading
history has to tolerate its absence rather than requiring it.

### spec 11 — tx 3 — 2026-09-03

**Recorded after the fact.** This row was missed when the version was bumped in
`0da2c698` (#140), which is the one rule this file has — noted here rather than
silently backfilled, since a gap in the log is worse than a late entry. Released
in `v0.1.0-rc.20` and **live on the public testnet**, confirmed by reading
`state_getRuntimeVersion` from `rpc-1`.

polkadot-sdk 2512 → 2606, and Hyperbridge integration for cross-chain messaging
with Paseo. **`transaction_version` stays at 3** — the SDK move and the new
pallets change metadata, not extrinsic encoding.

Adds `pallet-ismp`, `pallet-ismp-grandpa` and our own `pallet-ismp-messaging`
(indices 19, 20, 21), the ISMP runtime APIs, and the offchain DB the protocol
needs for its commitment tree. Also carries portable Frontier security and
correctness patches, sent upstream as polkadot-evm/frontier#1923.

See `scripts/hyperbridge/README.md` for the onboarding procedure and
`frame/ismp-messaging/README.md` for the pallet's own decisions.

### spec 10 — tx 3 — 2026-08-21

Validator onboarding moves off-chain, and the EVM relay identity becomes the
operator's to choose. Ships **validator-set 0.3.0** and **relayer 0.4.0**.
**`transaction_version` moves 2 → 3** — call indices are deleted and one
dispatch signature changes, so offline-signed extrinsics are invalidated and
wallets must ship alongside the runtime.

**No migration**, on two verified conditions rather than assumptions:

- `PendingValidators` was empty on testnet at release. A chain with a live queue
  would need one.
- Every `RelayerByAccount` holder must already be in `ApprovedValidators`. The
  new rules do not reach backwards, so a binding created by the old sudo-gated
  call for a non-validator would keep resolving in the fee path forever. This
  testnet runs 5 operator-owned validators, all in the set, so the gap is empty.

A chain where either does not hold needs migrations for them — for the second,
iterate `RelayerByAccount` and `clear_relayer` any holder outside the set.

**Relay guards**

Folded into this same version: spec 10 had not shipped when these landed, so
they released together with the onboarding change. `transaction_version` is
unaffected — no dispatch signature changes.

- `set_min_relay_fee` is capped by a new `Config::MaxMinRelayFee` (1 ORB, a
  thousand times the default) and rejects above it with `MinRelayFeeTooHigh`.
  Without a ceiling, one mistyped governance call could brick EVM relay until
  the next runtime upgrade — the call that would lower the fee again has to run
  on the runtime the mistake broke.
- `get_active_relayers` caps its result at 256 entries. The method has no
  callers today and registration is gated on the validator set, so nothing can
  reach the cap; it is headroom for whoever wires it up later.
- New `Event::RelayFeeDiverted`, emitted when relay calldata names an
  unregistered EVM address and the fee falls back to the block author. The
  fallback itself is unchanged — relaying is not gated on registration, so
  rejecting there would fail a user's transaction over someone else's
  misconfiguration.

**Relay fees are attributed by origin, not by argument**

`unshield` and `private_transfer` lose their `relayer: Option<H160>` parameter.
Both are `ensure_none`, so that field was an unauthenticated claim on an
unauthenticated call: anyone could take a propagated proof, resubmit it naming
themselves, and collect a fee they never paid for. It also had no honest
producer — the SDK sent `None`, and the precompile already knew the answer from
`handle.context().caller`.

The recipient now comes from the dispatch origin, which the calldata cannot
influence:

| Submitted via | Credited |
|---|---|
| EVM precompile | `context().caller` — signed the transaction and paid its gas |
| Signed extrinsic | the signer's registered EVM address |
| Unsigned extrinsic | nobody; the fee falls back to the block author |

The signed path is new and gives non-validator relayers a future on-ramp without
touching the registry. The registry still does the H160 → account resolution:
`EeSuffixAddressMapping` yields a synthetic account, not the validator's own.

**What this does not close.** A validator can still resubmit another node's spend
through the precompile under its own key and win *in the slots it authors* — the
pool tags on the nullifier alone, so the copy and the original are mutually
exclusive and it cannot win by arriving first. That caps theft at 1/N of relayed
volume, now costs real EVM gas, and names the thief in the block header. New
`Event::SelfRelayedFee` records every fee credited to the block's own author.
Self-relaying is legitimate — it happens ~1/N of the time by rotation — so this
is a signal for off-chain correlation, not grounds for automatic punishment;
enforcement is `validatorSet.removeValidator`. Closing it outright needs the
recipient as a circuit public input, which is a ceremony plus a VK migration and
is not proportionate while validation stays permissioned.

**Removed — validator self-registration**

- **`register_validator`, `approve_validator`, `reject_validator`** (call
  indices 2, 4, 5 — retired, never to be reassigned), the `PendingValidators`
  storage item, `MaxPendingValidators`, three events and four errors.
  Candidate selection now happens off-chain and sudo records the decision with
  `add_validator`. An on-chain queue only sudo could drain was a slower route
  to the same outcome.
- **`ValidatorPrerequisites::has_relayer`**, which severs the last
  validator-set → relayer coupling.

**Changed**

- **Session-key gate moved to `add_validator`.** Previously it guarded
  `register_validator`. Without it an approved account holding no keys would
  occupy a slot in the active set without ever authoring, leaving gaps in the
  slot schedule.
- **`relayer.register_relayer(who, evm_address)` →
  `register_relayer(evm_address, signature)`**, and from `ManageOrigin` to
  `Signed`. The operator registers their own address; the signer is the owner, so
  nobody can bind an address on another's behalf. **This is the dispatch
  signature change that forces the `transaction_version` bump.**

  `ManageOrigin` previously did two jobs: it kept arbitrary accounts out, and it
  let governance verify the operator actually owned the address. The validator-set
  gate replaces the first. The second needed the `signature`: a relay address is
  public (it is the `caller` of every relay transaction), so without proof of key
  ownership any approved validator could register a rival's address, take its
  fees, and lock the owner out permanently through `AlreadyRegistered`.

- **Zero and precompile-range addresses (`0x0..=0xffff`) are rejected.** Those
  "callers" originate inside the runtime, so no key can sign for them.

- **`SessionManager::new_session` filters out approved accounts with no session
  keys.** `session.purge_keys` is permissionless, so a validator could clear the
  `add_validator` gate and then drop its keys, holding an Aura slot while
  producing nothing.

**Added**

- **`ValidatorSetInterface`** in `pallet-validator-set`, implemented directly on
  its `Pallet<T>`, replacing a hand-written runtime adapter over
  `ApprovedValidators`. Follows the same provider-trait convention as
  `RelayerInterface`.
- **`OnValidatorRemoved` hook**, wired to `pallet_relayer::clear_relayer`: a
  relay binding cannot outlive the validator membership that authorised it.
  Infallible by design — leaving the set must never be blocked by cleanup.
  Accrued `PendingRelayerFees` are untouched; clearing a binding is not
  confiscation.

**Node-side (breaks running validators)**

- The node no longer derives its EVM relay key from the Aura mnemonic. It reads
  keystore type `evmr` instead, so consensus identity no longer dictates EVM
  identity. `relayer_register.rs` is deleted. **Without an `evmr` key a node
  still authors blocks — only relaying stops.** Operators keep their registered
  address by recovering the old key with `scripts/vk/derive-legacy-evm-key.cjs`.
- The relay fee fallback to the block author is **unchanged**: an unregistered
  relayer still credits the block author rather than failing the transaction.

**Removed — dead code**

- **`MigrateToV3` and the `migrations` module.** `Migrations` is now empty —
  every live chain is past v3, so the entry was a no-op behind a
  storage-version guard, and a migration that can no longer run is dead weight
  that could be re-armed by mistake. Replaying it against a v3 state aborts
  with *"produced an already-expired root"*, which `try-runtime
  on-runtime-upgrade` does by design (it forces migrations past their guard),
  so every upgrade rehearsal failed for the wrong reason. **No on-chain effect
  either way** — the guard already made it a single storage read.

### spec 9 — tx 2 — 2026-08-13

Security fixes plus one consensus fix. **`transaction_version` stays at 2** —
no dispatch signature changes, so offline-signed extrinsics remain valid and
wallet and runtime do NOT have to ship together.

**No migration, no storage change.**

**Consensus**

- **The sealed-node sweep no longer sizes its batch from the block's leftover
  weight — this halted the public testnet at block 406997.**
  `pallet-shielded-pool`'s `on_idle` divided `remaining` by the benchmarked
  per-node cost to pick how many nodes to prune. Leftover weight is not
  consensus: once post-dispatch refunds are in play an author and an importer
  measure the same block slightly differently, so each pruned a different
  number of nodes and wrote a different state. Frontier folds that state into
  the Ethereum block header it builds in `on_finalize`, so the divergence
  surfaced as a mismatched `"fron"` digest and `Executive::final_checks`
  panicked with *"Digest item must match that calculated."*

  Three validators with identical state at 406997 and byte-identical extrinsics
  in 406998 produced three mutually unimportable blocks; the chain stopped for 4
  hours. It survived five days on spec 8 only because empty blocks leave the
  same leftover weight on every node — the first block carrying real EVM
  traffic split the network three ways.

  The sweep now runs in `on_initialize` over a constant batch
  (`PRUNED_NODES_PER_BLOCK`, unchanged at 512, ~6.5 ms of a 2 s block) and
  charges the full batch rather than the removals, since a miss costs the same
  read as a hit. The state transition differs only in that it is now identical
  on every node.

  A governance runtime upgrade cannot deliver this fix: applying one needs a
  block, and a forked network no longer agrees on any. Roll the binary out to
  every validator together.

**Security**

- **shielded-pool 0.17.1 — pool admission tags one entry per nullifier**, in a
  namespace shared with `unshield` (`ShieldedPoolSpend`). `and_provides`
  contributes exactly ONE tag, so passing it a `Vec` encoded the whole
  nullifier set plus the relayer into a single blob. Three consequences, each
  free for an attacker since the fee is only charged on execution: reordering
  the two inputs minted a second admissible entry for the same spend; two
  transfers sharing only ONE note (A+B and A+C) did not collide at all, so one
  note could back unboundedly many entries; and transfer/unshield used
  different prefixes, so the same note could back one of each at once. Every
  variant propagates and is revalidated network-wide while at most one can
  execute.

  `relayer` deliberately leaves the tag. Binding it made a copy with a swapped
  fee recipient a *separate* entry, so anyone could rebroadcast another user's
  spend pointed at their own account; keyed on the nullifier the two are
  mutually exclusive, so taking the fee requires out-bidding — which means
  paying it.

  **Admission policy, not state transition** — consensus is unaffected. Nodes
  on the old logic keep accepting the duplicate variants, so the mitigation
  only completes as the network updates.
- **relay — the selector whitelist was stale for BOTH operations (ME-8).** The
  client held `0x47fc44a2` (unshield) and `0x8c0f5d24` (privateTransfer), while
  the decoder answers to `0x4e505348` and `0x66ed2cd4`. Derived by keccak, the
  stale pair turn out to be real selectors from signatures two versions old.
  Relaying was therefore rejecting every call as *"unsupported selector"* —
  silently, because that is indistinguishable from a legitimate rejection. The
  same stale literals sat in the runtime's fallback list and in
  `ts-tests/test-relay-rpc.ts`, so the tests stayed green while testing nothing.

  Both now derive from `pallet_evm_precompile_shielded_pool::selectors::*` (or
  from the ABI signature, in the TypeScript tests), and a unit test pins the
  client constants against the decoder's.
- **relay — per-operation calldata minimums were both 228 bytes**, the shared
  head up to the fee slot. Past that the layouts diverge: unshield's head is 10
  slots (324 with the selector), privateTransfer's is 8 (260). A call between
  228 and its real minimum passed validation and reached the decoder truncated.
- **relay — `gas_price` and the fee word saturate instead of panicking.**
  `U256::as_u128()` panics above 2^128. The fee word is caller-controlled over
  an unauthenticated RPC, so one crafted 32-byte value took down the handler;
  `gas_price` comes from the runtime and is not attacker-reachable, but a panic
  there still kills the relay RPC. Node-side only, no consensus effect.

### spec 8 — tx 2 — 2026-08-08

Bundles the whole audit-remediation batch plus the config/feature work that
preceded it. `transaction_version` stays at 2 — no call index or dispatch
signature changed; the metadata moves, so `spec_version` does.

**Features / config**

- **validator-set 0.2.0 — registration bond removed** (#121). The 1 000 ORB
  `register_validator` bond is gone: `ValidatorBond` and `Currency` Config
  items, the `ValidatorBondOf` map, both bond events and `InsufficientBond`.
  Governance approval already gated the active set, so the bond only added a
  funding step for hand-onboarded operators. No migration — `ValidatorBondOf`
  was queried on testnet first and found empty (0 entries, empty queue, 3
  validators all sudo-added), so nothing stays reserved.
- **shielded-pool — minimum shield amount removed** (#121). `MinShieldAmount`
  and `AmountTooSmall` are gone; any non-zero amount is shieldable, zero still
  refused via `InvalidAmount`. This shifts the numeric index of every `Error`
  variant declared after `AmountTooSmall` — clients matching on error *names*
  are unaffected; anything decoding by index needs fresh metadata.
- **shielded-pool — sealed-tree pruning** (#122). New Config
  `SealedTreePrunedBelowLevel` (production 10) and an `on_idle` sweep that
  reclaims ~99.8% of a sealed tree's `MerkleNodes` (1,048,574 → 2,046 per
  tree); `get_merkle_path` recomputes pruned siblings from `MerkleLeaves` on
  demand. Benchmarked at 12.68 µs/node, so the 512-node per-block ceiling
  costs ~6.5 ms. No migration — nothing prunes until a tree seals at 2^20
  leaves, and the sweep reaches already-sealed trees on its own.
- **runtime config split into modules** (#121). `template/runtime/src/configs/`.
  No consensus effect on its own.
- **legacy `shieldedPool_*` RPC server retired** (#119). Node-side only.

**Security (audit remediation)**

- **zk-verifier — deserialization bounds + circuit-id de-aliasing** (#123).
  `MAX_VK_BYTES` / `MAX_PROOF_BYTES` cap the length prefix before
  `Vec::with_capacity`; circuit ids no longer alias to the same `u8`, and
  genesis asserts VK arity.
- **shielded-pool — zero-hash ladder and tree-depth shift bounded** (#124).
  `zero_hash_at_level` is iterative (a recursive call could exhaust the 1 MB
  Wasm stack and abort the process); a const assertion pins tree `DEPTH < 32`
  so `capacity()` cannot shift into a `u32`.
- **shielded-pool 0.16.0 — non-canonical and zero commitments/nullifiers
  refused** (#125). Both are raw-byte storage keys while byte→field reduces
  mod the BN254 `p`, so `n` and `n + p` were two keys for one element — a
  double-spend vector. `is_canonical` is now checked on every write path
  (`shield`, `private_transfer`, `unshield`); zero commitments refused
  separately since zero is canonical but indistinguishable from an empty tree
  slot. Shifts `Error` indices (breaking for index-decoders, not name-matchers).
- **precompile 0.5.0 — ABI decoder truncation/overflow fixed** (#126).
  Offsets/lengths were narrowed with `low_u32()`; a wrapping length built an
  inverted slice range and panicked the runtime (`wasm unreachable`, reachable
  from an unsigned gas-free `eth_call`). Words are now rejected when they don't
  fit their type, and all offset/length arithmetic is checked. No ABI change.
- **shielded-pool 0.17.0 — duplicate nullifier in `private_transfer` refused**
  (#127). Two equal non-dummy nullifiers spent one input twice (both cleared
  the used-set check, the second `mark_as_used` was idempotent). `execute` now
  rejects a duplicate with `NullifierAlreadyUsed`. Defense in depth.

| spec | tx | Date | Commit | Change |
|------|----|------|--------|--------|
| 7 | 2 | 2026-08-05 | — | Two pallet changes shipping in one upgrade. **shielded-pool 0.14.0:** historic-root window re-anchored from insert counts to block numbers. New Config `RootRetentionBlocks` (300 blocks); `MaxHistoricRoots` (raised to 16384) becomes a queue-length cap rather than the window. `HistoricPoseidonRoots` now stores an expiry block instead of a bool; `HistoricRootsOrder` replaced by the slot-indexed `HistoricRootsQueue` + `Head`/`Tail`. `STORAGE_VERSION` 2 → 3 with `MigrateToV3` in the tuple. Weights re-benchmarked against the v3 layout. The amount-overflow pool rejection moves from `Custom(2)` to `Custom(4)`, which had two meanings. **Applied migrations removed (`72ff7b88`):** the v1/v2 modules are gone from shielded-pool and zk-verifier 0.11.0 — testnet was already past both, so they were no-ops, and `MigrateToV1` rebuilt the whole Merkle tree in one block. `spec_version` moves because storage layout and `on_runtime_upgrade` both change; `transaction_version` stays — no call signature changed. |
| 6 | 2 | 2026-08-03 | — | `pallet-account-mapping` and its precompile (index 14, address 0x0800) removed, along with the `private_link` circuit (id 5) and its verification key. Index 14 is retired and must not be reassigned. zk-verifier 0.10.0 gains `purge_circuit` (call index 7, Root) plus `STORAGE_VERSION` 1 and `MigrateToV1`, which drops the stranded circuit-5 key that no extrinsic could reach. `transaction_version` moves because the new call index changes extrinsic encoding. |
| 5 | 1 | 2026-07-30 | — | shielded-pool 0.12.0: multi-tree forest. Full trees seal (`TreeSealed`, permanent `SealedTreeRoots` anchors) and inserts roll over to a fresh tree — the 2^20-note network ceiling is gone. New Config `MaxLeavesPerTree` (2^20), `STORAGE_VERSION` 2 (`MigrateToV2`, version-only), runtime API v2 (`get_forest_info`, `get_root_for_leaf`). No circuit/extrinsic/ABI changes. |
| 4 | 1 | 2026-07-30 | `63caafca` | shielded-pool 0.11.0: `MerkleNodes` storage (internal nodes written on every insert) + `MigrateToV1` migration (backfill, `STORAGE_VERSION` 1). O(depth) Merkle proofs. Weights re-benchmarked. The upgrade block runs the one-shot migration (~3s at ~90k leaves). |
| 3 | 1 | 2026-07-27 | `d9d40244` | Build with the metadata hash `CheckMetadataHash` requires. |
| 2 | 1 | 2026-07-26 | `c285ac3f` | shielded-pool 0.10.1: `recipient_to_field` reduces mod BN254 r — fixes rejection of most Substrate recipients in `unshield` (consensus halt). |
| 1 | 1 | 2026-07-15 | `69d1b837` | Testnet genesis. Version reset (came from spec 6 in the dev era). |

## Previous era (dev, pre-reset)

History prior to the reset — does not correspond to any live chain.

| spec | tx | Date | Commit | Change |
|------|----|------|--------|--------|
| 6 | 2 | 2026-07-10 | `28decfe4` | `circuit_version` carried in the memo (`MAX_ENCRYPTED_MEMO_SIZE` 176→180). |
| 5 | 2 | 2026-07-09 | `aafb5989` | Per-note circuit versioning with version retirement; `private_transfer`/`unshield`/`claim_shielded_fees` gain a `circuit_version` arg (tx 1→2). |
| 3 | 1 | 2026-07-06 | `2ffd2fce` | Shielded pool hardening. |
| 2 | 1 | 2026-07-04 | `8930d626` | zk-verifier hardening. |
| 1 | 1 | — | `ce10bb01` | Initial Substrate template. |
